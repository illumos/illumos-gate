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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/fhc.h>
#include <sys/jtag.h>
#include <sys/ac.h>
#include <sys/machsystm.h>
#include <sys/cpu.h>
#include <sys/cpuvar.h>

/*
 * Defines for data structures used only in this module. They will
 * not be exported to external modules.
 */

/*
 * Define the hardware structure of JTAG
 */

#define	JTAG_CSR_BASE ((jtag_csr *)0xF0300000)


#define	JTAG_CR 0x08000f0
#define	JTAG_CMD 0x0800100

/* JTAG status flags */
#define	JTAG_BUSY_BIT 0x100

/* JTAG commands */
#define	JTAG_SEL_RING	0x6000
#define	JTAG_SEL_DR	0x5050
#define	JTAG_SEL_IR	0x5068
#define	JTAG_SHIFT	0x00A0
#define	JTAG_RUNIDLE	0x50C0
#define	JTAG_IR_TO_DR	0x50E8
#define	JTAG_DR_TO_IR	0x50F4
#define	JTAG_TAP_RESET	0x50FF


/*
 * Definitions of data types.
 *
 */

/*
 * Most routines in this interface return a negative value when
 * an error occurs. In the normal case, the routines return a non-negative
 * value, which may be of interest to the caller. The following enumeration
 * provides the meaning of each error return code.
 */

/*
 * When calling verify_jtag_chip, you must pass PRINT_ERR if you
 * want the cmn_err call to occur. This is because sometimes
 * when we verify rings, (checking for NPB's) we do not want to
 * print error messages.
 */
#define	PRINT_JTAG_ERR	5

/*
 * You must pass in the proper chip masks when calling
 * config board()
 */
#define	AC_INIT		1
#define	DCU1500_INIT	2
#define	DCU1600_INIT	2
#define	DCU1700_INIT	2
#define	DCU1800_INIT	2
#define	DCU1900_INIT	2
#define	DCU2000_INIT	2
#define	DCU2100_INIT	2
#define	DCU2200_INIT	2
#define	FHC_INIT	4

#define	SYSIO_INIT	8

/* scan ring numbers */
#define	RING0		0
#define	RING1		1
#define	RING2		2

/*
 * Scan ring 0 lengths. Boards are typed by their scan ring length. This
 * is inherently flawed if a new board type has the same number of
 * components as one of the original boards.
 *
 * The inherently flawed scenario now exists with the introduction
 * of the soc+ versions of the 2-SBus and UPA/SBus boards. Argh...
 */
#define	CPU_TYPE_LEN	12		/* CPU board ring length */
#define	IO_TYPE1_LEN	15		/* 2 sysio 1 HM */
#define	IO_TYPE2_LEN	14		/* 1 sysio 1 ffb */
#define	PCI_TYPE_LEN	16		/* PCI board ring length */
#define	PCI_TYPEA_LEN	110		/* PCI ISP off ring */
#define	PCI_TYPEB_LEN	104		/* PCI ISP in ring */
#define	DSK_TYPE_LEN	2		/* Disk board ring length */
#define	IO_TYPE4_LEN	126		/* 2 sysio soc+ */
#define	IO_TYPE5_LEN	110		/* 1 sysio 1 ffb soc+ */

#define	CPU_0_5_LEN	8		/* 0.5 Meg Module ring length */
#define	CPU_1_0_LEN	12		/* 1 Meg and 2 Meg ring length */
#define	FFB_SNG_LEN	6		/* Single bufferef FFB */
#define	FFB_DBL_LEN	18		/* Double buffered FFB */

/*
 * Component IDs of various SRAM chips. The only way to distinguish between
 * 1M, 2M, and 4M Ecache is via the component IDs of the SRAMs.
 */
#define	SRAM_256K	0x00000000
#define	SRAM_128K	0x000090E3
#define	SRAM_64K_1	0x000000E3
#define	SRAM_64K_2	0x01901149

typedef enum {
	JTAG_OK = 0,		/* no error */
	JTAG_FAIL = -1,		/* generic JTAG failure */
	TAP_TIMEOUT = -1,	/* JTAG TAP state machine not responding */
	BAD_ARGS = -2,		/* incorrect arguments passed by caller */
	BAD_CID = -3,		/* JTAG component ID does not match */
	RING_BROKEN = -4,	/* JTAG ring continuity test failed */
	INIT_MISMATCH = -5,	/* State after initialization not expected */
	LENGTH_MISMATCH = -6	/* Ring length does not match expected */
} jtag_error;

typedef u_short jtag_instruction;
typedef u_char jtag_ring;	/* format is bbbb rrrr in binary */

/* Internal macros */
static int tap_issue_cmd(volatile u_int *, u_int);

/* TAP register access macros */

/* NOTE the only status is the busy bit (8) */

/* read the jtag data bits */
#define	jtag_data(reg, nbits) (*(reg) >> (32 - (nbits)))

#define	JTAG_TIMEOUT 0x10000

#define	TAP_DECLARE int timeout;

#define	TAP_WAIT(reg)  timeout = JTAG_TIMEOUT;		\
	while ((*(reg) & JTAG_BUSY_BIT) != 0)		\
		if ((--timeout) < 0)			\
			return (TAP_TIMEOUT)

#define	TAP_SHIFT(reg, data, nbits)				\
	*(reg) = ((data<<16) | ((nbits-1)<<12) | JTAG_SHIFT);	\
	TAP_WAIT(reg)

/* Error-checking macros to simplify the coding */

#define	TAP_ISSUE_CMD(reg, cmd, status)		\
	status = tap_issue_cmd(reg, cmd);	\
	if (status < 0)				\
		return (status)

#define	TAP_SHIFT_CONSTANT(reg, val, nbits, status)	\
	status = tap_shift_constant(reg, val, nbits);	\
	if (status < 0)					\
		return (status)

#define	TAP_SHIFT_SINGLE(reg, val, nbits, status)	\
	status = tap_shift_single(reg, val, nbits);	\
	if (status < 0)					\
		return (status)

#define	TAP_SHIFT_MULTIPLE(reg, in, nbits, out, status)		\
	status = tap_shift_multiple(reg, in, nbits, out);	\
	if (status < 0)						\
		return (status)

/*
 * A jtag_log_comp describes a component as seen by JTAG.
 *
 * Since there are multiple versions & revision for a single
 * component, this can be a bit complicated...
 *
 * The implementation assumes that all components which can be used
 * interchangeably have the exact same programming model regarding
 * JTAG programming. Then, interchangeable components differ only by
 * their component IDs. The field id points to a NULL-terminated list
 * of component IDs. Allowable component IDs may differ only in the rev
 * number, which must be higher than or equal to the one in the list.
 *
 * The init_pdesc field points to a byte string which describes how to
 * initialize the component. The structure of this byte string is not
 * exported (see the implementation of jtag_init_chip).
 *
 * The fmt_desc field points to a byte string which describes how to
 * convert the scan-out format to the more usual DCSR format. The
 * structure of this string is not exported (see the implementation
 * of jtag_scanout_chip).
 */

typedef struct {
	u_int *id;		/* Pointer to component IDs, 0 if no CID */
	u_char ir_len;		/* number of bits in instruction register */
	u_char dr_len;		/* number of bits in DR for init/dump */
	jtag_instruction id_code;	/* instruction to read component ID */
	jtag_instruction init_code;	/* instruction to write parameters */
	jtag_instruction dump_code;	/* instruction to read parameters */
	u_char *init_pdesc;		/* initialization patch descriptors */
	u_char *fmt_desc;		/* reformat descriptor */
} jtag_log_comp;


/* A jtag_phys_comp describes a component position inside a ring */

typedef struct {
	jtag_log_comp *chip;	/* pointer to chip descriptor */
	short ir_after;		/* number of IR bits after chip in ring */
	short ir_before;	/* number of IR bits before chip in ring */
	short by_after;		/* number of bypass bits after chip in ring */
	short by_before;	/* number of bypass bits before chip in ring */
} jtag_phys_comp;


/* Board ring description */

typedef struct {
	int size;
	jtag_phys_comp *components;
} jtag_ring_desc;

/*
 *	Initialization options
 *
 * These data types describe the options for each type of component
 * internally to the jtag_init_*_ring routines. They can all be
 * recast into arrays of unsigned integers.
 *
 * Note that these types DEPEND on the *_init_pdesc structures, which
 * use indices to the components of the *_options types. As a result,
 * the data structure & the type must be modified simultaneously,
 * although this dependency is not immediately visible. This is ugly,
 * but it makes the initialization routines much more readable.
 */

typedef struct {
	u_int frozen;
	u_int reset_a;
	u_int reset_b;
	u_int board_id;
	u_int mask_hwerr;
	u_int arb_fast;
	u_int node_id;
	u_int pcr_hi;
	u_int pcr_lo;
	u_int pcc_ctl1;
	u_int pcc_ctl0;
	u_int pcc_tctrl;
} ac_options;

struct ac_regs {
	unsigned int bcsr;
	unsigned int brscr;
	unsigned int esr_hi;
	unsigned int esr_lo;
	unsigned int emr_hi;
	unsigned int emr_lo;
	unsigned int ccr;
	unsigned int cntr_hi;
	unsigned int cntr_lo;
};

typedef struct {
	u_int frozen;
	u_int mask_pe;
	u_int mask_oe;
} dc_options;

typedef struct {
	u_int csr_hi;		/* CSR 20:18 */
	u_int csr_mid;		/* CSR 16:8 */
	u_int csr_midlo;	/* CSR 6:4 */
} fhc_options;


struct fhc_regs {
	u_int por;
	u_int csr;
	u_int rcsr;
	u_int bsr;
};

/* Structure to capture the scan data from the bct8244's. */
struct bct_fields {
	u_int disk1_pres;
	u_int disk0_pres;
	u_int disk1_id;
	u_int disk0_id;
};

/* Collective type for *_options * */
typedef u_int *jtag_opt;

/*
 * The following definitions are the action flags used in the byte
 * string which is used to describe component initialization. The
 * only piece of code which understands those flags is jtag_init_chip.
 *
 * Initializing a component consists of scanning successive values
 * into the component. The data for each pass is obtained by applying
 * successive patches to a reference pattern. The patch descriptors
 * are a byte string which form a succession of operations. The first
 * byte of an operation is a set of flags defining the action:
 */
#define	JTIN_INDEX	0x0F
#define	JTIN_INSERT	0x10
#define	JTIN_UPDATE	0x20
#define	JTIN_COMPARE	0x40
#define	JTIN_END	0x80

/*
 * When JTIN_INSERT is specified, the flag byte is followed by
 * two bytes indicating the lsb and msb of the field to be updated, and
 * the JTIN_INDEX part of the flags indicate which value should be
 * inserted: if JTIN_INDEX is zero, the value to insert is the next
 * byte in the aray, extended to a 32-bit word; if JTIN_INDEX is
 * non-zero, the value to insert is at word offset index in the patch
 * array passed to jtag_init_chip.
 */

/*
 * The fmt_desc field points to a reformat table which converts the
 * scan-out format to the standard DSCR-style format. The format descriptor
 * is a byte string, with special bytes indicating functional operations
 * as indicated by bit fields in the following table:
 */
#define	JTSO_END	0x80	/* end of table */
#define	JTSO_XTRACT	0x40	/* extract & merge [lsb, msb] */
#define	JTSO_ST		0x20	/* store & increment */
#define	JTSO_SHIFT	0x1F	/* shift count for extract & merge */

/*
 * Function Declarations
 */
static void jtag_error_print(int, jtag_error);
static int jtag_get_comp_id(volatile u_int *, jtag_phys_comp *);

/*
 *	Bit-field manipulations
 */
static u_int jtag_bf_extract(u_char *s, int lsb, int msb);
static void jtag_bf_insert(u_char *s, int lsb, int msb, int value);
static void jtag_bf_zero(u_char *s, int nbits);
static int jtag_bf_cmp(u_char *s1, u_char *s2, int nbits);

/*
 *	Test-access port interface
 */
static int tap_wait(volatile u_int *);
static int tap_shift_single(volatile u_int *, int, int);
static int tap_shift_multiple(volatile u_int *, u_char *, int, u_char *);

/*
 *    Ring-level interface
 */

static int select_ring(volatile u_int *, jtag_ring, int);
static int jtag_rescan_IR_DR(volatile u_int *, jtag_phys_comp *,
	jtag_instruction, u_char *, int, u_char *);
static int jtag_single_IR_DR(volatile u_int *, jtag_phys_comp *,
	jtag_instruction, u_char *, int, u_char *);
static int jtag_ring_length(volatile u_int *, jtag_ring);
static int jtag_ring_ir_length(volatile u_int *, jtag_ring);

/*
 *    Component-level interface
 */

static int jtag_scanout_chip(volatile u_int *, jtag_ring, jtag_phys_comp *,
	u_int *);
static int jtag_init_chip(volatile u_int *, jtag_ring, jtag_phys_comp *,
	const u_int *, u_char *);
static jtag_phys_comp *find_chip(jtag_ring_desc *, jtag_log_comp *, int);
static void format_chip_data(u_char *, u_int *, u_char *);
static int jtag_init_ac(volatile u_int *, int, enum board_type);

/*
 * Data tables.
 *
 * The JTAG implementation is data table driven. These tables describe
 * the chip, ring, and board components.
 */

/*
 *    Data structures describing the scannable components
 */

static char jtag_err[] = "JTAG ERROR";

/* Constants defining the IR lengths for each of the chips */

#define	IR_LEN 8	/* all sunfire asics, spitfire, and sdb  are 8 bits */
#define	HM_LEN 4	/* happy meal is 4 bits */
#define	NDP_LEN 2	/* ndp83840 is 2 bits */
#define	SOC_LEN 4	/* SOC is 4 bits */
#define	SOCPLUS_LEN 8	/* SOC+ is 8 bits */
#define	SIO_LEN 16	/* sysio asic is 16 bits */
#define	PSYO_LEN 4	/* psycho asic is 4 bits */
#define	CHEO_LEN 4	/* cheerio asic is 4 bits */
#define	EC_LEN 3	/* ecache tag rams is 3 bits each */

#define	FFB_LEN 16	/* ffb module is 16 bits */
#define	THREED_LEN	4	/* IR length for three D rams */
#define	BT498_LEN 4	/* IR length for bt 498 chip (ramdac) */



/* Standard instructions */
#define	IDCODE		0xFFFE
#define	INITCODE	0xbe
#define	DUMPCODE	0xbe

#define	CID_TO_REV(cid)	((cid) >> 28)

/* ASIC Jag IDs */
static u_int cid_sf[] = {
	0x0002502f,
	0
};

static u_int cid_sdb[] = {
	0x0002602f,
	0
};

static u_int cid_fbc[] = {
	0x1241906d,
	0
};

static u_int cid_lvt[] = {
	0x0001d02f,
	0
};

static u_int cid_3dram[] = {
	0X0E9A103B,
	0
};

static u_int cid_bt498[] = {
	0x0001d02f,
	0
};

static u_int cid_sio[] = {
	0x0ef0703b,
	0
};

static u_int cid_hm[] = {
	0x01792045,
	0
};

static u_int cid_ac[] = {
	0x10f9e07d,
	0
};

static u_int cid_dc[] = {
	0x10f9f07d,
	0
};

static u_int cid_fhc[] = {
	0x10fa007d,
	0
};

static u_int cid_psyo[] = {
	0x3195401d,
	0
};

static u_int cid_cheo[] = {
	0x11791022,
	0
};


/*
 * NOTE the following chips are ignored for the most part by the POST JTAG
 * If if is later determined that scan data may be of interest then we need
 * to fill in the blanks below.
 */

static u_char ec_init_pdesc[] = {
	JTIN_END|JTIN_INSERT|0, 0, 0, 0x0
};

static u_char ec_fmt[] = {
	JTSO_ST|JTSO_XTRACT|JTSO_END| 0, 0, 4
};

static u_char sio_init_pdesc[] = {
	JTIN_END|JTIN_INSERT|0, 0, 0, 0x0
};

static u_char sio_fmt[] = {
	JTSO_ST|JTSO_XTRACT|JTSO_END| 0, 0, 4
};

static u_char psyo_init_pdesc[] = {
	JTIN_END|JTIN_INSERT|0, 0, 0, 0x0
};

static u_char psyo_fmt[] = {
	JTSO_ST|JTSO_XTRACT|JTSO_END| 0, 0, 4
};

static u_char hm_init_pdesc[] = {
	JTIN_END|JTIN_INSERT|0, 0, 0, 0x0
};

static u_char hm_fmt[] = {
	JTSO_ST|JTSO_XTRACT|JTSO_END| 0, 0, 4
};

static u_char ndp_init_pdesc[] = {
	JTIN_END|JTIN_INSERT|0, 0, 0, 0x0
};

static u_char ndp_fmt[] = {
	JTSO_ST|JTSO_XTRACT|JTSO_END| 0, 0, 4
};

static u_char cheo_init_pdesc[] = {
	JTIN_END|JTIN_INSERT|0, 0, 0, 0x0
};

static u_char cheo_fmt[] = {
	JTSO_ST|JTSO_XTRACT|JTSO_END| 0, 0, 4
};


/* The main ASCIS of interest are the AC, DC and FHC */

/*
 * The initialization of DC is as follows:
 *
 * Do NOT change the following data structure without checking
 * _options in jtag_private.h, which depends on it.
 */
static u_char dc_init_pdesc[] = {
	JTIN_INSERT|1,   0,   0,	/* NFZN */
	JTIN_INSERT|2,   4,   4,	/* Mask PE */
	JTIN_INSERT|3,   3,   3,	/* Mask OE */
	JTIN_INSERT|0,   1,   2,  3,	/* W1C Errors */
	JTIN_END|JTIN_UPDATE,
};

static u_char dc_fmt[] = {
	JTSO_ST|JTSO_XTRACT|JTSO_END| 0, 0, 4    /* DC[4:0] */
};

/*
 * The initialization of AC is as follows:
 *
 * Do NOT change the following data structure without checking
 * _options in jtag_private.h, which depends on it.
 */
static u_char ac_init_pdesc[] = {
	JTIN_INSERT|0, 161, 161, 1,	/* BOARD ADDR 40 */
	JTIN_INSERT|7, 159, 160,	/* BOARD ADDR 39:38, wfi node */
	JTIN_INSERT|4, 155, 158, 	/* BOARD ADDR 37:34 */
	JTIN_INSERT|4, 151, 154, 	/* BOARD ID */
	JTIN_INSERT|6, 146, 146,	/* ARB_FAST */
	JTIN_INSERT|1, 134, 134,	/* NFZN */
	JTIN_INSERT|0, 133, 133, 0,	/* ENWAKPOR  */
	JTIN_INSERT|2, 135, 135,	/* Reset B */
	JTIN_INSERT|3, 136, 136,	/* Reset A */
	JTIN_INSERT|0, 99, 106, 0xff,	/* W1C Errors */
	JTIN_INSERT|0, 107, 114, 0xff,	/* W1C Errors */
	JTIN_INSERT|0, 115, 122, 0xff,	/* W1C Errors */
	JTIN_INSERT|0, 123, 130, 0xff,	/* W1C Errors */
	JTIN_INSERT|0, 131, 132, 0xff,	/* W1C Errors */
	JTIN_INSERT|5, 88, 98,		/* Error Masks */
	JTIN_INSERT|12, 76, 87,		/* CNT1_CTL_<27:16> */
	JTIN_INSERT|10, 70, 75,		/* CNT1_CTL <13:8> */
	JTIN_INSERT|11, 64, 69,		/* CNT0_CTL <5:0> */
	JTIN_INSERT|8, 32, 63,		/* CNT1 */
	JTIN_INSERT|9, 0, 31,		/* CNT0 */
	JTIN_END|JTIN_UPDATE,		/* Clears counters */
};

static u_char ac_fmt[] = {
	JTSO_XTRACT|17,			148,	162,	/* BCSR[31:17] */
	JTSO_XTRACT|15,			147,	147,	/* BSCR[15] */
	JTSO_XTRACT|5,			138,	146,	/* BSCR[13:5] */
	JTSO_ST|JTSO_XTRACT|0,		134,	137,	/* BSCR[3:0] */
	JTSO_ST|JTSO_XTRACT|22,		133, 	133,	/* BRSCR[22] */
	JTSO_XTRACT|16,			131,	132,	/* ESR[49:48] */
	JTSO_XTRACT|8,			124,	130,	/* ESR[46:40] */
	JTSO_XTRACT|4,			122,	123,	/* ESR[37:36] */
	JTSO_ST|JTSO_XTRACT|0,		120,	121,	/* ESR[33:32] */
	JTSO_XTRACT|28,			116,	119,	/* ESR[31:28] */
	JTSO_XTRACT|24,			115,	115,	/* ESR[24] */
	JTSO_XTRACT|20,			112,	114,    /* ESR[22:20] */
	JTSO_XTRACT|12,			107,	111,    /* ESR[16:12] */
	JTSO_XTRACT|4,			101,	106,	/* ESR[9:4] */
	JTSO_ST|JTSO_XTRACT|0,		99,	100,	/* ESR[1:0] */
	JTSO_XTRACT|16,			97,	98,	/* EMR[49:48] */
	JTSO_XTRACT|8,			96,	96,	/* EMR[40] */
	JTSO_ST|JTSO_XTRACT|4,		94,	95,	/* EMR[37:36] */
	JTSO_XTRACT|28,			93,	93,	/* EMR[28] */
	JTSO_XTRACT|24,			92,	92,	/* EMR[24] */
	JTSO_XTRACT|20,			91,	91,	/* EMR[20] */
	JTSO_XTRACT|12,			90,	90,	/* EMR[12] */
	JTSO_XTRACT|8,			89,	89,	/* EMR[8] */
	JTSO_ST|JTSO_XTRACT|4,		88,	88,	/* EMR[4] */
	JTSO_XTRACT|16,			76,	87,	/* CCR[27:16] */
	JTSO_XTRACT|8,			70,	75,	/* CCR[13:8] */
	JTSO_ST|JTSO_XTRACT|0,		64,	69,	/* CCR[5:0] */
	JTSO_ST|JTSO_XTRACT|0,		32,	63,	/* CNT[63:32] */
	JTSO_ST|JTSO_XTRACT|JTSO_END|0,	0,	31	/* CNT[31:0] */
};

/*
 */

/*
 * The following structure has three variable elements, as noted
 * by the 1,2 and 3 digits or'ed in with the JTIN_INSERT flags.
 * The number nad position of these elements must correspond with
 * the fhc_ structure apssed into fhc_chip_init.
 */
static u_char fhc_init_pdesc[] = {
	JTIN_INSERT|0,	41,	41,	0,		/* POR */
	JTIN_INSERT|1,	38,	40,			/* CSR[20:18] */
	JTIN_INSERT|2,	29,	37,			/* CSR[16:8] */
	JTIN_INSERT|3,	26,	28,			/* CSR[6:4] */
	JTIN_INSERT|0,	24,	25,	0x0,		/* CSR[1:0] */
	JTIN_INSERT|0,	16,	23,	0x0,		/* RCSR[31:24] */
	JTIN_INSERT|0,	2,	15,	0x0,		/* BSR[18:5] */
	JTIN_INSERT|0,	0,	1,	0x0,		/* BSR[1:0] */
	JTIN_END|JTIN_UPDATE,
};

static u_char fhc_fmt[] = {
	JTSO_ST|JTSO_XTRACT|0,		41,	41,	/* POR State */
	JTSO_XTRACT|18,			38,	40,	/* CSR[20:18] */
	JTSO_XTRACT|8,			29,	37,	/* CSR[16:8] */
	JTSO_XTRACT|4,			26,	28,	/* CSR[6:4] */
	JTSO_ST|JTSO_XTRACT|0,		24,	25,	/* CSR[1:0] */
	JTSO_ST|JTSO_XTRACT|24,		16,	23,	/* RCSR[31:24] */
	JTSO_XTRACT|5,			2,	15,	/* BSR[18:5] */
	JTSO_ST|JTSO_XTRACT|JTSO_END|0,	0,	1,	/* BSR[1:0] */
};


static u_char bct8244_fmt[] = {
	JTSO_ST|JTSO_XTRACT|0,		17,	17,	/* Disk 1 present */
	JTSO_ST|JTSO_XTRACT|0,		16,	16,	/* Disk 0 present */
	JTSO_ST|JTSO_XTRACT|0,		12,	15,	/* Disk 1 Target */
	JTSO_ST|JTSO_XTRACT|JTSO_END|0,	8,	11,	/* Disk 0 Target */
};

/* A jtag_log_comp describes a component as seen by JTAG. */

static jtag_log_comp chip_ac = {
	cid_ac,
	IR_LEN, 163,
	IDCODE, INITCODE, DUMPCODE,
	ac_init_pdesc, ac_fmt
};

static jtag_log_comp chip_bct8244 = {
	0,
	IR_LEN, 18,
	0x2, 0x2, 0x2,
	NULL, bct8244_fmt
};

static jtag_log_comp chip_dc = {
	cid_dc,
	IR_LEN, 5,
	IDCODE, INITCODE, DUMPCODE,
	dc_init_pdesc, dc_fmt
};

static jtag_log_comp chip_fhc = {
	cid_fhc,
	IR_LEN, 42,
	IDCODE, INITCODE, DUMPCODE,
	fhc_init_pdesc, fhc_fmt
};

static jtag_log_comp chip_ec = {
	0,
	EC_LEN, 42,
	1, INITCODE, IDCODE,
	ec_init_pdesc, ec_fmt
};

static jtag_log_comp chip_fbc = {
	cid_fbc,
	FFB_LEN, 42,
	0xb000, 0xb000, 0xb000,
	NULL, NULL
};

static jtag_log_comp chip_lvt = {
	cid_lvt,
	IR_LEN, 42,
	IDCODE, INITCODE, DUMPCODE,
	NULL, NULL
};

static jtag_log_comp chip_3dram = {
	cid_3dram,
	THREED_LEN, 42,
	IDCODE, INITCODE, DUMPCODE,
	NULL, NULL
};

static jtag_log_comp chip_bt498 = {
	cid_bt498,
	BT498_LEN, 42,
	IDCODE, INITCODE, DUMPCODE,
	NULL, NULL
};

static jtag_log_comp chip_sio = {
	cid_sio,
	SIO_LEN, 42,
	0xb000, 0xb000, 0xb000,
	sio_init_pdesc, sio_fmt
};

static jtag_log_comp chip_hm = {
	cid_hm,
	HM_LEN, 42,
	0xe, 0xe, 0xe,
	hm_init_pdesc, hm_fmt
};

static jtag_log_comp chip_ndp = {
	0,
	NDP_LEN, 42,
	2, 2, 2,
	ndp_init_pdesc, ndp_fmt
};

static jtag_log_comp chip_soc = {
	0,
	SOC_LEN, 42,
	4, 4, 4,
	NULL, NULL
};

static jtag_log_comp chip_socplus = {
	0,
	SOCPLUS_LEN, 42,
	0xfe, 4, 4,
	NULL, NULL
};

static jtag_log_comp chip_spitfire = {
	cid_sf,
	IR_LEN, 42,
	0xfe, 0xfe, 0xfe,
	NULL, NULL
};


static jtag_log_comp chip_sdb = {
	cid_sdb,
	IR_LEN,  42,
	0xfe, 0xfe, 0xfe,
	NULL, NULL
};

static jtag_log_comp chip_psyo = {
	cid_psyo,
	PSYO_LEN, 42,
	0xb000, 0xb000, 0xb000,
	psyo_init_pdesc, psyo_fmt
};

static jtag_log_comp chip_cheo = {
	cid_cheo,
	CHEO_LEN, 42,
	0xb000, 0xb000, 0xb000,
	cheo_init_pdesc, cheo_fmt
};

/*
 *    Ring descriptions for sunfire boards
 *
 * For each ring, there is a generic type descriptor which describes
 * the order of chips in the static data structure describing the
 * ring.
 *
 * Rings are described by an array of physical components, and are
 * recast into the specific ring type by routines which use them, see
 * for example the jtag_init_*_ring routines.
 *
 * Although the ring data structures are declared as jtag_phys_comp[],
 * the components must be ordered as required by the corresponding
 * *_*_ring type (in jtag_private.h).
 */

/*
 *    Data structures describing the system board rings
 */

static jtag_phys_comp cpu_sysbd_ring_components[] = {
	{ &chip_ac, 11*IR_LEN,	0,		11,	0 },	/* AC */
	{ &chip_dc, 10*IR_LEN,	1*IR_LEN,	10,	1 },	/* DC 1 */
	{ &chip_dc, 9*IR_LEN,	2*IR_LEN,	9,	2 }, 	/* DC 2 */
	{ &chip_dc, 8*IR_LEN,	3*IR_LEN,	8,	3 }, 	/* DC 3 */
	{ &chip_dc, 7*IR_LEN,	4*IR_LEN,	7,	4 }, 	/* DC 4 */
	{ &chip_dc, 6*IR_LEN,	5*IR_LEN,	6,	5 }, 	/* DC 5 */
	{ &chip_dc, 5*IR_LEN,	6*IR_LEN,	5,	6 }, 	/* DC 6 */
	{ &chip_dc, 4*IR_LEN,	7*IR_LEN,	4,	7 }, 	/* DC 7 */
	{ &chip_dc, 3*IR_LEN,	8*IR_LEN,	3,	8 }, 	/* DC 8 */
	{ &chip_fhc, 2*IR_LEN,	9*IR_LEN,	2,	9 }, 	/* FHC */
	{ &chip_ec, 1*IR_LEN,	10*IR_LEN,	1,	10 }, 	/* RAM 0 */
	{ &chip_ec, 0*IR_LEN,	11*IR_LEN,	0,	11 }, 	/* RAM 1 */
};

static jtag_ring_desc  cpu_sysbd_ring = {
	12, cpu_sysbd_ring_components
};


static jtag_phys_comp cpu_mod_1m_ring_components[] = {
	{ &chip_spitfire, 43,	0,	11,	0 },	/* Spitfire */
	{ &chip_ec,	40,	8,	10,	1 },	/* Parity chip */
	{ &chip_ec,	37,	11,	9,	2 },	/* Byte 0 */
	{ &chip_ec,	34,	14,	8,	3 },	/* Byte 1 */
	{ &chip_ec,	31,	17,	7,	4 },	/* Byte 2 */
	{ &chip_ec,	28,	20,	6,	5 },	/* Byte 3 */
	{ &chip_ec,	25,	23,	5,	6 },	/* Byte 4 */
	{ &chip_ec,	22,	26,	4,	7 },	/* Byte 5 */
	{ &chip_ec,	19,	29,	3,	8 },	/* Byte 6 */
	{ &chip_ec,	16,	32,	2,	9 },	/* Byte 7 */
	{ &chip_sdb,	8,	35,	1,	10 },	/* SDB */
	{ &chip_sdb,	0,	43,	0,	11 },	/* SDB */
};

static jtag_ring_desc  cpu_mod_1m_ring = {
	12, cpu_mod_1m_ring_components
};

static jtag_phys_comp cpu_mod_ring_components[] = {
	{ &chip_spitfire, 31,	0,	7,	0 },	/* Spitfire */
	{ &chip_ec,	28,	8,	6,	1 },	/* Parity chip */
	{ &chip_ec,	25,	11,	5,	2 },	/* Byte 0 */
	{ &chip_ec,	22,	14,	4,	3 },	/* Byte 1 */
	{ &chip_ec,	19,	17,	3,	4 },	/* Byte 2 */
	{ &chip_ec,	16,	20,	2,	5 },	/* Byte 3 */
	{ &chip_sdb,	8,	23,	1,	6 },	/* SDB */
	{ &chip_sdb,	0,	31,	0,	7 },	/* SDB */
};

static jtag_ring_desc  cpu_mod_ring = {
	8, cpu_mod_ring_components
};

static jtag_phys_comp io1_sysbd_ring_components[] = {
	{ &chip_ac,	114,	0,	14,	0 },	/* AC */
	{ &chip_dc,	106,	8,	13,	1 },	/* DC 1 */
	{ &chip_dc,	98,	16,	12,	2 },	/* DC 2 */
	{ &chip_dc,	90,	24,	11,	3 },	/* DC 3 */
	{ &chip_dc,	82,	32,	10,	4 },	/* DC 4 */
	{ &chip_dc,	74,	40,	9,	5 },	/* DC 5 */
	{ &chip_dc,	66,	48,	8,	6 },	/* DC 6 */
	{ &chip_dc,	58,	56,	7,	7 },	/* DC 7 */
	{ &chip_dc,	50,	64,	6,	8 },	/* DC 8 */
	{ &chip_fhc,	42,	72,	5,	9 },	/* FHC */
	{ &chip_sio,	26,	80,	4,	10 },	/* SIO 0 */
	{ &chip_sio,	10,	96,	3,	11 },	/* SIO 1 */
	{ &chip_hm,	6,	112,	2,	12 },	/* HM */
	{ &chip_ndp,	4,	116,	1,	13 },	/* NDP */
	{ &chip_soc,	0,	118,	0,	14 },	/* SOC */
};

static jtag_phys_comp io2_sysbd_ring_components[] = {
	{ &chip_ac,	98,	0,	13,	0 },	/* AC */
	{ &chip_dc,	90,	8,	12,	1 },	/* DC 1 */
	{ &chip_dc,	82,	16,	11,	2 },	/* DC 2 */
	{ &chip_dc,	74,	24,	10,	3 },	/* DC 3 */
	{ &chip_dc,	66,	32,	9,	4 },	/* DC 4 */
	{ &chip_dc,	58,	40,	8,	5 },	/* DC 5 */
	{ &chip_dc,	50,	48,	7,	6 },	/* DC 6 */
	{ &chip_dc,	42,	56,	6,	7 },	/* DC 7 */
	{ &chip_dc,	34,	64,	5,	8 },	/* DC 8 */
	{ &chip_fhc,	26,	72,	4,	9 },	/* FHC */
	{ &chip_sio,	10,	80,	3,	10 },	/* SIO */
	{ &chip_hm,	6,	96,	2,	11 },	/* HM */
	{ &chip_ndp,	4,	100,	1,	12 },	/* NDP */
	{ &chip_soc,	0,	102,	0,	13 },	/* SOC */
};

static jtag_phys_comp io1plus_sysbd_ring_components[] = {
	{ &chip_ac,	118,	0,	14,	0 },	/* AC */
	{ &chip_dc,	110,	8,	13,	1 },	/* DC 1 */
	{ &chip_dc,	102,	16,	12,	2 },	/* DC 2 */
	{ &chip_dc,	94,	24,	11,	3 },	/* DC 3 */
	{ &chip_dc,	86,	32,	10,	4 },	/* DC 4 */
	{ &chip_dc,	78,	40,	9,	5 },	/* DC 5 */
	{ &chip_dc,	70,	48,	8,	6 },	/* DC 6 */
	{ &chip_dc,	62,	56,	7,	7 },	/* DC 7 */
	{ &chip_dc,	54,	64,	6,	8 },	/* DC 8 */
	{ &chip_fhc,	46,	72,	5,	9 },	/* FHC */
	{ &chip_sio,	30,	80,	4,	10 },	/* SIO 0 */
	{ &chip_sio,	14,	96,	3,	11 },	/* SIO 1 */
	{ &chip_hm,	10,	112,	2,	12 },	/* HM */
	{ &chip_ndp,	8,	116,	1,	13 },	/* NDP */
	{ &chip_socplus, 0,	118,	0,	14 },	/* SOC+ */
};

static jtag_phys_comp io2plus_sysbd_ring_components[] = {
	{ &chip_ac,	102,	0,	13,	0 },	/* AC */
	{ &chip_dc,	94,	8,	12,	1 },	/* DC 1 */
	{ &chip_dc,	86,	16,	11,	2 },	/* DC 2 */
	{ &chip_dc,	78,	24,	10,	3 },	/* DC 3 */
	{ &chip_dc,	70,	32,	9,	4 },	/* DC 4 */
	{ &chip_dc,	62,	40,	8,	5 },	/* DC 5 */
	{ &chip_dc,	54,	48,	7,	6 },	/* DC 6 */
	{ &chip_dc,	46,	56,	6,	7 },	/* DC 7 */
	{ &chip_dc,	38,	64,	5,	8 },	/* DC 8 */
	{ &chip_fhc,	30,	72,	4,	9 },	/* FHC */
	{ &chip_sio,	14,	80,	3,	10 },	/* SIO */
	{ &chip_hm,	10,	96,	2,	11 },	/* HM */
	{ &chip_ndp,	8,	100,	1,	12 },	/* NDP */
	{ &chip_socplus, 0,	102,	0,	13 },	/* SOC+ */
};

static jtag_phys_comp io3_sysbd_ring_components[] = {
	{ &chip_ac,	102,	0,	15,	0 },	/* AC */
	{ &chip_dc,	94,	8,	14,	1 },	/* DC 1 */
	{ &chip_dc,	86,	16,	13,	2 },	/* DC 2 */
	{ &chip_dc,	78,	24,	12,	3 },	/* DC 3 */
	{ &chip_dc,	70,	32,	11,	4 },	/* DC 4 */
	{ &chip_dc,	62,	40,	10,	5 },	/* DC 5 */
	{ &chip_dc,	54,	48,	9,	6 },	/* DC 6 */
	{ &chip_dc,	46,	56,	8,	7 },	/* DC 7 */
	{ &chip_dc,	38,	64,	7,	8 },	/* DC 8 */
	{ &chip_fhc,	30,	72,	6,	9 },	/* FHC */
	{ &chip_psyo,	26,	80,	5,	10 },	/* PSYO 0 */
	{ &chip_cheo,	22,	84,	4,	11 },	/* CHEO */
	{ &chip_ndp,	20,	88,	3,	12 },	/* NDP */
	{ &chip_psyo,	16,	90,	2,	13 },	/* PSYO 1 */
	{ &chip_bct8244,	8,	94,	1,	14 },	/* BCT 8244 */
	{ &chip_bct8244,	0,	102,	0,	15 },	/* BCT 8244 */
};

static jtag_phys_comp dsk_sysbd_ring_components[] = {
	{ &chip_bct8244, 8,	0,	1,	0 },	/* BCT 8244 */
	{ &chip_fhc,	0,	8,	0,	1 },	/* FHC */
};

static jtag_ring_desc  io1_sysbd_ring = {
	15, io1_sysbd_ring_components
};

static jtag_ring_desc  io1plus_sysbd_ring = {
	15, io1plus_sysbd_ring_components
};

static jtag_ring_desc  io2_sysbd_ring = {
	14, io2_sysbd_ring_components
};

static jtag_ring_desc  io2plus_sysbd_ring = {
	14, io2plus_sysbd_ring_components
};

static jtag_ring_desc  io3_sysbd_ring = {
	16, io3_sysbd_ring_components
};

static jtag_ring_desc dsk_sysbd_ring = {
	2, dsk_sysbd_ring_components
};

/*
 * Ring descriptors for single and double buffered FFB boards.
 * Note - Only the FBC has a component ID register. None of the
 * other chips on the FFB board has one, so do not check them.
 */
static jtag_phys_comp ffb_sngl_ring_components[] = {
	{ &chip_fbc,	20,	0,	5,	0 },	/* FBC */
	{ &chip_3dram,	16,	16,	4,	1 },	/* 3DRAM */
	{ &chip_3dram,	12,	20,	3,	2 },	/* 3DRAM */
	{ &chip_3dram,	8,	24,	2,	3 },	/* 3DRAM */
	{ &chip_3dram,	4,	28,	1,	4 },	/* 3DRAM */
	{ &chip_bt498,	0,	32,	0,	5 },	/* RAMDAC */
};

static jtag_phys_comp ffb_dbl_ring_components[] = {
	{ &chip_fbc,	84,	0,	17,	0 },	/* FBC */
	{ &chip_lvt,	76,	16,	16,	1 },	/* LVT */
	{ &chip_lvt,	68,	24,	15,	2 },	/* LVT */
	{ &chip_lvt,	60,	32,	14,	3 },	/* LVT */
	{ &chip_lvt,	52,	40,	13,	4 },	/* LVT */
	{ &chip_3dram,	48,	48,	12,	5 },	/* 3DRAM */
	{ &chip_3dram,	44,	52,	11,	6 },	/* 3DRAM */
	{ &chip_3dram,	40,	56,	10,	7 },	/* 3DRAM */
	{ &chip_3dram,	36,	60,	9,	8 },	/* 3DRAM */
	{ &chip_3dram,	32,	64,	8,	9 },	/* 3DRAM */
	{ &chip_3dram,	28,	68,	7,	10 },	/* 3DRAM */
	{ &chip_3dram,	24,	72,	6,	11 },	/* 3DRAM */
	{ &chip_3dram,	20,	76,	5,	12 },	/* 3DRAM */
	{ &chip_3dram,	16,	80,	4,	13 },	/* 3DRAM */
	{ &chip_3dram,	12,	84,	3,	14 },	/* 3DRAM */
	{ &chip_3dram,	8,	88,	2,	15 },	/* 3DRAM */
	{ &chip_3dram,	4,	92,	1,	16 },	/* 3DRAM */
	{ &chip_bt498,	0,	96,	0,	17 },	/* RAMDAC */
};

static jtag_ring_desc ffb_sngl_ring = {
	6, ffb_sngl_ring_components
};

static jtag_ring_desc ffb_dbl_ring = {
	18, ffb_dbl_ring_components
};

/*
 *    Board descriptions
 */

static jtag_ring_desc *cpu_system_board[] = {
	&cpu_sysbd_ring,		/* Ring 0 */
	&cpu_mod_ring,			/* Ring 1 */
	&cpu_mod_ring,			/* Ring 2 */
};

static jtag_ring_desc *io1_system_board[] = {
	&io1_sysbd_ring,			/* Ring 0 */
	(jtag_ring_desc *) NULL,		/* Ring 1 */
	(jtag_ring_desc *) NULL,		/* Ring 2 */
};

static jtag_ring_desc *io1plus_system_board[] = {
	&io1plus_sysbd_ring,			/* Ring 0 */
	(jtag_ring_desc *) NULL,		/* Ring 1 */
	(jtag_ring_desc *) NULL,		/* Ring 2 */
};

static jtag_ring_desc *io2_system_board[] = {
	&io2_sysbd_ring,			/* Ring 0 */
	(jtag_ring_desc *) NULL,		/* Ring 1 (ffb) */
	(jtag_ring_desc *) NULL,		/* Ring 2  */
};

static jtag_ring_desc *io2plus_system_board[] = {
	&io2plus_sysbd_ring,			/* Ring 0 */
	(jtag_ring_desc *) NULL,		/* Ring 1 (ffb) */
	(jtag_ring_desc *) NULL,		/* Ring 2  */
};

static jtag_ring_desc *io3_system_board[] = {
	&io3_sysbd_ring,			/* Ring 0 */
	(jtag_ring_desc *) NULL,		/* Ring 1 */
	(jtag_ring_desc *) NULL,		/* Ring 2 */
};

static jtag_ring_desc *disk_system_board[] = {
	&dsk_sysbd_ring,			/* Ring 0 */
	(jtag_ring_desc *) NULL,		/* Ring 1 */
	(jtag_ring_desc *) NULL,		/* Ring 2 */
};

/*
 * Function Definitions:
 * ---------------------
 */

/* For sunfire there will be a ring descriptor for each type of board */
static jtag_ring_desc *
get_ring_descriptor_bytype(int ring, enum board_type type)
{

	switch (type) {
	case CPU_BOARD:
		return (cpu_system_board[ring & 0xf]);

	case IO_2SBUS_BOARD:
		return (io1_system_board[ring & 0xf]);

	case IO_2SBUS_SOCPLUS_BOARD:
		return (io1plus_system_board[ring & 0xf]);

	case IO_SBUS_FFB_BOARD:
		return (io2_system_board[ring & 0xf]);

	case IO_SBUS_FFB_SOCPLUS_BOARD:
		return (io2plus_system_board[ring & 0xf]);

	case IO_PCI_BOARD:
		return (io3_system_board[ring & 0xf]);

	case DISK_BOARD:
		return (disk_system_board[ring & 0xf]);

	default:
		return (NULL);
	}
}

static void
jtag_check_plus_board(
	volatile u_int *jreg,
	jtag_ring ring,
	jtag_phys_comp *comp,
	sysc_cfga_stat_t *sc)
{
	struct fhc_regs fhc_data;

	/*
	 * the FHC Board Status Register indicates whether
	 * the board 100 Mhz capable or not.
	 */
	fhc_data.bsr = (u_int)0xffffffff;

	if ((jtag_scanout_chip(jreg, ring, comp, (u_int *)&fhc_data) >= 0) &&
	    (FHC_BSR_TO_BD(fhc_data.bsr) == sc->board) &&
	    ISPLUSBRD(fhc_data.bsr))
		sc->plus_board = 1;
}

/*
 * Returns (positive) board type if something detected, including
 * UNKNOWN_BOARD.
 * Returns -1 if nothing there.
 */
enum board_type
jtag_get_board_type(volatile u_int *jreg, sysc_cfga_stat_t *sc)
{
	int len;
	int ring;
	int result;
	int board;
	int status;

	/*
	 * Select Board Ring 0 to scan. This contains the AC, FHC,
	 * and DC ASICs
	 */

	/*
	 * Ring number is JTAG Board (7:4) and ring number (3:0)
	 */
	board = sc->board;
	ring = (board << 4) | 0;

	if ((status = select_ring(jreg, ring, 1)) < 0) {
		cmn_err(CE_WARN, "Select ring error %d\n", status);
	}

	len = jtag_ring_length(jreg, ring);
	switch (len) {
	case CPU_TYPE_LEN:
		result = CPU_BOARD;

		jtag_check_plus_board(jreg, ring,
			&cpu_sysbd_ring_components[9], sc);

		break;

	case IO_TYPE1_LEN:
		switch (jtag_ring_ir_length(jreg, ring)) {
		case RING_BROKEN:
			result = UNKNOWN_BOARD;
			break;
		case IO_TYPE4_LEN:
			result = IO_2SBUS_SOCPLUS_BOARD;
			jtag_check_plus_board(jreg, ring,
			    &io1plus_sysbd_ring_components[9], sc);
			break;
		default:
			result = IO_2SBUS_BOARD;
			jtag_check_plus_board(jreg, ring,
			    &io1_sysbd_ring_components[9], sc);
			break;
		}

		break;

	case IO_TYPE2_LEN:
		switch (jtag_ring_ir_length(jreg, ring)) {
		case RING_BROKEN:
			result = UNKNOWN_BOARD;
			break;
		case IO_TYPE5_LEN:
			result = IO_SBUS_FFB_SOCPLUS_BOARD;
			jtag_check_plus_board(jreg, ring,
			    &io2plus_sysbd_ring_components[9], sc);
			break;
		default:
			result = IO_SBUS_FFB_BOARD;
			jtag_check_plus_board(jreg, ring,
			    &io2_sysbd_ring_components[9], sc);
			break;
		}

		break;

	case PCI_TYPE_LEN:
		switch (jtag_ring_ir_length(jreg, ring)) {
		case RING_BROKEN:
			result = UNKNOWN_BOARD;
			break;
		case PCI_TYPEA_LEN:
			result = IO_PCI_BOARD;
			jtag_check_plus_board(jreg, ring,
			    &io3_sysbd_ring_components[9], sc);
			break;
		case PCI_TYPEB_LEN:
		default:
			result = UNKNOWN_BOARD;
			break;
		}
		break;

	case DSK_TYPE_LEN:
		result = DISK_BOARD;
		break;

	case RING_BROKEN:
		result = -1;
		break;

	default:
		result = UNKNOWN_BOARD;
		break;
	}

	TAP_ISSUE_CMD(jreg, JTAG_TAP_RESET, status);

	return (result);
}

#ifndef RFE_4174486
/*
 * Until the RFE is fully investigated the likelyhood is that the
 * CPU frequency may be incorrectly displayed. Coupled with the lack of
 * Ecache size information and no information at all unless the
 * CPU board is physically plugged in, the default is not to get any
 * CPU information.
 * This patchable flag is provided so that more testing can be done
 * without re-compilation.
 */
static int jtag_cpu_scan_enable = 0;
#endif /* RFE_4174486 */

int
jtag_get_board_info(volatile u_int *jreg, sysc_cfga_stat_t *sc)
{
	jtag_ring_desc *rd;
	jtag_phys_comp *rc;
	int status;
	int ring;
	int len;
	int i;
	struct cpu_info *cpu;
	struct bct_fields bct_data;

	/* fill in the board info structure */

	ring = sc->board << 4;

	if ((status = select_ring(jreg, ring, 1)) < 0) {
		return (status);
	}

	rd = get_ring_descriptor_bytype(ring, sc->type);

	if (rd == NULL) {
		return (JTAG_FAIL);
	}

	/* scan in the generic data common to all board types. */

	/* get the AC component ID */
	rc = find_chip(rd, &chip_ac, 0);
	if (rc != NULL) {
		sc->ac_compid = jtag_get_comp_id(jreg, rc);
	}

	/* get the FHC component ID */
	rc = find_chip(rd, &chip_fhc, 0);
	if (rc != NULL) {
		sc->fhc_compid = jtag_get_comp_id(jreg, rc);
	}

	/* Now scan the board type dependent components */
	switch (sc->type) {
	case CPU_BOARD:
		/*
		 * first determine the cache size of each module, then
		 * use that ring descriptor.
		 */

		for (i = 0, cpu = &sc->bd.cpu[i]; i < 2; i++, cpu++) {
			bzero(cpu, sizeof (*cpu));
#ifndef RFE_4174486
			if (!jtag_cpu_scan_enable)
				continue;
#endif /* RFE_4174486 */
			if (select_ring(jreg, ring | (i + 1), 1) < 0) {
				continue;
			}

			len = jtag_ring_length(jreg, ring | (i + 1));

			switch (len) {
			case CPU_0_5_LEN:
				rd = &cpu_mod_ring;
				cpu->cpu_detected = 1;
				break;

			case CPU_1_0_LEN:
				rd = &cpu_mod_1m_ring;
				cpu->cpu_detected = 1;
				break;

			case RING_BROKEN:
			default:
				rd = NULL;
				break;
			}

			if (!cpu->cpu_detected)
				continue;

			if (rd != NULL) {
				rc = find_chip(rd, &chip_spitfire, 0);
				if (rc != NULL) {
					cpu->cpu_compid =
						jtag_get_comp_id(jreg, rc);
				}

				/*
				 * Do not get the component ID from the
				 * first E$ chip. This is the tag chip
				 * and does not help determine cache size.
				 */
				rc = find_chip(rd, &chip_ec, 1);
				if (rc != NULL) {
					cpu->ec_compid =
						jtag_get_comp_id(jreg, rc);
				}

				rc = find_chip(rd, &chip_sdb, 0);
				if (rc != NULL) {
					cpu->sdb0_compid =
						jtag_get_comp_id(jreg, rc);
				}

				rc = find_chip(rd, &chip_sdb, 1);
				if (rc != NULL) {
					cpu->sdb1_compid =
						jtag_get_comp_id(jreg, rc);
				}
			}

#ifdef RFE_4174486
			/* Work out Ecache size. */
			switch (len) {
			case CPU_0_5_LEN:
				cpu->cache_size = 0x80000;
				break;

			case CPU_1_0_LEN:
				/* default cache size for 9 SRAM chips */
				cpu->cache_size = 0x100000;
				break;

			default:
				break;
			}
#endif /* RFE_4174486 */
		}

		break;

	case IO_2SBUS_BOARD:
		rc = find_chip(rd, &chip_sio, 0);
		if (rc != NULL) {
			sc->bd.io1.sio0_compid =
				jtag_get_comp_id(jreg, rc);
		}

		rc = find_chip(rd, &chip_sio, 1);
		if (rc != NULL) {
			sc->bd.io1.sio1_compid =
				jtag_get_comp_id(jreg, rc);
		}

		rc = find_chip(rd, &chip_hm, 0);
		if (rc != NULL) {
			sc->bd.io1.hme_compid = jtag_get_comp_id(jreg, rc);
		}

		rc = find_chip(rd, &chip_soc, 0);
		if (rc != NULL) {
			sc->bd.io1.soc_compid = jtag_get_comp_id(jreg, rc);
		}

		break;

	case IO_2SBUS_SOCPLUS_BOARD:
		rc = find_chip(rd, &chip_sio, 0);
		if (rc != NULL) {
			sc->bd.io1.sio0_compid =
				jtag_get_comp_id(jreg, rc);
		}

		rc = find_chip(rd, &chip_sio, 1);
		if (rc != NULL) {
			sc->bd.io1.sio1_compid =
				jtag_get_comp_id(jreg, rc);
		}

		rc = find_chip(rd, &chip_hm, 0);
		if (rc != NULL) {
			sc->bd.io1.hme_compid = jtag_get_comp_id(jreg, rc);
		}

		rc = find_chip(rd, &chip_socplus, 0);
		if (rc != NULL) {
			sc->bd.io1plus.socplus_compid =
					jtag_get_comp_id(jreg, rc);
		}

		break;

	case IO_SBUS_FFB_BOARD:
		rc = find_chip(rd, &chip_sio, 0);
		if (rc != NULL) {
			sc->bd.io2.sio1_compid = jtag_get_comp_id(jreg, rc);
		}

		rc = find_chip(rd, &chip_hm, 0);
		if (rc != NULL) {
			sc->bd.io2.hme_compid = jtag_get_comp_id(jreg, rc);
		}

		rc = find_chip(rd, &chip_soc, 0);
		if (rc != NULL) {
			sc->bd.io2.soc_compid = jtag_get_comp_id(jreg, rc);
		}

		/* Now scan for an FFB board */
		if (select_ring(jreg, ring | 1, 1) < 0) {
			len = RING_BROKEN;
		} else {
			len = jtag_ring_length(jreg, ring | 1);
		}

		switch (len) {
		case FFB_SNG_LEN:
			rd = &ffb_sngl_ring;
			sc->bd.io2.ffb_size = FFB_SINGLE;
			break;

		case FFB_DBL_LEN:
			rd = &ffb_dbl_ring;
			sc->bd.io2.ffb_size = FFB_DOUBLE;
			break;

		case RING_BROKEN:
			rd = NULL;
			sc->bd.io2.ffb_size = FFB_NOT_FOUND;
			break;

		default:
			rd = NULL;
			sc->bd.io2.ffb_size = FFB_FAILED;
			break;
		}

		/* Now scan out the FBC component ID */
		if (rd != NULL) {
			rc = find_chip(rd, &chip_fbc, 0);
		}

		if (rc != NULL) {
			sc->bd.io2.fbc_compid = jtag_get_comp_id(jreg, rc);
		}
		break;

	case IO_SBUS_FFB_SOCPLUS_BOARD:
		rc = find_chip(rd, &chip_sio, 0);
		if (rc != NULL) {
			sc->bd.io2.sio1_compid = jtag_get_comp_id(jreg, rc);
		}

		rc = find_chip(rd, &chip_hm, 0);
		if (rc != NULL) {
			sc->bd.io2.hme_compid = jtag_get_comp_id(jreg, rc);
		}

		rc = find_chip(rd, &chip_socplus, 0);
		if (rc != NULL) {
			sc->bd.io2plus.socplus_compid =
				jtag_get_comp_id(jreg, rc);
		}

		/* Now scan for an FFB board */
		if (select_ring(jreg, ring | 1, 1) < 0) {
			len = RING_BROKEN;
		} else {
			len = jtag_ring_length(jreg, ring | 1);
		}

		switch (len) {
		case FFB_SNG_LEN:
			rd = &ffb_sngl_ring;
			sc->bd.io2.ffb_size = FFB_SINGLE;
			break;

		case FFB_DBL_LEN:
			rd = &ffb_dbl_ring;
			sc->bd.io2.ffb_size = FFB_DOUBLE;
			break;

		case RING_BROKEN:
			rd = NULL;
			sc->bd.io2.ffb_size = FFB_NOT_FOUND;
			break;

		default:
			rd = NULL;
			sc->bd.io2.ffb_size = FFB_FAILED;
			break;
		}

		/* Now scan out the FBC component ID */
		if (rd != NULL) {
			rc = find_chip(rd, &chip_fbc, 0);
		}

		if (rc != NULL) {
			sc->bd.io2.fbc_compid = jtag_get_comp_id(jreg, rc);
		}
		break;

	case IO_PCI_BOARD:
		rc = find_chip(rd, &chip_psyo, 0);
		if (rc != NULL) {
			sc->bd.io3.psyo0_compid =
				jtag_get_comp_id(jreg, rc);
		}

		rc = find_chip(rd, &chip_psyo, 1);
		if (rc != NULL) {
			sc->bd.io3.psyo1_compid =
				jtag_get_comp_id(jreg, rc);
		}

		rc = find_chip(rd, &chip_cheo, 0);
		if (rc != NULL) {
			sc->bd.io3.cheo_compid = jtag_get_comp_id(jreg, rc);
		}

		break;

	case DISK_BOARD:
		/*
		 * Scan the BCT8244 to get the disk drive info out of
		 * the chip.
		 */
		if (jtag_scanout_chip(jreg, ring,
		    &dsk_sysbd_ring_components[0], (u_int *)&bct_data) < 0) {
			TAP_ISSUE_CMD(jreg, JTAG_TAP_RESET, status);
			return (-1);
		}

		if ((bct_data.disk0_pres && 0x1) == 0) {
			sc->bd.dsk.disk_pres[0] = 1;
			sc->bd.dsk.disk_id[0] = 0xf & ~bct_data.disk0_id;
		} else {
			sc->bd.dsk.disk_pres[0] = 0;
		}

		if ((bct_data.disk1_pres && 0x1) == 0) {
			sc->bd.dsk.disk_pres[1] = 1;
			sc->bd.dsk.disk_id[1] = 0xf & ~bct_data.disk1_id;
		} else {
			sc->bd.dsk.disk_pres[1] = 0;
		}

		break;

	default:
		break;
	}

	return (JTAG_OK);
}

static jtag_phys_comp *
find_chip(jtag_ring_desc *rd, jtag_log_comp *chip, int instance)
{
	int i;
	int found = 0;
	jtag_phys_comp *rc;

	for (i = rd->size, rc = rd->components; i != 0; rc++, i--) {
		if (rc->chip == chip) {
			if (found == instance) {
				return (rc);
			} else {
				found++;
			}
		}
	}
	return (NULL);
}

/*
 * Function jtag_error() :
 *
 *	This function centrailizes the use of the JTAG error strings.
 * It should be called with the JTAG error code anytime the programmer
 * wants to print the type of JTAG error encountered. Just call with the
 * error code returned by the JTAG function. If no error occurred, nothing
 * is printed.
 */
static void
jtag_error_print(int ring, jtag_error code)
{
	char *ring_str = "System Board";

	switch (code) {
	case JTAG_OK :
		break;

	case TAP_TIMEOUT :
		cmn_err(CE_WARN, "%s : TAP controller timeout\n", jtag_err);
		break;

	case BAD_ARGS :
		cmn_err(CE_WARN,
			"%s : routine reports bad args: Board %d, %s Ring\n",
			jtag_err, ring >> 4, ring_str);
		break;

	case BAD_CID :
		cmn_err(CE_WARN,
			"%s : Bad component ID detected: Board %d, %s Ring\n",
			jtag_err, ring >> 4, ring_str);
		break;

	case RING_BROKEN :
		cmn_err(CE_WARN, "%s : ring broken: Board %d, %s Ring\n",
			jtag_err, ring >> 4, ring_str);
		break;

	case INIT_MISMATCH:
		cmn_err(CE_WARN,
			"%s : State after init not expected: Board %d, "
			"%s Ring\n", jtag_err, ring >> 4, ring_str);
		break;

	case LENGTH_MISMATCH :
		cmn_err(CE_WARN,
			"%s : Scan Chain Length mismatch: Board %d,"
			" %s Ring\n",
			jtag_err, ring >> 4, ring_str);
		break;

	}	/* end of switch on code */
}	/* end of jtag_error_print() */


static int
jtag_get_comp_id(volatile u_int *jreg, jtag_phys_comp *comp)
{
	u_char b[4];
	u_int id;
	int status;

	status = jtag_single_IR_DR(jreg, comp, comp->chip->id_code,
		b, 32, b);

	/* Reorder the bytes of the ID read out */
	id = b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);

	if (status < 0) {
		return (0);
	} else {
		return (id);
	}
}

/*
 *    Bit-manipulation routines
 */

/*
 * jtag_bf_extract()
 *
 * This routine extracts bit strings from JTAG data scanout strings. This
 * routine is used to decode data scanned out of chips via JTAG.
 */
static u_int
jtag_bf_extract(u_char *s, int lsb, int msb)
{
	u_int result = 0;

	ASSERT(s);

	/*
	 * lsb and msb are assumed to be within string,
	 * and to span 32 bits at most
	 */
	for (; msb >= lsb; msb--) {
		result = (result << 1) | ((s[msb>>3] >> (msb & 7)) & 1);
	}
	return (result);
}

/*
 * jtag_bf_insert()
 *
 * This routine is used to build bit strings for scanning into the
 * shadow chains of ASICs.
 */
static void
jtag_bf_insert(u_char *s, int lsb, int msb, int value)
{
	ASSERT(s);

	/*
	 * lsb and msb are assumed to be within string,
	 * and to span 32 bits at most
	 */

	for (; msb >= lsb; lsb++) {
		s[lsb>>3] = (s[lsb>>3] & ~ (1 << (lsb & 7))) |
			((value & 1) << (lsb & 7));
		value = value >> 1;
	}
}

/*
 *
 */
static void
jtag_bf_zero(u_char *s, int nbits)
{
	int nbytes = (nbits+7)>>3;

	while (nbytes-- != 0) {
		*s++ = 0;
	}
}

/*
 * Return 0 if equal, != 0 else
 */
static int
jtag_bf_cmp(u_char *s1, u_char *s2, int nbits)
{
	int mask;
	for (nbits -= 8; nbits > 0; nbits -= 8) {
		if (*s1++ != *s2++) {
			return (-1);
		}
		mask = 0xFF >> (-nbits);
		if ((*s1++ & mask) != (*s2++ & mask)) {
			return (-1);
		}
	}

	return (0);
}


/*
 * Generic chip-level top routines
 */
static int
jtag_init_chip(
	volatile u_int *jreg,
	jtag_ring ring,
	jtag_phys_comp *component,
	const u_int *pval,
	u_char scan_out[32])
{
	int status;
	jtag_log_comp *chip;
	u_char scan_in[32];
	u_char *pdesc;

	status = select_ring(jreg, ring, 1);
	if (status < 0) {
		return (status);
	}

	pval = pval - 1; /* adjust pval since indices start at 1 */
	chip = component->chip;
	pdesc = chip->init_pdesc;

	/* Zero out the scan-in area */
	jtag_bf_zero(scan_in, 8*32);
	jtag_bf_zero(scan_out, 8*32);

	for (;;) {
		u_int flags, lsb, msb, patch;
		flags = *pdesc++;
		if ((flags & JTIN_INSERT) != 0) {
			lsb = *pdesc++;
			msb = *pdesc++;
			if ((flags & JTIN_INDEX) != 0) {
				patch = pval[flags & JTIN_INDEX];
			} else {
				patch = *pdesc++;
			}
			jtag_bf_insert(scan_in, lsb, msb, patch);
		}

		if ((flags & JTIN_UPDATE) != 0) {
			status = jtag_single_IR_DR(jreg, component,
				chip->init_code, scan_in, chip->dr_len,
				scan_out);

			if (status < 0) {
				return (status);
			}

			if ((status = select_ring(jreg, ring, 1)) < 0) {
				return (status);
			}
		}

		if ((flags & JTIN_COMPARE) != 0) {
			if (jtag_bf_cmp(scan_in, scan_out, chip->dr_len) != 0)
				return (INIT_MISMATCH);
		}

		if ((flags & JTIN_END) != 0) {
			break;
		}
	}

	return (JTAG_OK);    /* all is OK... */
}

/*
 * Dump the info from a chip.
 * Return the number of bytes used, or <0 if failed
 */
static int
jtag_scanout_chip(
	volatile u_int *jreg,
	jtag_ring ring,
	jtag_phys_comp *component,
	u_int *result)
{
	int status;
	jtag_log_comp *chip;
	u_char scan_in[32];
	u_char scan_out[32];
	u_char *p;
	u_int value;
	int bytes_used = 0;

	if ((status = select_ring(jreg, ring, 1)) < 0) {
		return (status);
	}

	chip = component->chip;

	p = chip->fmt_desc;
	if (p == NULL) {
		return (bytes_used);
	}

	status = jtag_rescan_IR_DR(jreg, component, chip->dump_code, scan_in,
		chip->dr_len, scan_out);

	if (status < 0) {
		return (status);
	}

	if ((status = select_ring(jreg, ring, 1)) < 0) {
		return (status);
	}

	for (value = 0; ; ) {
		u_char cmd = *p++;

		if ((cmd & JTSO_XTRACT) != 0) {
			u_int lsb, msb;
			lsb = *p++;
			msb = *p++;
			value |= jtag_bf_extract(scan_out, lsb, msb) <<
				(cmd & JTSO_SHIFT);
		}

		if ((cmd & JTSO_ST) != 0) {
			*result++ = value;
			bytes_used += 4;
			value = 0;
		}

		if ((cmd & JTSO_END) != 0) {
			break;
		}
	}
	return (bytes_used);
}

/*
 * Set the AC into hotplug mode upon insertion
 */
static int
jtag_init_ac(volatile u_int *jreg, int bid, enum board_type brdtype)
{
	int rc = JTAG_OK;
	int status;
	int ring = (bid << 4);
	ac_options ac_opt;
	u_char scan_out[64];
	uint_t cs_value;

	if (brdtype == UNKNOWN_BOARD)
		return (rc);

	ac_opt.frozen = 0;	/* 0 = frozen */
	ac_opt.reset_a = 1;
	ac_opt.reset_b = 1;
	ac_opt.board_id = bid;
	ac_opt.mask_hwerr = (uint_t)-1;
	ac_opt.node_id = 3;

	/* Get a good AC BCSR value from the board we are running on. */
	cs_value = ldphysio(AC_BCSR(FHC_CPU2BOARD(CPU->cpu_id)));

	ac_opt.arb_fast = (cs_value & AC_ARB_FAST) ? 1 : 0;
	ac_opt.pcr_hi = 0;
	ac_opt.pcr_lo = 0x80000000LL - 0x9ac4  - (bid << 3);
	ac_opt.pcc_ctl0 = 0x3f;
	ac_opt.pcc_ctl1 = 0x3f;
	ac_opt.pcc_tctrl = (1 << 11); /* TREN */

	if ((brdtype == CPU_BOARD) || (brdtype == MEM_BOARD)) {
		rc = jtag_init_chip(jreg, ring, &cpu_sysbd_ring_components[0],
			(jtag_opt)&ac_opt, scan_out);
	} else if (brdtype == IO_2SBUS_BOARD) {
		rc = jtag_init_chip(jreg, ring, &io1_sysbd_ring_components[0],
			(jtag_opt)&ac_opt, scan_out);
	} else if (brdtype == IO_2SBUS_SOCPLUS_BOARD) {
		rc = jtag_init_chip(jreg, ring,
			&io1plus_sysbd_ring_components[0],
			(jtag_opt)&ac_opt, scan_out);
	} else if (brdtype == IO_SBUS_FFB_BOARD) {
		rc = jtag_init_chip(jreg, ring, &io2_sysbd_ring_components[0],
			(jtag_opt)&ac_opt, scan_out);
	} else if (brdtype == IO_SBUS_FFB_SOCPLUS_BOARD) {
		rc = jtag_init_chip(jreg, ring,
			&io2plus_sysbd_ring_components[0],
			(jtag_opt)&ac_opt, scan_out);
	} else if (brdtype == IO_PCI_BOARD) {
		rc = jtag_init_chip(jreg, ring, &io3_sysbd_ring_components[0],
			(jtag_opt)&ac_opt, scan_out);
	} else {
		cmn_err(CE_NOTE, " jtag_init_ac() Board %d"
		    " unsupported type %2X", bid, brdtype);
	}

	TAP_ISSUE_CMD(jreg, JTAG_TAP_RESET, status);

	if (rc != JTAG_OK) {
		jtag_error_print(ring, rc);
	}

	return (rc);
}

#define	EN_LOC_FATAL		0x02
#define	MOD_OFF			0x80
#define	ACDC_OFF		0x40
#define	EPDA_OFF		0x10
#define	EPDB_OFF		0x08
#define	NOT_BRD_PRESENT		0x02
#define	NOT_BRD_LED_LEFT	0x04
#define	BRD_LED_MID		0x02
#define	BRD_LED_RIGHT		0x01

/*
 * Each board has an FHC asic.
 */
int
jtag_powerdown_board(volatile u_int *jreg, int board, enum board_type type,
	u_int *fhc_csr, u_int *fhc_bsr, int intr)
{
	int rc = JTAG_OK;
	fhc_options fhc_opt;
	struct fhc_regs fhc_data;
	u_char scan_out[32];
	int status;
	int ring;

	if (type == UNKNOWN_BOARD) {
		sysc_cfga_stat_t asc;

		bzero(&asc, sizeof (asc));
		asc.board = board;
		type = jtag_get_board_type(jreg, &asc);
	}

	if (!intr)
		(void) jtag_init_ac(jreg, board, type);

	ring = board << 4;

	fhc_opt.csr_hi = 0;
	fhc_opt.csr_mid = MOD_OFF | EPDA_OFF | EPDB_OFF | NOT_BRD_PRESENT;
	if (intr) {
		/*
		 * by not setting NOT_BRD_PRESENT we can simulate a board
		 * insertion
		 */
		fhc_opt.csr_mid &= ~NOT_BRD_PRESENT;
	}

	fhc_opt.csr_midlo = NOT_BRD_LED_LEFT | BRD_LED_MID;

	if ((type == CPU_BOARD) || (type == MEM_BOARD)) {
		rc = jtag_init_chip(jreg, ring, &cpu_sysbd_ring_components[9],
			(jtag_opt)&fhc_opt, scan_out);
	} else if (type == IO_2SBUS_BOARD) {
		rc = jtag_init_chip(jreg, ring, &io1_sysbd_ring_components[9],
			(jtag_opt)&fhc_opt, scan_out);
	} else if (type == IO_2SBUS_SOCPLUS_BOARD) {
		rc = jtag_init_chip(jreg, ring,
			&io1plus_sysbd_ring_components[9],
			(jtag_opt)&fhc_opt, scan_out);
	} else if (type == IO_SBUS_FFB_BOARD) {
		rc = jtag_init_chip(jreg, ring, &io2_sysbd_ring_components[9],
			(jtag_opt)&fhc_opt, scan_out);
	} else if (type == IO_SBUS_FFB_SOCPLUS_BOARD) {
		rc = jtag_init_chip(jreg, ring,
			&io2plus_sysbd_ring_components[9],
			(jtag_opt)&fhc_opt, scan_out);
	} else if (type == IO_PCI_BOARD) {
		rc = jtag_init_chip(jreg, ring, &io3_sysbd_ring_components[9],
			(jtag_opt)&fhc_opt, scan_out);
	} else if (type == UNKNOWN_BOARD) {
		rc = jtag_init_chip(jreg, ring, &cpu_sysbd_ring_components[9],
			(jtag_opt)&fhc_opt, scan_out);
	} else {
		cmn_err(CE_WARN, "Unsupported Board type %2X\n",
			fhc_bd_type(board));
	}

	TAP_ISSUE_CMD(jreg, JTAG_TAP_RESET, status);

	if (rc != JTAG_OK) {
		jtag_error_print(ring, rc);
	}

	/* Reformat the FHC shadow chain scan data */
	format_chip_data(chip_fhc.fmt_desc, (u_int *)&fhc_data,
		scan_out);

	*fhc_csr = fhc_data.csr;
	*fhc_bsr = fhc_data.bsr;


	return (rc);
}

/*
 * This function performs the fhc initialization for a disk board. The
 * hotplug variable tells the function whether to put the LED into low
 * power mode or not.
 */
int
jtag_init_disk_board(volatile u_int *jreg, int board,
	u_int *fhc_csr, u_int *fhc_bsr)
{
	int rc = JTAG_OK;
	fhc_options fhc_opt;
	struct fhc_regs fhc_data;
	u_char scan_out[32];
	int status;
	int ring;

	ring = board << 4;

	fhc_opt.csr_hi = 0;
	fhc_opt.csr_mid = NOT_BRD_PRESENT;
	fhc_opt.csr_midlo = NOT_BRD_LED_LEFT | BRD_LED_MID;

	rc = jtag_init_chip(jreg, ring, &dsk_sysbd_ring_components[1],
		(jtag_opt)&fhc_opt, scan_out);

	TAP_ISSUE_CMD(jreg, JTAG_TAP_RESET, status);

	if (rc != JTAG_OK) {
		jtag_error_print(ring, rc);
		return (-1);
	}

	/* Reformat the FHC shadow chain scan data */
	format_chip_data(chip_fhc.fmt_desc, (u_int *)&fhc_data,
		scan_out);

	*fhc_csr = fhc_data.csr;
	*fhc_bsr = fhc_data.bsr;

	return (0);
}

/*
 * NOTES:
 *	1. Scan data streams are little-endian sequences of bytes: byte 0
 *	   will provide the 8 lsb of the scan chain, and so on. If the last
 *	   byte is not full (count not a multiple of 8), the least significant
 *	   bits are used.
 *	2. All procedures assume that the JTAG control register
 *	   is non-busy on entry, and return with the control register
 *	   non-busy. It is a good idea to call tap_wait as part of the JTAG
 *	   sanity check sequence to verify there is no obvious malfunction.
 */


/*
 *	Non-data TAP commands
 */

/*
 * Wait for the TAP to be idle.
 * Return <0 if error, >=0 if OK.
 */

int
tap_wait(volatile u_int *jreg)
{
	TAP_DECLARE;
	TAP_WAIT(jreg);
	return (JTAG_OK);
}

/*
 * Send a TAP command, wait for completion.
 * Return <0 if error, >=0 if OK.
 */

static int
tap_issue_cmd(volatile u_int *jreg, u_int command)
{
	TAP_DECLARE;

	*jreg = command;
	TAP_WAIT(jreg);
	return (JTAG_OK);
}

/*
 *	Data TAP commands
 */

/*
 * Shift 1 to 16 bits into the component.
 * Return <0 if error, the shifted out bits (always >=0) if OK.
 */

int
tap_shift_single(volatile u_int *jreg, int data, int nbits)
{
	/* Return <0 if error, >0 (16-bit data) if OK */
	TAP_DECLARE;
	TAP_SHIFT(jreg, data, nbits);
	return (jtag_data(jreg, nbits));
}

/*
 * Shift the required number of bits from in into the component,
 * retrieve the bits shifted out.
 * Return <0 if error, >=0 if OK.
 */

int
tap_shift_multiple(
	volatile u_int *jreg,
	u_char *data_in,
	int nbits,
	u_char *data_out)    /* data_out may be NULL if not needed */
{
	TAP_DECLARE;

	/*
	 * The loop is done a byte at a time to avoid stepping out
	 * of the caller's buffer
	 */
	for (; nbits > 0; nbits = nbits - 8) {
		int bits_this_pass = nbits > 8 ? 8 : nbits;
		TAP_SHIFT(jreg, *data_in++, bits_this_pass);
		if (data_out != NULL) {
			*data_out = jtag_data(jreg, bits_this_pass);
			data_out++;
		}
	}

	return (JTAG_OK);
}

/*
 * Shift the required number of bits of the specified
 * value into the selected register. Note that this routine makes
 * sense only for value = 0 and value = -1.
 * Return <0 if error, >=0 if OK.
 */

static int
tap_shift_constant(volatile u_int *jreg, int value, int nbits)
{
	TAP_DECLARE;

	TAP_WAIT(jreg);

	/*
	 * The loop is done a half-word at a time
	 */
	for (; nbits > 0; nbits = nbits - 16) {
		int bits_this_pass = nbits > 16 ? 16 : nbits;
		TAP_SHIFT(jreg, value, bits_this_pass);
	}

	return (JTAG_OK);
}


/*
 *	Ring-level commands
 */

/*
 * Select the required ring. Reset it if required (reset != 0).
 * Return <0 if error, >=0 if OK.
 */

static int
select_ring(volatile u_int *jreg, jtag_ring ring, int reset)
{
	int status;
	jtag_ring jring;

	status = tap_wait(jreg);
	if (status < 0) {
		return (status);
	}

	/* Translate a Physical Board number to a JTAG board number */
	jring = ((u_int)(ring & 0x10) << 3) | ((u_int)(ring & 0xE0) >> 1) |
		(ring & 0xF);
	status = tap_issue_cmd(jreg, (jring << 16) | JTAG_SEL_RING);
	if (status < 0) {
		return (status);
	}

	if (reset != 0) {
		status = tap_issue_cmd(jreg, JTAG_TAP_RESET);
	}

	return (status);
}

/*
 * Shift the specified instruction into the component, then
 * shift the required data in & retrieve the data out.
 * Return <0 if error, >=0 if OK.
 */

static int
jtag_single_IR_DR(
	volatile u_int *jreg,
	jtag_phys_comp *component,
	jtag_instruction instr,
	u_char *in,
	int nbits,
	u_char *out)
{
	int status;

	TAP_ISSUE_CMD(jreg, JTAG_SEL_IR, status);
	TAP_SHIFT_CONSTANT(jreg, -1, component->ir_after, status);
	TAP_SHIFT_SINGLE(jreg, instr, component->chip->ir_len, status);
	TAP_SHIFT_CONSTANT(jreg, -1, component->ir_before, status);
	TAP_ISSUE_CMD(jreg, JTAG_IR_TO_DR, status);
	TAP_SHIFT_CONSTANT(jreg, 0, component->by_after, status);
	TAP_SHIFT_MULTIPLE(jreg, in, nbits, out, status);
	TAP_SHIFT_CONSTANT(jreg, 0, component->by_before, status);
	TAP_ISSUE_CMD(jreg, JTAG_RUNIDLE, status);

	return (status);
}

/*
 * jtag_rescan_IR_DR()
 *
 * This function is used in order to rescan the DC ASICs when taking
 * them out of the frozen state. This is necessary because of a problem
 * when taking DCs out of the frozen state. Sometimes the operation must
 * be retryed.
 *
 * TODO - Eliminate the *in input parameter if able to.
 */

/* ARGSUSED */
static int
jtag_rescan_IR_DR(
	volatile u_int *jreg,
	jtag_phys_comp *component,
	jtag_instruction instr,
	u_char *in,
	int nbits,
	u_char *out)
{
	int status, i;
	u_char tmp[32];

	for (i = 0; i < 32; i++)
		tmp[i] = 0;

	TAP_ISSUE_CMD(jreg, JTAG_SEL_IR, status);
	TAP_SHIFT_CONSTANT(jreg, -1, component->ir_after, status);
	TAP_SHIFT_SINGLE(jreg, instr, component->chip->ir_len, status);
	TAP_SHIFT_CONSTANT(jreg, -1, component->ir_before, status);
	TAP_ISSUE_CMD(jreg, JTAG_IR_TO_DR, status);

	/* scan the chip out */
	TAP_SHIFT_CONSTANT(jreg, 0, component->by_after, status);
	TAP_SHIFT_MULTIPLE(jreg, tmp, nbits, out, status);
	TAP_SHIFT_CONSTANT(jreg, 0, component->by_before, status);

	/* re scan the chip */
	TAP_SHIFT_CONSTANT(jreg, 0, component->by_after, status);
	TAP_SHIFT_MULTIPLE(jreg, out, nbits, tmp, status);
	TAP_SHIFT_CONSTANT(jreg, 0, component->by_before, status);

	TAP_ISSUE_CMD(jreg, JTAG_RUNIDLE, status);

	return (status);
}

/*
 * Return the number of components of the current ring, or <0 if failed
 */
static int
jtag_ring_length(volatile u_int *jreg, jtag_ring ring)
{
	int status, length;

	/*
	 * Reset the ring & check that there is a component
	 * This is based on the fact that TAP reset forces the IDCODE,
	 * or BYPASS (with 0 preloaded) if there is no ID
	 */

	status = select_ring(jreg, ring, 1);
	if (status < 0) {
		cmn_err(CE_WARN, "select ring error jtag status %x\n",
			status);
		return (status);
	}

	TAP_ISSUE_CMD(jreg, JTAG_SEL_DR, status);
	TAP_SHIFT_SINGLE(jreg, -1, 8, status);
	if (status == 0xFF) {
		return (RING_BROKEN); /* no CID detected */
	}

	/*
	 * Put all components in BYPASS. This assumes the chain has
	 * at most 32 components, and that each IR is at most 16-bits.
	 * Note that the algorithm depends on the bypass FF to be cleared
	 * on a tap reset!
	 */
	TAP_ISSUE_CMD(jreg, JTAG_TAP_RESET, status);
	TAP_ISSUE_CMD(jreg, JTAG_SEL_IR, status);
	TAP_SHIFT_CONSTANT(jreg, -1, 32*16, status);
	TAP_ISSUE_CMD(jreg, JTAG_IR_TO_DR, status);
	TAP_SHIFT_CONSTANT(jreg, 0, 32, status);

	for (length = 0; length <= 33; length++) { /* bit by bit */
		TAP_SHIFT_SINGLE(jreg, -1, 1, status);

		if (status != 0) {
			break;
		}
	}
	TAP_ISSUE_CMD(jreg, JTAG_RUNIDLE, status);
	/* more than 32 components ??? */
	return ((length <= 32) ? length : RING_BROKEN);
}

/*
 * Return the total number of instruction register bits in the
 * current ring,  or < 0 if failed.
 */
int
jtag_ring_ir_length(volatile u_int *jreg, jtag_ring ring)
{
	int status, length;

	/*
	 * Reset the ring & check that there is a component
	 * This is based on the fact that TAP reset forces the IDCODE,
	 * or BYPASS (with 0 preloaded) if there is no ID
	 */
	status = select_ring(jreg, ring, 1);
	if (status < 0) {
		cmn_err(CE_WARN, "select error status %x", status);
		return (status);
	}

	/*
	 * Reset, Select IR, Shift in all 1's assuming the chain has
	 * at most 32 components, and that each IR is at most 16-bits.
	 * Then shift in 0's and count until a 0 comes out.
	 * And cleanup by flushing with all 1's before reset or idle
	 * --- FATAL's if you don't as you go through update-ir state
	 */
	TAP_ISSUE_CMD(jreg, JTAG_TAP_RESET, status);
	TAP_ISSUE_CMD(jreg, JTAG_SEL_IR, status);

	/* 1 fill, look for 0 */
	TAP_SHIFT_CONSTANT(jreg, -1, 32 * 16, status);
	for (length = 0; length <= 32 * 16; length++) {	/* bit by bit */
		TAP_SHIFT_SINGLE(jreg, 0, 1, status);
		if (status == 0)
			break;
	}

	/* bypass should be safe */
	TAP_SHIFT_CONSTANT(jreg, -1, 32 * 16, status);
	TAP_ISSUE_CMD(jreg, JTAG_RUNIDLE, status);
	/* more than 32*16 ir bits ??? */
	return ((length <= 32 * 16) ? length : RING_BROKEN);
}

/*
 * Format the jtag shadow scan data from scan_out bit string and store
 * in the array on u_ints. The datap represents the registers from
 * the chip under scan.
 * XXX - How to represent 64 bit registers here?
 */
static void
format_chip_data(u_char *fmt, u_int *datap, u_char *scan_out)
{
	u_int value;

	for (value = 0; ; ) {
		u_char cmd = *fmt++;

		if ((cmd & JTSO_XTRACT) != 0) {
			u_int lsb, msb;
			lsb = *fmt++;
			msb = *fmt++;
			value |= jtag_bf_extract(scan_out, lsb, msb) <<
				(cmd & JTSO_SHIFT);
		}

		if ((cmd & JTSO_ST) != 0) {
			*datap++ = value;
			value = 0;
		}

		if ((cmd & JTSO_END) != 0) {
			break;
		}
	}
}
