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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FHC_H
#define	_SYS_FHC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types32.h>
#include <sys/dditypes.h>

/* useful debugging stuff */
#define	FHC_ATTACH_DEBUG	0x1
#define	FHC_INTERRUPT_DEBUG	0x2
#define	FHC_REGISTERS_DEBUG	0x4
#define	FHC_CTLOPS_DEBUG	0x8

#define	FHC_BOARDS 0
#define	FHC_CLOCKS 1

/*
 * OBP supplies us with 6 register sets for the FHC. The code for the fhc
 * driver relies on these register sets being presented by the PROM in the
 * order specified below. If this changes, the following comments must be
 * revised and the code in fhc_init() must be changed to reflect these
 * revisions.
 *
 * They are:
 * 	0	FHC internal registers
 * 	1	IGR Interrupt Group Number
 *	2	FanFail IMR, ISMR
 *	3	System IMR, ISMR
 *	4	UART IMR, ISMR
 *	5	TOD IMR, ISMR
 */

/*
 * The offsets are defined as offsets from the base of the OBP register
 * set which the register belongs to.
 */

/* Register set 0 */
#define	FHC_OFF_ID		0x0	/* FHC ID register */
#define	FHC_OFF_RCTRL		0x10	/* FHC Reset Control and Status */
#define	FHC_OFF_CTRL		0x20	/* FHC Control and Status */
#define	FHC_OFF_BSR		0x30	/* FHC Board Status Register */
#define	FHC_OFF_JTAG_CTRL	0xF0	/* JTAG Control Register */
#define	FHC_OFF_JTAG_CMD	0x100	/* JTAG Comamnd Register */

/* Register sets 2-5, the ISMR offset is the same */
#define	FHC_OFF_ISMR		0x10	/* FHC Interrupt State Machine */

/* Bit field defines for FHC Control and Status Register */
#define	FHC_CENTERDIS		0x00100000

/* NOTE: this bit is only used by firmware and must always be cleared by OS */
#define	FHC_CSR_SYNC		0x00010000
#define	FHC_MOD_OFF		0x00008000
#define	FHC_ACDC_OFF		0x00004000
#define	FHC_FHC_OFF		0x00002000
#define	FHC_EPDA_OFF		0x00001000
#define	FHC_EPDB_OFF		0x00000800
#define	FHC_PS_OFF		0x00000400
#define	FHC_NOT_BRD_PRES	0x00000200
#define	FHC_LED_LEFT		0x00000040
#define	FHC_LED_MID		0x00000020
#define	FHC_LED_RIGHT		0x00000010

/* Bit field defines for FHC Reset Control and Status Register */
#define	FHC_POR			0x80000000
#define	FHC_SOFT_POR		0x40000000
#define	FHC_SOFT_XIR		0x20000000

/* Bit field defines for the JTAG control register. */
#define	JTAG_MASTER_EN		0x80000000
#define	JTAG_MASTER_NPRES	0x40000000


/* Macros for decoding UPA speed pins from the Board Status Register */
#define	CPU_0_PINS(bsr)		(((bsr) >> 10) & 0x7)
#define	CPU_1_PINS(bsr)		(((bsr) >> 7) & 0x7)

#define	CID_REV_MASK		0x0fffffff
#define	ULTRAI_COMPID		0x0002502f
#define	ULTRAII_COMPID		0x0003602f

/* Macro for extracting the "plus" bit from the Board Status Register */
#define	ISPLUSBRD(bsr)		(((bsr) & 1) == 0)

/* Macros for physical access */
#define	FHC_OFFSET		0xf8000000ull
#define	FHC_REGOFF		0x800000ull
#define	FHC_OFF_IGN		0x2000ull
#define	FHC_OFF_SIM		0x6000ull
#define	FHC_OFF_SSM		0x6010ull
#define	FHC_OFF_UIM		0x8000ull
#define	FHC_OFF_USM		0x8010ull
#define	FHC_CTRL(board)		(FHC_BOARD_BASE(2*(board)) + FHC_OFFSET + \
				FHC_REGOFF + FHC_OFF_CTRL)
#define	FHC_JTAG_CTRL(board)	(FHC_BOARD_BASE(2*(board)) + FHC_OFFSET + \
				FHC_REGOFF + FHC_OFF_JTAG_CTRL)
#define	FHC_IGN(board)		(FHC_BOARD_BASE(2*(board)) + FHC_OFFSET + \
				FHC_REGOFF + FHC_OFF_IGN)
#define	FHC_SIM(board)		(FHC_BOARD_BASE(2*(board)) + FHC_OFFSET + \
				FHC_REGOFF + FHC_OFF_SIM)
#define	FHC_SSM(board)		(FHC_BOARD_BASE(2*(board)) + FHC_OFFSET + \
				FHC_REGOFF + FHC_OFF_SSM)
#define	FHC_UIM(board)		(FHC_BOARD_BASE(2*(board)) + FHC_OFFSET + \
				FHC_REGOFF + FHC_OFF_UIM)
#define	FHC_USM(board)		(FHC_BOARD_BASE(2*(board)) + FHC_OFFSET + \
				FHC_REGOFF + FHC_OFF_USM)

/*
 * the foolowing defines are used for trans phy-addr to board number
 */
#define	BOARD_PHYADDR_SHIFT	24
#define	CLOCKBOARD_PHYADDR_BITS	0x1fff8
#define	IO_BOARD_NUMBER_SHIFT	10
#define	IO_BOARD_NUMBER_MASK	0xf

/*
 * The following defines are used by the fhc driver to determine the
 * difference between IO and CPU type boards. This will be replaced
 * later by JTAG scan to determine board type.
 */

/* XXX */
#define	FHC_UPADATA64A		0x40000
#define	FHC_UPADATA64B		0x20000
/* XXX */

/* Bit field defines for Board Status Register */
#define	FHC_DIAG_MODE		0x40

/* Bit field defines for the FHC Board Status Register when on a disk board */
#define	FHC_FANFAIL		0x00000040
#define	FHC_SCSI_VDD_OK		0x00000001

/* Size of temperature recording array */
#define	MAX_TEMP_HISTORY	16

/* Maximum number of boards in system */
#define	MAX_BOARDS		16

/* Maximum number of Board Power Supplies. */
#define	MAX_PS_COUNT		8

/* Use predefined strings to name the kstats from this driver. */
#define	FHC_KSTAT_NAME		"fhc"
#define	CSR_KSTAT_NAMED		"csr"
#define	BSR_KSTAT_NAMED		"bsr"

/*
 * The following defines are for the AC chip, but are needed to be global,
 * so have been put in the fhc header file.
 */

/*
 * Most Sunfire ASICs have the chip rev encoded into bits 31-28 of the
 * component ID register.
 */
#define	CHIP_REV(c)	((c) >> 28)

#ifndef _ASM

/* Use predefined strings to name the kstats from this driver. */

/* Bit field defines for Interrupt Mapping registers */
#define	IMR_VALID	((uint_t)1 << INR_EN_SHIFT) /* Mondo valid bit */

/* Bit defines for Interrupt State Machine Register */
#define	INT_PENDING	3	/* state of the interrupt dispatch */

struct intr_regs {
	volatile uint_t *mapping_reg;
	volatile uint_t *clear_reg;
	uint_t mapping_reg_cache;	/* cache current value for CPR */
};

#define	BD_IVINTR_SHFT		0x7

/*
 * Convert the Board Number field in the FHC Board Status Register to
 * a board number. The field in the register is bits 0,3-1 of the board
 * number. Therefore a macro is necessary to extract the board number.
 */
#define	FHC_BSR_TO_BD(bsr)	((((bsr) >> 16) & 0x1)  | \
				(((bsr) >> 12) & 0xE))

#define	FHC_INO(ino) ((ino) & 0x7)
#define	FHC_CPU2BOARD(cpuid) ((cpuid) >> 1)
#define	FHC_CPU_IS_A(cpuid) (!((cpuid) & 1))
#define	FHC_CPU_IS_B(cpuid) ((cpuid) & 1)
#define	FHC_BOARD2CPU_A(board) ((board) << 1)
#define	FHC_BOARD2CPU_B(board) (((board) << 1) + 1)
#define	FHC_PS2BOARD(ps) ((((ps) & 0x6) << 1) | ((ps) & 0x1))
#define	FHC_BOARD2PS(board) ((((board) & 0xc) >> 1) | ((board) & 0x1))
#define	FHC_OTHER_CPU_ID(cpuid) ((cpuid) ^ 1)

/* this base address is assumed to never map to real memory */
#define	FHC_BASE_NOMEM		(1ull << 40)
#define	FHC_MAX_ECACHE_SIZE	(16 * 1024 * 1024)

#define	FHC_BOARD_0		0x1c000000000ull
#define	FHC_BOARD_SPAN		0x200000000ull
#define	FHC_DTAG_OFFSET		0xfa000000ull
#define	FHC_BOARD_BASE(cpuid)	(FHC_BOARD_0 + (cpuid) * FHC_BOARD_SPAN)
#define	FHC_DTAG_BASE(cpuid)	(FHC_BOARD_BASE(cpuid) + FHC_DTAG_OFFSET)
#define	FHC_DTAG_LOW		0x300000000ull
#define	FHC_DTAG_HIGH		0x3ull
#define	FHC_DTAG_SIZE		(16 * 1024 * 1024)
#define	FHC_DTAG_SKIP		64

/*
 * Each Sunfire CPU Board has 32Kbytes of SRAM on the FireHose Bus.
 *
 * The SRAM is allocated as follows:
 *
 * 0x1ff.f020.0000 - 0x1ff.f020.5fff  scratch/stacks
 * 0x1ff.f020.6000 - 0x1ff.f020.67ff  reset info     (2K bytes)
 * 0x1ff.f020.6800 - 0x1ff.f020.6fff  POST private   (2K bytes)
 * 0x1ff.f020.7000 - 0x1ff.f020.77ff  OS private     (2K bytes)
 * 0x1ff.f020.7800 - 0x1ff.f020.7fff  OBP private    (2K bytes)
 */
#define	FHC_LOCAL_SRAM_BASE	0x1fff0200000ull
#define	FHC_GLOBAL_SRAM_BASE	0x1c0f8200000ull
#define	FHC_CPU2GLOBAL_SRAM(mid) \
			(FHC_GLOBAL_SRAM_BASE + (mid) * 0x200000000ull)

#define	FHC_SRAM_OS_BASE	0x7000
#define	FHC_LOCAL_OS_PAGEBASE	((FHC_LOCAL_SRAM_BASE + FHC_SRAM_OS_BASE) & \
				MMU_PAGEMASK)
#define	FHC_SRAM_OS_OFFSET	((FHC_LOCAL_SRAM_BASE + FHC_SRAM_OS_BASE) & \
				MMU_PAGEOFFSET)

#define	FHC_SHUTDOWN_WAIT_MSEC	1000

#define	FHC_MAX_INO	4

#define	FHC_SYS_INO		0x0
#define	FHC_UART_INO		0x1
#define	FHC_TOD_INO		0x2
#define	FHC_FANFAIL_INO		0x3

/*
 * Defines for the kstats created for passing temperature values and
 * history out to user level programs. All temperatures passed out
 * will be in degrees Centigrade, corrected for the board type the
 * temperature was read from. Since each Board type has a different
 * response curve for the A/D convertor, the temperatures are all
 * calibrated inside the kernel.
 */

#define	OVERTEMP_KSTAT_NAME	"temperature"

/*
 * This kstat is used for manually overriding temperatures.
 */

#define	TEMP_OVERRIDE_KSTAT_NAME	"temperature override"

/*
 * Time averaging based method of recording temperature history.
 * Higher level temperature arrays are composed of temperature averages
 * of the array one level below. When the lower array completes a
 * set of data, the data is averaged and placed into the higher
 * level array. Then the lower level array is overwritten until
 * it is once again complete, where the process repeats.
 *
 * This method gives a user a fine grained view of the last minute,
 * and larger grained views of the temperature as one goes back in
 * time.
 *
 * The time units for the longer samples are based on the value
 * of the OVERTEMP_TIMEOUT_SEC and the number of elements in each
 * of the arrays between level 1 and the higher level.
 */

#define	OVERTEMP_TIMEOUT_SEC	2

/* definition of the clock board index */
#define	CLOCK_BOARD_INDEX	16

#define	L1_SZ		30	/* # of OVERTEMP_TIMEOUT_SEC samples */
#define	L2_SZ		15	/* size of array for level 2 samples */
#define	L3_SZ		12	/* size of array for level 3 samples */
#define	L4_SZ		4	/* size of array for level 4 samples */
#define	L5_SZ		2	/* size of array for level 5 samples */

/*
 * Macros for determining when to do the temperature averaging of arrays.
 */
#define	L2_INDEX(i)	((i) / L1_SZ)
#define	L2_REM(i)	((i) % L1_SZ)
#define	L3_INDEX(i)	((i) / (L1_SZ * L2_SZ))
#define	L3_REM(i)	((i) % (L1_SZ * L2_SZ))
#define	L4_INDEX(i)	((i) / (L1_SZ * L2_SZ * L3_SZ))
#define	L4_REM(i)	((i) % (L1_SZ * L2_SZ * L3_SZ))
#define	L5_INDEX(i)	((i) / (L1_SZ * L2_SZ * L3_SZ * L4_SZ))
#define	L5_REM(i)	((i) % (L1_SZ * L2_SZ * L3_SZ * L4_SZ))

/*
 * define for an illegal temperature. This temperature will never be seen
 * in a real system, so it is used as an illegal value in the various
 * functions processing the temperature data structure.
 */
#define	NA_TEMP		0x7FFF

/*
 * State variable for board temperature. Each board has its own
 * temperature state. State transitions from OK -> bad direction
 * happen instantaneously, but use a counter in the opposite
 * direction, so that noise in the A/D counters does not cause
 * a large number of messages to appear.
 */
enum temp_state {	TEMP_OK = 0,		/* normal board temperature */
			TEMP_WARN = 1,		/* start warning operator */
			TEMP_DANGER = 2 };	/* get ready to shutdown */

/*
 * Number of temperature poll counts to wait before printing that the
 * system has cooled down.
 */
#define	TEMP_STATE_TIMEOUT_SEC	20
#define	TEMP_STATE_COUNT	((TEMP_STATE_TIMEOUT_SEC) / \
				(OVERTEMP_TIMEOUT_SEC))

/*
 * Number of poll counts that a system temperature must be at or above danger
 * temperature before system is halted and powers down.
 */
#define	SHUTDOWN_TIMEOUT_SEC	20
#define	SHUTDOWN_COUNT		((SHUTDOWN_TIMEOUT_SEC) / \
				(OVERTEMP_TIMEOUT_SEC))

/*
 * State variable for temperature trend.  Each state represents the
 * current temperature trend for a given device.
 */
enum temp_trend {	TREND_UNKNOWN = 0,	/* Unknown temperature trend */
			TREND_RAPID_FALL = 1,	/* Rapidly falling temp. */
			TREND_FALL = 2,		/* Falling temperature */
			TREND_STABLE = 3,	/* Stable temperature */
			TREND_RISE = 4,		/* Rising temperature */
			TREND_RAPID_RISE = 5,   /* Rapidly rising temperature */
			TREND_NOISY = 6 };	/* Unknown trend (noisy) */

/* Thresholds for temperature trend */
#define	NOISE_THRESH		2
#define	RAPID_RISE_THRESH	4
#define	RAPID_FALL_THRESH	4

/*
 * Main structure for passing the calibrated and time averaged temperature
 * values to user processes. This structure is copied out via the kstat
 * mechanism.
 */
#define	TEMP_KSTAT_VERSION 3	/* version of temp_stats structure */
struct temp_stats {
	uint_t index;		/* index of current temperature */
	short l1[L1_SZ];	/* OVERTEMP_TIMEOUT_SEC samples */
	short l2[L2_SZ];	/* level 2 samples */
	short l3[L3_SZ];	/* level 3 samples */
	short l4[L4_SZ];	/* level 4 samples */
	short l5[L5_SZ];	/* level 5 samples */
	short max;		/* maximum temperature recorded */
	short min;		/* minimum temperature recorded */
	enum temp_state state;	/* state of board temperature */
	int temp_cnt;		/* counter for state changes */
	int shutdown_cnt;	/* counter for overtemp shutdown */
	int version;		/* version of this structure */
	enum temp_trend trend;	/* temperature trend for board */
	short override;		/* override temperature for testing */
};

/* The variable fhc_cpu_warning_temp_threshold is initialized to this value. */
#define	FHC_CPU_WARNING_TEMP_THRESHOLD		45

/*
 * Fault list management.
 *
 * The following defines and enum definitions have been created to support
 * the fault list (struct ft_list). These defines must match with the
 * fault string table in fhc.c. If any faults are added, they must be
 * added at the end of this list, and the table must be modified
 * accordingly.
 */
enum ft_type {
	FT_CORE_PS = 0,		/* Core power supply */
	FT_OVERTEMP,		/* Temperature */
	FT_AC_PWR,		/* AC power Supply */
	FT_PPS,			/* Peripheral Power Supply */
	FT_CLK_33,		/* System 3.3 Volt Power */
	FT_CLK_50,		/* System 5.0 Volt Power */
	FT_V5_P,		/* Peripheral 5V Power */
	FT_V12_P,		/* Peripheral 12V Power */
	FT_V5_AUX,		/* Auxiliary 5V Power */
	FT_V5_P_PCH,		/* Peripheral 5V Precharge */
	FT_V12_P_PCH,		/* Peripheral 12V Precharge */
	FT_V3_PCH,		/* System 3V Precharge */
	FT_V5_PCH,		/* System 5V Precharge */
	FT_PPS_FAN,		/* Peripheral Power Supply Fan */
	FT_RACK_EXH,		/* Rack Exhaust Fan */
	FT_DSK_FAN,		/* 4 (or 5) Slot Disk Fan */
	FT_AC_FAN,		/* AC Box Fan */
	FT_KEYSW_FAN,		/* Key Switch Fan */
	FT_INSUFFICIENT_POWER,	/* System has insufficient power */
	FT_PROM,		/* fault inherited from PROM */
	FT_HOT_PLUG,		/* hot plug unavailable */
	FT_TODFAULT		/* tod error detection */
};

enum ft_class {
	FT_BOARD,
	FT_SYSTEM
};

/*
 * This extern allows other drivers to use the ft_str_table if they
 * have fhc specified as a depends_on driver.
 */
extern char *ft_str_table[];

/* Maximum length of string table entries */
#define	MAX_FT_DESC	64

#define	FT_LIST_KSTAT_NAME	"fault_list"

/*
 * The fault list structure is a structure for holding information on
 * kernel detected faults. The fault list structures are linked into
 * a list and the list is protected by the ftlist_mutex. There are
 * also several routines for manipulating the fault list.
 */
struct ft_list {
	int32_t unit;		/* unit number of faulting device */
	enum ft_type type;	/* type of faulting device */
	int32_t pad;		/* padding to replace old next pointer */
	enum ft_class fclass;	/* System or board class fault */
	time32_t create_time;	/* Time stamp at fault detection */
	char msg[MAX_FT_DESC];	/* fault string */
};

/*
 * Allow binary compatibility between ILP32 and LP64 by
 * eliminating the next pointer and making ft_list a fixed size.
 * The structure name "ft_list" remains unchanged for
 * source compatibility of kstat applications.
 */
struct ft_link_list {
	struct ft_list f;
	struct ft_link_list *next;
};

/*
 * Board list management.
 *
 * Enumerated types for defining type of system and clock
 * boards. It is used by both the kernel and user programs.
 */
enum board_type {
	UNINIT_BOARD = 0,		/* Uninitialized board type */
	UNKNOWN_BOARD,			/* Unknown board type */
	CPU_BOARD,			/* System board CPU(s) */
	MEM_BOARD,			/* System board no CPUs */
	IO_2SBUS_BOARD,			/* 2 SBus & SOC IO Board */
	IO_SBUS_FFB_BOARD,		/* SBus & FFB SOC IO Board */
	IO_PCI_BOARD,			/* PCI IO Board */
	DISK_BOARD,			/* Disk Drive Board */
	CLOCK_BOARD,			/* System Clock board */
	IO_2SBUS_SOCPLUS_BOARD,		/* 2 SBus & SOC+ IO board */
	IO_SBUS_FFB_SOCPLUS_BOARD	/* SBus&FFB&SOC+ board */
};

/*
 * Defined strings for comparing with OBP board-type property. If OBP ever
 * changes the board-type properties, these string defines must be changed
 * as well.
 */
#define	CPU_BD_NAME			"cpu"
#define	MEM_BD_NAME			"mem"
#define	IO_2SBUS_BD_NAME		"dual-sbus"
#define	IO_SBUS_FFB_BD_NAME		"upa-sbus"
#define	IO_PCI_BD_NAME			"dual-pci"
#define	DISK_BD_NAME			"disk"
#define	IO_2SBUS_SOCPLUS_BD_NAME	"dual-sbus-soc+"
#define	IO_SBUS_FFB_SOCPLUS_BD_NAME	"upa-sbus-soc+"

/*
 * The following structures and union are needed because the bd_info
 * structure describes all types of system boards.
 * XXX - We cannot determine Spitfire rev from JTAG scan, so it is
 * left blank for now. Future implementations might fill in this info.
 */
struct cpu_info {
	int cpu_rev;		/* CPU revision */
	int cpu_speed;		/* rated speed of CPU in MHz */
	int cpu_compid;		/* CPU component ID */
	int sdb0_compid;	/* SDB component ID */
	int sdb1_compid;	/* SDB component ID */
	int ec_compid;		/* Ecache RAM ID, needed for cache size */
	int cache_size;		/* Cache size in bytes */
	int cpu_sram_mode;	/* module's sram mode */
	int cpu_detected;	/* Something on the CPU JTAG ring. */
};

struct io1_info {
	int sio0_compid;	/* Sysio component ID */
	int sio1_compid;	/* Sysio component ID */
	int hme_compid;		/* several revs in existence */
	int soc_compid;		/* SOC */
};

struct io1plus_info {
	int sio0_compid;	/* Sysio component ID */
	int sio1_compid;	/* Sysio component ID */
	int hme_compid;		/* several revs in existence */
	int socplus_compid;	/* SOC+ */
};

/* Defines for the FFB size field */
#define	FFB_FAILED	-1
#define	FFB_NOT_FOUND	0
#define	FFB_SINGLE	1
#define	FFB_DOUBLE	2

struct io2_info {
	int fbc_compid;		/* FBC component ID */
	int ffb_size;		/* not present, single or dbl buffered */
	int sio1_compid;	/* Sysio component ID */
	int hme_compid;		/* several revs in existence */
	int soc_compid;		/* SOC component ID */
};

struct io2plus_info {
	int fbc_compid;		/* FBC component ID */
	int ffb_size;		/* not present, single or dbl buffered */
	int sio1_compid;	/* Sysio component ID */
	int hme_compid;		/* several revs in existence */
	int socplus_compid;	/* or SOC+ component ID */
};

struct io3_info {
	int psyo0_compid;	/* Psycho+ component ID */
	int psyo1_compid;	/* Psycho+ component ID */
	int cheo_compid;	/* Cheerio component ID */
};

struct dsk_info {
	int disk_pres[2];
	int disk_id[2];
};

union bd_un {
	struct cpu_info cpu[2];
	struct io1_info io1;
	struct io2_info io2;
	struct io3_info io3;
	struct dsk_info dsk;
	struct io1plus_info io1plus;
	struct io2plus_info io2plus;
};

/*
 * board_state and bd_info are maintained for backward
 * compatibility with prtdiag and others user programs that may rely
 * on them.
 */
enum board_state {
	UNKNOWN_STATE = 0,	/* Unknown board */
	ACTIVE_STATE,		/* active and working */
	HOTPLUG_STATE,		/* Hot plugged board */
	LOWPOWER_STATE, 	/* Powered down board */
	DISABLED_STATE,		/* Board disabled by PROM */
	FAILED_STATE		/* Board failed by POST */
};

struct bd_info {
	enum board_type type;		/* Type of board */
	enum board_state state;		/* current state of this board */
	int board;			/* board number */
	int fhc_compid;			/* fhc component id */
	int ac_compid;			/* ac component id */
	char prom_rev[64];		/* best guess as to what is needed */
	union bd_un bd;
};

/*
 * Config admin interface.
 *
 * Receptacle states.
 */
typedef enum {
	SYSC_CFGA_RSTATE_EMPTY = 0,		/* Empty state */
	SYSC_CFGA_RSTATE_DISCONNECTED,		/* DISCONNECTED state */
	SYSC_CFGA_RSTATE_CONNECTED		/* CONNECTED state */
} sysc_cfga_rstate_t;

/*
 * Occupant states.
 */
typedef enum {
	SYSC_CFGA_OSTATE_UNCONFIGURED = 0,	/* UNCONFIGURED state */
	SYSC_CFGA_OSTATE_CONFIGURED		/* CONFIGURED state */
} sysc_cfga_ostate_t;

/*
 * Receptacle/Occupant condition.
 */
typedef enum {
	SYSC_CFGA_COND_UNKNOWN = 0,	/* Unknown condition */
	SYSC_CFGA_COND_OK,		/* Condition OK */
	SYSC_CFGA_COND_FAILING,		/* Failing */
	SYSC_CFGA_COND_FAILED,		/* Failed */
	SYSC_CFGA_COND_UNUSABLE		/* Unusable */
} sysc_cfga_cond_t;

/*
 * Error definitions for CFGADM platform library
 */
typedef enum {
	SYSC_ERR_DEFAULT = 0,	/* generic errors */
	SYSC_ERR_INTRANS,	/* hardware in transition */
	SYSC_ERR_UTHREAD,	/* can't stop user thread */
	SYSC_ERR_KTHREAD,	/* can't stop kernel thread */
	SYSC_ERR_SUSPEND,	/* can't suspend a device */
	SYSC_ERR_RESUME,	/* can't resume a device */
	SYSC_ERR_POWER,		/* not enough power for slot */
	SYSC_ERR_COOLING,	/* not enough cooling for slot */
	SYSC_ERR_PRECHARGE,	/* not enough precharge for slot */
	SYSC_ERR_HOTPLUG,	/* Hot Plug Unavailable */
	SYSC_ERR_HW_COMPAT,	/* incompatible hardware found during dr */
	SYSC_ERR_NON_DR_PROM,	/* prom not support Dynamic Reconfiguration */
	SYSC_ERR_CORE_RESOURCE,	/* core resource cannot be removed */
	SYSC_ERR_PROM,		/* error encountered in OBP/POST */
	SYSC_ERR_DR_INIT,	/* error encountered in sysc_dr_init op */
	SYSC_ERR_NDI_ATTACH,	/* error encountered in NDI attach operations */
	SYSC_ERR_NDI_DETACH,	/* error encountered in NDI detach operations */
	SYSC_ERR_RSTATE,	/* wrong receptacle state */
	SYSC_ERR_OSTATE,	/* wrong occupant state */
	SYSC_ERR_COND		/* invalid condition */
} sysc_err_t;

/*
 * Config admin structure.
 */
typedef struct sysc_cfga_stat {
	/* generic representation of the attachment point below */
	sysc_cfga_rstate_t rstate;	/* current receptacle state */
	sysc_cfga_ostate_t ostate;	/* current occupant state */
	sysc_cfga_cond_t condition;	/* current board condition */
	time32_t last_change;		/* last state/condition change */
	uint_t in_transition:1;		/* board is in_transition */

	/* platform specific below */
	enum board_type type;		/* Type of board */
	int board;			/* board number */
	int fhc_compid;			/* fhc component id */
	int ac_compid;			/* ac component id */
	char prom_rev[64];		/* best guess as to what is needed */
	union bd_un bd;
	uint_t no_detach:1;		/* board is non_detachable */
	uint_t plus_board:1;		/* board is 98 MHz capable */
} sysc_cfga_stat_t;

/*
 * Config admin command structure for SYSC_CFGA ioctls.
 */
typedef struct sysc_cfga_cmd {
	uint_t		force:1;	/* force this state transition */
	uint_t		test:1;		/* Need to test hardware */
	int		arg;		/* generic data for test */
	sysc_err_t	errtype;	/* error code returned */
	char		*outputstr;	/* output returned from ioctl */
} sysc_cfga_cmd_t;

typedef struct sysc_cfga_cmd32 {
	uint_t		force:1;	/* force this state transition */
	uint_t		test:1;		/* Need to test hardware */
	int		arg;		/* generic data for test */
	sysc_err_t	errtype;	/* error code returned */
	caddr32_t	outputstr;	/* output returned from ioctl */
} sysc_cfga_cmd32_t;

typedef struct sysc_cfga_pkt {
	sysc_cfga_cmd_t	cmd_cfga;
	char		*errbuf;	/* internal error buffer */
} sysc_cfga_pkt_t;

/*
 * Sysctrl DR sequencer interface.
 */
typedef struct sysc_dr_handle {
	dev_info_t **dip_list;		/* list of top dips for board */
	int dip_list_len;		/* length devinfo list */
	int flags;			/* dr specific flags */
	int error;			/* dr operation error */
	char *errstr;			/* dr config/unfig error message */
} sysc_dr_handle_t;

#define	SYSC_DR_MAX_NODE	32
#define	SYSC_DR_FHC		0x1	/* connect phase init (fhc) */
#define	SYSC_DR_DEVS		0x2	/* config phase init (devices) */
#define	SYSC_DR_FORCE		0x4	/* force detach */
#define	SYSC_DR_REMOVE		0x8	/* remove dev_info */

#define	SYSC_DR_HANDLE_FHC	0x0
#define	SYSC_DR_HANDLE_DEVS	0x1

/*
 * Sysctrl event interface.
 */
typedef enum sysc_evt {
	SYSC_EVT_BD_EMPTY = 0,
	SYSC_EVT_BD_PRESENT,
	SYSC_EVT_BD_DISABLED,
	SYSC_EVT_BD_FAILED,
	SYSC_EVT_BD_OVERTEMP,
	SYSC_EVT_BD_TEMP_OK,
	SYSC_EVT_BD_PS_CHANGE,
	SYSC_EVT_BD_INS_FAILED,
	SYSC_EVT_BD_INSERTED,
	SYSC_EVT_BD_REMOVED,
	SYSC_EVT_BD_HP_DISABLED,
	SYSC_EVT_BD_CORE_RESOURCE_DISCONNECT
} sysc_evt_t;

/*
 * sysctrl audit message events
 */
typedef enum sysc_audit_evt {
	SYSC_AUDIT_RSTATE_EMPTY = 0,
	SYSC_AUDIT_RSTATE_CONNECT,
	SYSC_AUDIT_RSTATE_DISCONNECT,
	SYSC_AUDIT_RSTATE_SUCCEEDED,
	SYSC_AUDIT_RSTATE_EMPTY_FAILED,
	SYSC_AUDIT_RSTATE_CONNECT_FAILED,
	SYSC_AUDIT_RSTATE_DISCONNECT_FAILED,
	SYSC_AUDIT_OSTATE_CONFIGURE,
	SYSC_AUDIT_OSTATE_UNCONFIGURE,
	SYSC_AUDIT_OSTATE_SUCCEEDED,
	SYSC_AUDIT_OSTATE_CONFIGURE_FAILED,
	SYSC_AUDIT_OSTATE_UNCONFIGURE_FAILED
} sysc_audit_evt_t;

typedef struct {
	void (*update)(void *, sysc_cfga_stat_t *, sysc_evt_t);
	void *soft;
} sysc_evt_handle_t;

void fhc_bd_sc_register(void f(void *, sysc_cfga_stat_t *, sysc_evt_t), void *);

/*
 * The board list structure is the central storage for the kernel's
 * knowledge of normally booted and hotplugged boards.
 */
typedef struct bd_list {
	struct fhc_soft_state *softsp;	/* handle for DDI soft state */
	sysc_cfga_stat_t sc;		/* board info */
	sysc_dr_handle_t sh[2];		/* sysctrl dr interface */
	void *dev_softsp;		/* opaque pointer to device state */
	void *ac_softsp;		/* opaque pointer to our AC */
	struct kstat *ksp;		/* pointer used in kstat destroy */
	int fault;			/* failure on this board? */
	int flags;			/* board state flags */
} fhc_bd_t;

/*
 * Fhc_bd.c holds 2 resizable arrays of boards. First for clock
 * boards under central and second for normally booted and
 * hotplugged boards.
 */
typedef struct resizable_bd_list {
	fhc_bd_t **boards;
	int size;
	int last;
	int sorted;
} fhc_bd_resizable_t;

#define	BDF_VALID		0x1			/* board entry valid */
#define	BDF_DETACH		0x2			/* board detachable */
#define	BDF_DISABLED		0x4			/* board disabled */

#define	SYSC_OUTPUT_LEN		MAXPATHLEN		/* output str len */

/*
 * Board list management interface.
 */
int			fhc_max_boards(void);
void		fhc_bdlist_init(void);
void		fhc_bdlist_fini(void);
void		fhc_bdlist_prime(int, int, int);
fhc_bd_t	*fhc_bdlist_lock(int);
void		fhc_bdlist_unlock(void);

void		fhc_bd_init(struct fhc_soft_state *, int, enum board_type);
fhc_bd_t 	*fhc_bd(int);
fhc_bd_t	*fhc_bd_clock(void);
fhc_bd_t 	*fhc_bd_first(void);
fhc_bd_t 	*fhc_bd_next(fhc_bd_t *);
enum board_type	fhc_bd_type(int);
char 		*fhc_bd_typestr(enum board_type);
int		fhc_bd_valid(int);
int		fhc_bd_detachable(int);

int		fhc_bd_insert_scan(void);
int		fhc_bd_remove_scan(void);
int		fhc_bd_test(int, sysc_cfga_pkt_t *);
int		fhc_bd_test_set_cond(int, sysc_cfga_pkt_t *);
void		fhc_bd_update(int, sysc_evt_t);
void		fhc_bd_env_set(int, void *);

int		fhc_bdlist_locked(void);
int		fhc_bd_busy(int);
int		fhc_bd_is_jtag_master(int);
int		fhc_bd_is_plus(int);

#if defined(_KERNEL)

/*
 * In order to indicate that we are in an environmental chamber, or
 * oven, the test people will set the 'mfg-mode' property in the
 * options node to 'chamber'. Therefore we have the following define.
 */
#define	CHAMBER_VALUE	"chamber"

/*
 * zs design for fhc has two zs' interrupting on same interrupt mondo
 * This requires us to poll for zs and zs alone. The poll list has been
 * defined as a fixed size for simplicity.
 */
#define	MAX_ZS_CNT	2

/* FHC Interrupt routine wrapper structure */
struct fhc_wrapper_arg {
	struct fhc_soft_state *softsp;
	volatile uint_t *clear_reg;
	volatile uint_t *mapping_reg;
	dev_info_t *child;
	uint32_t inum;
	uint_t (*funcp)(caddr_t, caddr_t);
	caddr_t arg1;
	caddr_t arg2;
};

/*
 * The JTAG master command structure. It contains the address of the
 * the JTAG controller on this system board. The controller can only
 * be used if this FHC holds the JTAG master signal. This is checked
 * by reading the JTAG control register on this FHC.
 */
struct jt_mstr {
	volatile uint_t *jtag_cmd;
	int is_master;
	kmutex_t lock;
};

/* Functions exported to manage the fault list */
void reg_fault(int, enum ft_type, enum ft_class);
void clear_fault(int, enum ft_type, enum ft_class);
int process_fault_list(void);
void create_ft_kstats(int);

/* memloc's are protected under the bdlist lock */
struct fhc_memloc {
	struct fhc_memloc *next;
	int		board;		/* reference our board element */
	uint_t		pa;		/* base PA of this segment (in MB) */
	uint_t		size;		/* size of this segment (in MB) */
};

/* Functions used to manage memory 'segments' */
#define	FHC_MEMLOC_SHIFT	20
#define	FHC_MEMLOC_MAX		(0x10000000000ull >> FHC_MEMLOC_SHIFT)
void fhc_add_memloc(int board, uint64_t pa, uint_t size);
void fhc_del_memloc(int board);
uint64_t fhc_find_memloc_gap(uint_t size);
void fhc_program_memory(int board, uint64_t base);

/* Structures used in the driver to manage the hardware */
struct fhc_soft_state {
	dev_info_t *dip;		/* dev info of myself */
	struct bd_list *list;		/* pointer to board list entry */
	int is_central;			/* A central space instance of FHC */
	volatile uint_t *id;		/* FHC ID register */
	volatile uint_t *rctrl;		/* FHC Reset Control and Status */
	volatile uint_t *bsr;		/* FHC Board Status register */
	volatile uint_t *jtag_ctrl;	/* JTAG Control register */
	volatile uint_t *igr;		/* Interrupt Group Number */
	struct intr_regs intr_regs[FHC_MAX_INO];
	struct fhc_wrapper_arg poll_list[MAX_ZS_CNT];
	struct fhc_wrapper_arg *intr_list[FHC_MAX_INO];
	kmutex_t poll_list_lock;
	uchar_t spurious_zs_cntr;	/* Spurious counter for zs devices */
	kmutex_t pokefault_mutex;
	int pokefault;

	/* this lock protects the following data */
	/* ! non interrupt use only ! */
	kmutex_t ctrl_lock;		/* lock for access to FHC CSR */
	volatile uint_t *ctrl;		/* FHC Control and Status */

	/* The JTAG master structure has internal locking */
	struct jt_mstr jt_master;

	/* the pointer to the kstat is stored for deletion upon detach */
	kstat_t *fhc_ksp;
};

/*
 * Function shared with child drivers which require fhc
 * support. They gain access to this function through the use of the
 * _depends_on variable.
 */
enum board_type get_board_type(int board);
void update_temp(dev_info_t *pdip, struct temp_stats *envstat, uchar_t value);
enum temp_trend temp_trend(struct temp_stats *);
void fhc_reboot(void);
int overtemp_kstat_update(kstat_t *ksp, int rw);
int temp_override_kstat_update(kstat_t *ksp, int rw);
void init_temp_arrays(struct temp_stats *envstat);
void update_board_leds(fhc_bd_t *, uint_t, uint_t);
struct jt_mstr *jtag_master_lock(void);
void jtag_master_unlock(struct jt_mstr *);
extern int fhc_board_poweroffcpus(int board, char *errbuf, int cpu_flags);


/* FHC interrupt specification */
struct fhcintrspec {
	uint_t mondo;
	uint_t pil;
	dev_info_t *child;
	struct fhc_wrapper_arg *handler_arg;
};

/* kstat structure used by fhc to pass data to user programs. */
struct fhc_kstat {
	struct kstat_named csr;	/* FHC Control and Status Register */
	struct kstat_named bsr;	/* FHC Board Status Register */
};

#endif	/* _KERNEL */

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FHC_H */
