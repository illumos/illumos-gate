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

#ifndef	_SYS_SYSCTRL_H
#define	_SYS_SYSCTRL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	TRUE
#define	TRUE (1)
#endif
#ifndef	FALSE
#define	FALSE (0)
#endif

/*
 * Debugging macros
 *
 * The DPRINTF macro can be used by setting the sysc_debug_print_level to the
 * appropriate debugging level.  The debug levels are defined in each source
 * file where this header file is included.  The scoping of sysc_debug_info,
 * and sysc_debug_print_level is to the file which included the header file.
 * If multiple levels need to be output, the values can be 'ored'
 * together into sysc_debug_print_level.  If sysc_debug_print_line's bit 1 is
 * set, the line number of the debugging statement is printed out. If it has
 * bit 2 set, the macro will drop into either the debugger or the OBP PROM.
 */

#ifdef  DEBUG

#define	SYSCTRL_ATTACH_DEBUG	0x1
#define	SYSCTRL_INTERRUPT_DEBUG	0x2
#define	SYSCTRL_REGISTERS_DEBUG	0x4
#define	SYSC_DEBUG		SYSCTRL_ATTACH_DEBUG

#include <sys/promif.h>
extern void debug_enter(char *);

extern int sysc_debug_info;
extern int sysc_debug_print_level;

#define	PRINT_LINE_NUMBER	0x1
#define	ENTER_MON		0x2

#define	_PRINTF prom_printf	/* For logging to the console */

#define	DPRINTF(print_flag, args)			\
	if (sysc_debug_print_level & (print_flag) && sysc_debug_info & \
	    PRINT_LINE_NUMBER) \
		_PRINTF("%s line %d:\n", __FILE__, __LINE__);	\
	if (sysc_debug_print_level & (print_flag)) {	\
		_PRINTF args;				\
	if (sysc_debug_info & ENTER_MON)			\
		debug_enter("");				\
	}

#else
#define	DPRINTF(print_flag, args)
#endif /* DEBUG */

/*
 * OBP supplies us with 3 register sets for the clock-board node. The code for
 * the syctrl driver relies on these register sets being presented by the
 * PROM in the order specified below. If this changes, the following comments
 * must be revised and the code in sysctrl_attach() must be changed to reflect
 * these revisions.
 *
 * They are:
 * 	0	Clock frequency registers
 *	1	Misc registers
 *	2       Clock version register
 */

/*
 * The offsets are defined as offsets in bytes from the base of the OBP
 * register to which the register belongs to.
 */

/* Register set 0 */
#define	SYS_OFF_CLK_FREQ2	0x2	/* offset of clock register 2 */

/* Important bits for Clock Frequency register 2 */
#define	RCONS_UART_EN	0x80	/* Remote console reset enabled */
#define	GEN_RESET_EN	0x40	/* Enable reset on freq change */
#define	TOD_RESET_EN	0x20	/* Enable reset from TOD watchdog */
#define	CLOCK_FREQ_8	0x01	/* Frequency bit 8 */
#define	CLOCK_DIV_0	0x02	/* Cpu module divisor bit 0 */
#define	CLOCK_RANGE	0x0c	/* Bits 3:2 control the clock range */
#define	CLOCK_DIV_1	0x10	/* Cpu module divisor bit 1 */

/* Register set 1 */
#define	SYS_OFF_CTRL	0x0	/* Offset of System Control register */
#define	SYS_OFF_STAT1	0x10	/* Offset of System Status1 register */
#define	SYS_OFF_STAT2	0x20	/* Offset of System Status2 register */
#define	SYS_OFF_PSSTAT	0x30	/* Offset of Power Supply Status */
#define	SYS_OFF_PSPRES	0x40	/* Offset of Power Supply Presence */
#define	SYS_OFF_TEMP	0x50	/* Offset of temperature register */
#define	SYS_OFF_DIAG	0x60	/* Offset of interrupt diag register */
#define	SYS_OFF_PPPSR	0x70	/* Offset of second Power Supply Status */
#define	SYS_STATUS1_PADDR	0x1fff8906010 /* physical address for physio */

/* Register set 2 (not present on old vintage clock boards) */
#define	CLK_VERSION_REG	0x0	/* Offset of clock version register */
#define	CLK_VERSION_REG_PADDR 0x1fff890c000 /* physical address for physio */

/* Important bits for the board version register */
#define	OLD_CLK_GEN	0x1
#define	OLD_CLK_DIV	0x2

#define	RMT_CONS_OFFSET	0x4004	/* Offset of Remote Console UART */
#define	RMT_CONS_LEN	0x8	/* Size of Remote Console UART */

/* Bit field defines for System Control register */
#define	SYS_PPS_FAN_FAIL_EN	0x80	/* PPS Fan Fail Interrupt Enable */
#define	SYS_PS_FAIL_EN		0x40	/* PS DC Fail Interrupt Enable */
#define	SYS_AC_PWR_FAIL_EN	0x20	/* AC Power Fail Interrupt Enable */
#define	SYS_SBRD_PRES_EN	0x10	/* Board Insertion Interrupt En */
#define	SYS_PWR_OFF		0x08	/* Bit to turn system power */
#define	SYS_LED_LEFT		0x04	/* System Left LED. Reverse Logic */
#define	SYS_LED_MID		0x02	/* System Middle LED */
#define	SYS_LED_RIGHT		0x01	/* System Right LED */

/* Bit field defines for System Status1 register */
#define	SYS_SLOTS		0xC0	/* system type slot field */
#define	SYS_NOT_SECURE		0x20	/* ==0 Keyswitch in secure pos. */
#define	SYS_NOT_P_FAN_PRES	0x10	/* ==0 PPS cooling tray present */
#define	SYS_NOT_BRD_PRES	0x08	/* ==0 When board inserted */
#define	SYS_NOT_PPS0_PRES	0x04	/* ==0 If PPS0 present */
#define	SYS_TOD_NOT_RST		0x02	/* ==0 if TOD reset occurred */
#define	SYS_GEN_NOT_RST		0x01	/* ==0 if clock freq reset occured */

/* Macros to determine system type from System Status1 register */
#define	SYS_TYPE(x)		((x) & SYS_SLOTS)
#define	SYS_16_SLOT		0x40
#define	SYS_8_SLOT		0xC0
#define	SYS_4_SLOT		0x80
#define	SYS_TESTBED		0x00

/* Bit field defines for Clock Version Register */
#define	SYS_SLOTS2		0x80	/* system type slot2 mask */
#define	SYS_PLUS_SYSTEM		0x00	/* bit 7 is low for plus system */

/* Macros to determine frequency capability from clock version register */
#define	SYS_TYPE2(x)		((x) & SYS_SLOTS2)
#define	ISPLUSSYS(reg)		((reg != 0) && \
					(SYS_TYPE2(*reg) == SYS_PLUS_SYSTEM))

/* Macros to determine system type based on number of physical slots */
#define	IS4SLOT(n)		((n) == 4)
#define	IS5SLOT(n)		((n) == 5)
#define	IS8SLOT(n)		((n) == 8)
#define	IS16SLOT(n)		((n) == 16)
#define	ISTESTBED(n)		((n) == 0)

/* Bit field defines for System Status2 register */
#define	SYS_RMTE_NOT_RST	0x80	/* Remote Console reset occurred */
#define	SYS_PPS0_OK		0x40	/* ==1 PPS0 OK */
#define	SYS_CLK_33_OK		0x20	/* 3.3V OK on clock board */
#define	SYS_CLK_50_OK		0x10	/* 5.0V OK on clock board */
#define	SYS_AC_FAIL		0x08	/* System lost AC Power source */
#define	SYS_RACK_FANFAIL	0x04	/* Peripheral Rack fan status */
#define	SYS_AC_FAN_OK		0x02	/* Status of 4 AC box fans */
#define	SYS_KEYSW_FAN_OK	0x01	/* Status of keyswitch fan */

/* Bit field defines for Power Supply Presence register */
#define	SYS_NOT_PPS1_PRES	0x80	/* ==0 if PPS1 present in 4slot */

/* Bit field defines for Precharge and Peripheral Power Status register */
#define	SYS_NOT_CURRENT_S	0x80	/* Current share backplane */
#define	SYS_PPPSR_BITS		0x7f	/* bulk test bit mask */
#define	SYS_V5_P_OK		0x40	/* ==1 peripheral 5v ok */
#define	SYS_V12_P_OK		0x20	/* ==1 peripheral 12v ok */
#define	SYS_V5_AUX_OK		0x10	/* ==1 auxiliary 5v ok */
#define	SYS_V5_P_PCH_OK		0x08	/* ==1 peripheral 5v precharge ok */
#define	SYS_V12_P_PCH_OK	0x04	/* ==1 peripheral 12v precharge ok */
#define	SYS_V3_PCH_OK		0x02	/* ==1 system 3.3v precharge ok */
#define	SYS_V5_PCH_OK		0x01	/* ==1 system 5.0v precharge ok */

#ifndef _ASM

#define	SYSCTRL_KSTAT_NAME	"sysctrl"
#define	CSR_KSTAT_NAMED		"csr"
#define	STAT1_KSTAT_NAMED	"status1"
#define	STAT2_KSTAT_NAMED	"status2"
#define	CLK_FREQ2_KSTAT_NAMED	"clk_freq2"
#define	FAN_KSTAT_NAMED		"fan_status"
#define	KEY_KSTAT_NAMED		"key_status"
#define	POWER_KSTAT_NAMED	"power_status"
#define	BDLIST_KSTAT_NAME	"bd_list"
#define	CLK_VER_KSTAT_NAME	"clk_ver"

/*
 * The Power Supply shadow kstat is too large to fit in a kstat_named
 * struct, so it has been changed to be a raw kstat.
 */
#define	PSSHAD_KSTAT_NAME	"ps_shadow"

/* States of a power supply DC voltage. */
enum e_state { PS_BOOT = 0, PS_OUT, PS_UNKNOWN, PS_OK, PS_FAIL };
enum e_pres_state { PRES_UNKNOWN = 0, PRES_IN, PRES_OUT };

/*
 * several power supplies are managed -- 8 core power supplies,
 * up to two pps, a couple of clock board powers and a register worth
 * of precharges.
 */
#define	SYS_PS_COUNT 19
/* core PS 0 thru 7 are index 0 thru 7 */
#define	SYS_PPS0_INDEX		8
#define	SYS_CLK_33_INDEX	9
#define	SYS_CLK_50_INDEX	10
#define	SYS_V5_P_INDEX		11
#define	SYS_V12_P_INDEX		12
#define	SYS_V5_AUX_INDEX	13
#define	SYS_V5_P_PCH_INDEX	14
#define	SYS_V12_P_PCH_INDEX	15
#define	SYS_V3_PCH_INDEX	16
#define	SYS_V5_PCH_INDEX	17
#define	SYS_P_FAN_INDEX		18	/* the peripheral fan assy */

/* fan timeout structures */
enum pps_fan_type { RACK = 0, AC = 1, KEYSW = 2 };
#define	SYS_PPS_FAN_COUNT	3

/*
 * States of the secure key switch position.
 */
enum keyswitch_state { KEY_BOOT = 0, KEY_SECURE, KEY_NOT_SECURE };

/* Redundant power states */
enum power_state { BOOT = 0, BELOW_MINIMUM, MINIMUM, REDUNDANT };

/*
 * minor device mask
 * B	- bottom 4 bits (16 slots) are for the slot/receptacle id
 * I	- next 4 bits are for the instance number
 * X	- rest are not used
 *
 * Upper                  Lower
 * XXXXX...............IIIIBBBB
 *
 * Example:
 * device at instance 0 and slot 8, minor device number 0x8 = decimal 8
 * device at instance 1 and slot 10, minor device number 0x1A = decimal 26
 */
#define	SYSC_SLOT_MASK		0x0F
#define	SYSC_INSTANCE_MASK	0xF0
#define	SYSC_INSTANCE_SHIFT	4

/* Macro definitions */
#define	HOTPLUG_DISABLED_PROPERTY "hotplug-disabled"
#define	GETSLOT(unit)		(getminor(unit) & SYSC_SLOT_MASK)
#define	GETINSTANCE(unit) \
	((getminor(unit) & SYSC_INSTANCE_MASK) >> SYSC_INSTANCE_SHIFT)
#define	PUTINSTANCE(inst) \
	(((inst) << SYSC_INSTANCE_SHIFT) & SYSC_INSTANCE_MASK)
#define	GETSOFTC(i) \
	((struct sysctrl_soft_state *)ddi_get_soft_state(sysctrlp, getminor(i)))

/*
 * Definition of sysctrl ioctls.
 */
#define	SYSC_IOC		('H'<<8)

#define	SYSC_CFGA_CMD_GETSTATUS		(SYSC_IOC|68)
#define	SYSC_CFGA_CMD_EJECT		(SYSC_IOC|69)
#define	SYSC_CFGA_CMD_INSERT		(SYSC_IOC|70)
#define	SYSC_CFGA_CMD_CONNECT		(SYSC_IOC|71)
#define	SYSC_CFGA_CMD_DISCONNECT	(SYSC_IOC|72)
#define	SYSC_CFGA_CMD_UNCONFIGURE	(SYSC_IOC|73)
#define	SYSC_CFGA_CMD_CONFIGURE		(SYSC_IOC|74)
#define	SYSC_CFGA_CMD_TEST		(SYSC_IOC|75)
#define	SYSC_CFGA_CMD_TEST_SET_COND	(SYSC_IOC|76)
#define	SYSC_CFGA_CMD_QUIESCE_TEST	(SYSC_IOC|77)

#if defined(_KERNEL)

#define	SPUR_TIMEOUT_USEC			(1 * MICROSEC)
#define	SPUR_LONG_TIMEOUT_USEC			(5 * MICROSEC)
#define	AC_TIMEOUT_USEC				(1 * MICROSEC)
#define	PS_FAIL_TIMEOUT_USEC			(500 * (MICROSEC / MILLISEC))
#define	PPS_FAN_TIMEOUT_USEC			(1 * MICROSEC)

#define	BRD_INSERT_DELAY_USEC			(500 * (MICROSEC / MILLISEC))
#define	BRD_INSERT_RETRY_USEC			(5 * MICROSEC)
#define	BRD_REMOVE_TIMEOUT_USEC			(2 * MICROSEC)
#define	BLINK_LED_TIMEOUT_USEC			(300 * (MICROSEC / MILLISEC))
#define	KEYSWITCH_TIMEOUT_USEC			(1 * MICROSEC)

#define	PS_INSUFFICIENT_COUNTDOWN_SEC		30

/*
 * how many ticks to wait to register the state change
 * NOTE: ticks are measured in PS_FAIL_TIMEOUT_USEC clicks
 */
#define	PS_PRES_CHANGE_TICKS	1
#define	PS_FROM_BOOT_TICKS	1
#define	PS_FROM_UNKNOWN_TICKS	10
#define	PS_POWER_COUNTDOWN_TICKS 60

/* Note: this timeout needs to be longer than FAN_OK_TIMEOUT_USEC */
#define	PS_P_FAN_FROM_UNKNOWN_TICKS 15

#define	PS_FROM_OK_TICKS	1
#define	PS_PCH_FROM_OK_TICKS	3
#define	PS_FROM_FAIL_TICKS	4

/* NOTE: these ticks are measured in PPS_FAN_TIMEOUT_USEC clicks */
#define	PPS_FROM_FAIL_TICKS	7

/*
 * how many spurious interrupts to take during a SPUR_LONG_TIMEOUT_USEC
 * before complaining
 */
#define	MAX_SPUR_COUNT		2

/*
 * Global driver structure which defines the presence and status of
 * all board power supplies.
 */
struct ps_state {
	int pctr;			/* tick counter for presense deglitch */
	int dcctr;			/* tick counter for dc ok deglitch */
	enum e_pres_state pshadow;	/* presense shadow state */
	enum e_state dcshadow;		/* dc ok shadow state */
};

/*
 * for sysctrl_thread_wakeup()
 */
#define	OVERTEMP_POLL	1
#define	KEYSWITCH_POLL	2

/*
 * Structures used in the driver to manage the hardware
 * XXX will need to add a nodeid
 */
struct sysctrl_soft_state {
	dev_info_t *dip;		/* dev info of myself */
	dev_info_t *pdip;		/* dev info of parent */
	struct sysctrl_soft_state *next;
	int mondo;			/* INO for this type of interrupt */
	uchar_t nslots;			/* slots in this system (0-16) */

	pnode_t options_nodeid;		/* for nvram powerfail-time */

	ddi_iblock_cookie_t iblock;	/* High level interrupt cookie */
	ddi_idevice_cookie_t idevice;	/* TODO - Do we need this? */
	ddi_softintr_t spur_id;		/* when we get a spurious int... */
	ddi_iblock_cookie_t spur_int_c;	/* spur int cookie */
	ddi_softintr_t spur_high_id;	/* when we reenable disabled ints */
	ddi_softintr_t spur_long_to_id;	/* long timeout softint */
	ddi_softintr_t ac_fail_id;	/* ac fail softintr id */
	ddi_softintr_t ac_fail_high_id;	/* ac fail re-enable softintr id */
	ddi_softintr_t ps_fail_int_id;	/* ps fail from intr softintr id */
	ddi_iblock_cookie_t ps_fail_c;	/* ps fail softintr cookie */
	ddi_softintr_t ps_fail_poll_id;	/* ps fail from polling softintr */
	ddi_softintr_t pps_fan_id;	/* pps fan fail softintr id */
	ddi_softintr_t pps_fan_high_id;	/* pps fan re-enable softintr id */
	ddi_softintr_t sbrd_pres_id;	/* sbrd softintr id */
	ddi_softintr_t sbrd_gone_id;	/* sbrd removed softintr id */
	ddi_softintr_t blink_led_id;	/* led blinker softint */
	ddi_iblock_cookie_t sys_led_c;	/* mutex cookie for sys LED lock */

	volatile uchar_t *clk_freq1;	/* Clock frequency reg. 1 */
	volatile uchar_t *clk_freq2;	/* Clock frequency reg. 2 */
	volatile uchar_t *status1;	/* System Status1 register */
	volatile uchar_t *status2;	/* System Status2 register */
	volatile uchar_t *ps_stat;	/* Power Supply Status register */
	volatile uchar_t *ps_pres;	/* Power Supply Presence register */
	volatile uchar_t *pppsr;	/* 2nd Power Supply Status register */
	volatile uchar_t *temp_reg;	/* VA of temperature register */
	volatile uchar_t *rcons_ctl;	/* VA of Remote console UART */
	volatile uchar_t *clk_ver;	/* clock version register */

	/* This mutex protects the following data */
	/* NOTE: *csr should only be accessed from interrupt level */
	kmutex_t csr_mutex;		/* locking for csr enable bits */
	volatile uchar_t *csr;		/* System Control Register */
	uchar_t pps_fan_saved;		/* cached pps fanfail state */
	uchar_t saved_en_state;		/* spurious int cache */
	int spur_count;			/* count multiple spurious ints */

	/* This mutex protects the following data */
	kmutex_t spur_int_lock;		/* lock spurious interrupt data */
	timeout_id_t spur_timeout_id;	/* quiet the int timeout id */
	timeout_id_t spur_long_timeout_id; /* spurious long timeout interval */

	/* This mutex protects the following data */
	kmutex_t ps_fail_lock;		/* low level lock */
	struct ps_state ps_stats[SYS_PS_COUNT]; /* state struct for all ps */
	enum power_state power_state;	/* redundant power state */
	int power_countdown;		/* clicks until reboot */

	/* This mutex protects the following data */
	kmutex_t sys_led_lock;		/* low level lock */
	int sys_led;			/* on (TRUE) or off (FALSE) */
	int sys_fault;			/* on (TRUE) or off (FALSE) */

	/* various elements protected by their inherent access patterns */
	int pps_fan_external_state;	/* external state of the pps fans */
	int pps_fan_state_count[SYS_PPS_FAN_COUNT]; /* fan state counter */
	struct temp_stats tempstat;	/* in memory storage of temperature */
	enum keyswitch_state key_shadow; /* external state of the key switch */

	int enable_rcons_atboot;	/* enable remote console at boot */
};

/*
 * Kstat structures used to contain data which is requested by user
 * programs.
 */
struct sysctrl_kstat {
	struct kstat_named	csr;		/* system control register */
	struct kstat_named	status1;	/* system status 1 */
	struct kstat_named	status2;	/* system status 2 */
	struct kstat_named	clk_freq2;	/* Clock register 2 */
	struct kstat_named	fan_status;	/* shadow status 2 for fans */
	struct kstat_named	key_status;	/* shadow status for key */
	struct kstat_named	power_state;	/* redundant power status */
	struct kstat_named	clk_ver;	/* clock version register */
};

#define	SYSC_ERR_SET(pkt, err)	(pkt)->cmd_cfga.errtype = (err)

/*
 * Function prototype
 */
int sysc_policy_disconnect(struct sysctrl_soft_state *,
				sysc_cfga_pkt_t *, sysc_cfga_stat_t *);
int sysc_policy_connect(struct sysctrl_soft_state *,
				sysc_cfga_pkt_t *, sysc_cfga_stat_t *);
int sysc_policy_unconfigure(struct sysctrl_soft_state *,
				sysc_cfga_pkt_t *, sysc_cfga_stat_t *);
int sysc_policy_configure(struct sysctrl_soft_state *,
				sysc_cfga_pkt_t *, sysc_cfga_stat_t *);

void sysc_policy_update(void *softsp, sysc_cfga_stat_t *sc, sysc_evt_t event);

extern void		sysctrl_suspend_prepare(void);
extern int		sysctrl_suspend(sysc_cfga_pkt_t *);
extern void		sysctrl_resume(sysc_cfga_pkt_t *);

#endif /* _KERNEL */
#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SYSCTRL_H */
