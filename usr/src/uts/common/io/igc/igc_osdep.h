/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _IGC_OSDEP_H
#define	_IGC_OSDEP_H

/*
 * Definitions that are required for the igc core code.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The common code requires the following headers.
 */
#include <sys/stdbool.h>
#include <sys/sunddi.h>

/*
 * It requires the following due to what we have declared.
 */
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/bitext.h>

/*
 * We redeclare the forward struct igc_hw here because this is required to be
 * included for igc_hw.h.
 */
struct igc_hw;

/*
 * The following typedefs allow for the types in the core code to be defined in
 * terms of types that we actually use.
 */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;

/*
 * Register read and write APIs. While these are in all caps because they are
 * conventionally macros, we implement them as functions in igc_osdep.c.
 */
extern uint32_t IGC_READ_REG(struct igc_hw *, uint32_t);
extern void IGC_WRITE_REG(struct igc_hw *, uint32_t, uint32_t);
extern void IGC_WRITE_REG_ARRAY(struct igc_hw *, uint32_t, uint32_t, uint32_t);

/*
 * This is the implementation of a flush command which forces certain PCIe
 * transaction ordering to complete.
 */
#define	IGC_WRITE_FLUSH(hw)	IGC_READ_REG(hw, IGC_STATUS)

/*
 * Delay variants. The semantics in the common code and Linux use non-sleeping
 * delay variants. It's not really clear that we should be spinning for
 * miliseconds, but for now, that's what we end up doing.
 */
#define	usec_delay(x)		drv_usecwait(x)
#define	usec_delay_irq(x)	drv_usecwait(x)
#define	msec_delay(x)		drv_usecwait((x) * 1000)
#define	msec_delay_irq(x)	drv_usecwait((x) * 1000)

/*
 * Debugging macros that the common code expects to exist. Because of how these
 * are used, we need to define something lest we generate empty body warnings.
 */
extern void igc_core_log(struct igc_hw *, const char *, ...);
#define	DEBUGOUT(str)		igc_core_log(hw, str)
#define	DEBUGOUT1(str, d1)	igc_core_log(hw, str, d1)
#define	DEBUGOUT2(str, d1, d2)	igc_core_log(hw, str, d1, d2)
#define	DEBUGFUNC(str)		igc_core_log(hw, str)

/*
 * The following defines registers or register values that should be defined by
 * the core code, but are not right now. As such, we define them here to
 * minimize the diffs that are required in the core code.
 */

/*
 * Used in the IGC_EECD register to indicate that a flash device is present.
 */
#define	IGC_EECD_EE_DET		(1 << 19)

/*
 * Starting positions of the IVAR queue regions.
 */
#define	IGC_IVAR_RX0_START	0
#define	IGC_IVAR_TX0_START	8
#define	IGC_IVAR_RX1_START	16
#define	IGC_IVAR_TX1_START	24
#define	IGC_IVAR_ENT_LEN	8

/*
 * The I225 has the exact same LED controls that the other parts have. There are
 * three LEDs defined in the IC which are initialized by firmware and controlled
 * through the classic LEDCTL register just like igb/e1000g. While the register
 * is in igc_regs.h, the actual values for the modes in igc_defines.h do not
 * match the I225 Ethernet Controller Datasheet. They match older parts without
 * 2.5 GbE support. See I225/6 Datasheet v2.6.7 Section 3.4 'Configurable LED
 * Outputs'.
 */
typedef enum {
	I225_LED_M_ON	= 0,
	I225_LED_M_OFF,
	I225_LED_M_LINK_UP,
	I225_LED_M_FILTER_ACT,
	I225_LED_M_LINK_ACT,
	I225_LED_M_LINK_10,
	I225_LED_M_LINK_100,
	I225_LED_M_LINK_1000,
	I225_LED_M_LINK_2500,
	I225_LED_M_SDP,
	I225_LED_M_PAUSE,
	I225_LED_M_ACT,
	I225_LED_M_LINK_10_100,
	I225_LED_M_LINK_100_1000,
	I225_LED_M_LINK_1000_2500,
	I225_LED_M_LINK_100_2500,
} i225_led_mode_t;

/*
 * The LED registers are organized into three groups that repeat. Register
 * manipulation functions are defined in igc.c. The following are constants for
 * the various registers.
 */
#define	IGC_I225_NLEDS			3
#define	IGC_LEDCTL_GLOB_BLINK_200MS	0
#define	IGC_LEDCTL_GLOB_BLINK_83MS	1

/*
 * IEEE MMD Status register 7.33 access. These definitions are done in the style
 * of igc_defines.h, where this phy is missing. We should eventually update the
 * mii layer headers to know about this. See IEEE Table 45-386 'MultiGBASE-T AN
 * status 1 register'.
 */
#define	ANEG_MULTIGBT_AN_STS1		0x0021 /* MULTI GBT Status 1 register */
#define	MMD_AN_STS1_LP_40T_FRT		(1 << 0)
#define	MMD_AN_STS1_LP_10T_FRT		(1 << 1)
#define	MMD_AN_STS1_LP_25T_FRT		(1 << 2)
#define	MMD_AN_STS1_LP_2P5T_FRT		(1 << 3)
#define	MMD_AN_STS1_LP_5T_FRT		(1 << 4)
#define	MMD_AN_STS1_LP_2P5T_CAP		(1 << 5)
#define	MMD_AN_STS1_LP_5T_CAP		(1 << 6)
#define	MMD_AN_STS1_LP_25T_CAP		(1 << 7)
#define	MMD_AN_STS1_LP_40T_CAP		(1 << 8)
#define	MMD_AN_STS1_LP_10T_PMA		(1 << 9)
#define	MMD_AN_STS1_LP_LOOP_TIME	(1 << 10)
#define	MMD_AN_STS1_LP_10T_CAP		(1 << 11)
#define	MMD_AN_STS1_LP_REM_STS		(1 << 12)
#define	MMD_AN_STS1_LP_LOC_STS		(1 << 13)
#define	MMD_AN_STS1_LP_MSC_RES		(1 << 14)
#define	MMD_AN_STS1_LP_MSC_FLT		(1 << 15)

/*
 * Reserved bits in the RXDCTL register that must be preserved. The I210
 * datasheet indicates that it leverages bits 24:21 and then 31:27. There are
 * other reserved portions by they are explicitly write 0.
 */
#define	IGC_RXDCTL_PRESERVE	0xf9e00000

/*
 * Missing setters for the various prefetch, host, and write-back thresholds.
 */
#define	IGC_RXDCTL_SET_PTHRESH(r, v)	bitset32(r, 4, 0, v)
#define	IGC_RXDCTL_SET_HTHRESH(r, v)	bitset32(r, 12, 8, v)
#define	IGC_RXDCTL_SET_WTHRESH(r, v)	bitset32(r, 20, 16, v)

/*
 * Missing setters for the tx varaint. We assume that this uses the shorter I210
 * 5-bit range as opposed to the I217 6-bit range. Given we don't set anything
 * much higher than this, this is the best we can do. In general this is more
 * I210-like than I217-like.
 */
#define	IGC_TXDCTL_SET_PTHRESH(r, v)	bitset32(r, 4, 0, v)
#define	IGC_TXDCTL_SET_HTHRESH(r, v)	bitset32(r, 13, 8, v)
#define	IGC_TXDCTL_SET_WTHRESH(r, v)	bitset32(r, 20, 16, v)

#ifdef __cplusplus
}
#endif

#endif /* _IGC_OSDEP_H */
