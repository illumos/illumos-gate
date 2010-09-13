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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_LOM_PRIV_H
#define	_SYS_LOM_PRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Project private LOMlite definitions.
 * The definitions here are not used by the end user.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#ifdef __sparc
#include <sys/cpu_sgnblk_defs.h>
#endif /* __sparc */
#endif /* _KERNEL */

/*
 * Data structures which are passed to the driver via the LOMIOCPROG ioctl.
 *
 * The userland utility constructs an image which begins with a
 * lom_prog_data_t structure and is followed by platform specific data
 * the contents of which are identified by the 'platmagic' value.
 */
typedef struct {
	union {
		uint32_t	magic;
		struct {
			uint16_t	size;
			uint16_t	loadaddr;
		} old_prog;
	}		header;
	uint32_t	platmagic;
	/* Platform specific */
	union {
		struct {
			uint32_t	loadaddr;
			uint32_t	size;
		} bscv;
	} platform;
} lom_prog_data_t;

/*
 * header.magic value - this is chosen because it never occurs on the old
 * programming data
 */
#define	PROG_MAGIC	0

/*
 * platmagic values.
 * Top two bytes assigned to specific lom implementations/platform
 * Bottom two bytes assigned by the implementations/platform.
 *
 * 0x4c56 "LV" - bscv and derivatives.
 *	0x4c564c4f "LVLO" - firmware downloader.
 *	0x4c56494d "LVIM" - firmware image.
 * 0x5347 "SG" - serengeti based lom.
 *	Not specified here.
 */

#define	PROG_PLAT_BSCV_LOADER	0x4c564c4f
#define	PROG_PLAT_BSCV_IMAGE	0x4c56494d
#define	PROG_PLAT_SG_IMAGE	0x5347494d

/* defn for top byte of 16bit event code */
#define	EVENT_SUBSYS_NONE	0x00
#define	EVENT_SUBSYS_ALARM	0x01
#define	EVENT_SUBSYS_TEMP	0x02
#define	EVENT_SUBSYS_OVERTEMP	0x03
#define	EVENT_SUBSYS_FAN	0x04
#define	EVENT_SUBSYS_SUPPLY	0x05
#define	EVENT_SUBSYS_BREAKER	0x06
#define	EVENT_SUBSYS_PSU	0x07
#define	EVENT_SUBSYS_USER	0x08
#define	EVENT_SUBSYS_PHONEHOME	0x09
#define	EVENT_SUBSYS_LOM	0x0a
#define	EVENT_SUBSYS_HOST	0x0b
#define	EVENT_SUBSYS_EVENTLOG	0x0c
#define	EVENT_SUBSYS_EXTRA	0x0d	/* reserved for future use */
#define	EVENT_SUBSYS_LED	0x0e

#define	EVENT_MASK_SHUTDOWN_REQD	0x20
#define	EVENT_MASK_FAULT		0x40
#define	EVENT_MASK_FATAL		0x80


#define	EVENT_NONE			0x00
#define	EVENT_STATE_ON			0x01
#define	EVENT_STATE_OFF			0x02
#define	EVENT_STATE_CHANGE		0x03
#define	EVENT_POWER_ON			0x04
#define	EVENT_POWER_OFF			0x05
#define	EVENT_UNEXPECTED_POWER_OFF	0x06
#define	EVENT_UNEXPECTED_RESET		0x07
#define	EVENT_BOOTED			0x08
#define	EVENT_WATCHDOG_ON		0x09
#define	EVENT_WATCHDOG_OFF		0x0a
#define	EVENT_WATCHDOG_TRIGGER		0x0b
#define	EVENT_FAILED			0x0c
#define	EVENT_RECOVERED			0x0d
#define	EVENT_RESET			0x0e
#define	EVENT_ABORT			0x0f
#define	EVENT_CONSOLE_SELECT		0x10
#define	EVENT_TIME_REFERENCE		0x11
#define	EVENT_SCRIPT_FAILURE		0x12
#define	EVENT_MODEM_ACCESS_FAIL		0x13
#define	EVENT_MODEM_DIAL_FAIL		0x14
#define	EVENT_BAD_CHECKSUM		0x15
#define	EVENT_USER_ADDED		0x16
#define	EVENT_USER_REMOVED		0x17
#define	EVENT_USER_PERMSCHANGED		0x18
#define	EVENT_USER_LOGIN		0x19
#define	EVENT_USER_PASSWORD_CHANGE	0x1a
#define	EVENT_USER_LOGINFAIL		0x1b
#define	EVENT_USER_LOGOUT		0x1c
#define	EVENT_FLASH_DOWNLOAD		0x1d
#define	EVENT_DATA_LOST			0x1e
#define	EVENT_DEVICE_BUSY		0x1f
#define	EVENT_FAULT_LED			0x20
#define	EVENT_OVERHEAT			0x21
#define	EVENT_SEVERE_OVERHEAT		0x22
#define	EVENT_NO_OVERHEAT		0x23
#define	EVENT_SCC_STATUS		0x24
/* bscv only */
#define	EVENT_DEVICE_INACCESSIBLE	0x25
#define	EVENT_HOSTNAME_CHANGE		0x26
#define	EVENT_CPUSIG_TIMEOUT		0x27
#define	EVENT_BOOTMODE_CHANGE		0x28
#define	EVENT_WATCHDOG_CHANGE_POLICY	0x29
#define	EVENT_WATCHDOG_CHANGE_TIMEOUT	0x2a

/*
 * Event "detail" information - bscv only
 */
#define	LOM_RESET_DETAIL_BYUSER			1
#define	LOM_RESET_DETAIL_REPROGRAMMING 		2

#define	LOM_WDOGTRIGGER_DETAIL_HARD		0
#define	LOM_WDOGTRIGGER_DETAIL_SOFT		1

#define	LOM_UNEXPECTEDRESET_MASK_BADTRAP	0x80
#define	EBUS_BOOTMODE_FORCE_CONSOLE		0x01

/*
 * Event log filtering
 */
#define	EVENT_LEVEL_USER		4
#define	EVENT_LEVEL_NOTICE		3
#define	EVENT_LEVEL_FAULT		2
#define	EVENT_LEVEL_FATAL		1

/*
 * Event data
 */
typedef struct {
	uint8_t		ev_subsys;
	uint8_t		ev_event;
	uint8_t		ev_resource;
	uint8_t		ev_detail;
	uint8_t		ev_data[4];
} lom_event_t;


#define	EVENT_DECODE_SUBSYS(evcode)	((evcode) & 0x1f)
#define	EVENT_DECODE_FAULT(evcode)	((evcode) & (EVENT_MASK_FAULT| \
						EVENT_MASK_FATAL| \
						EVENT_MASK_SHUTDOWN_REQD))

/* Magic numbers for reading values from conf files */
#define	LOM_TEMP_PROP_NOT_SET	0x80000000	/* Use current setting */
#define	LOM_TEMP_PROP_MIN	40		/* Minimum temp settable */
#define	LOM_TEMP_PROP_MAX	120		/* Maximum temp settable */

#define	LOM_SERIAL_TOUT_DEFAULT	0		/* Default value */
#define	LOM_SERIAL_TOUT_MIN	5		/* Minimum timeout period */
#define	LOM_SERIAL_TOUT_MAX	0xff		/* Maximum timeout period */

#ifdef	_KERNEL
/* Inter Driver Interface */

#define	SUNW_KERN_BSCV_MODULENAME		"bscv"
#define	SUNW_KERN_BSCV_IDI_FN			"bscv_idi_set"

enum bscv_idi_type    {
	BSCV_IDI_NULL = 0,
	BSCV_IDI_NODENAME,
	BSCV_IDI_SIG,
	BSCV_IDI_WDOG_PAT,
	BSCV_IDI_WDOG_CFG
};

#ifdef __sparc
typedef
struct {
	uint32_t	cpu;
	sig_state_t	sig_info;
} bscv_sig_t;
#endif /* __sparc */

typedef
struct {
	/*
	 * Enable the watchdog.  This must be done before patting is done.
	 */
	uint8_t			enable_wdog;

	/*
	 * wdog_timeout_s seconds before watchdog expires; minimum
	 * value is 1, maximum value is 127.  The dog must be patted
	 * once per second.
	 */
	uint_t			wdog_timeout_s;

	/*
	 * reset_system_on_timeout false means the microcontroller will only
	 * log the fact that the watchdog expired, rather than actually
	 * resetting the host.
	 */
	uint8_t			reset_system_on_timeout;

} bscv_wdog_t;

struct bscv_idi_info  {
	enum bscv_idi_type	type;
	void			*data;
	size_t			size;
};

void bscv_idi_set(struct bscv_idi_info info);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_LOM_PRIV_H */
