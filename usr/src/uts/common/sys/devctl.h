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

#ifndef	_SYS_DEVCTL_H
#define	_SYS_DEVCTL_H

/*
 * Device control interfaces
 */
#include <sys/types.h>
#include <sys/nvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * structure used to pass IOCTL data between the libdevice interfaces
 * and nexus driver devctl IOCTL interface.
 *
 * Applications and nexus drivers may not access the contents of this
 * structure directly.  Instead, drivers must use the ndi_dc_*(9n)
 * interfaces, while applications must use the interfaces provided by
 * libdevice.so.1.
 */
struct devctl_iocdata {
	uint_t	cmd;			/* ioctl cmd */
	uint_t	flags;			/* command-specific flags */
	void	*cpyout_buf;		/* copyout vector */
	nvlist_t *nvl_user;		/* application defined attributes */
	size_t  nvl_usersz;
	char	*c_nodename;		/* child device nodename */
	char	*c_unitaddr;		/* child device unit address */
};

#if defined(_SYSCALL32)
/*
 * Structure to pass/return data from 32-bit program's.
 */
struct devctl_iocdata32 {
	uint32_t  cmd;
	uint32_t  flags;
	caddr32_t cpyout_buf;
	caddr32_t nvl_user;
	uint32_t  nvl_usersz;
	caddr32_t c_nodename;
	caddr32_t c_unitaddr;
};
#endif

/*
 * Limit size of packed application defined attributes (nvl_user) to prevent
 * user application from requesting excessive kernel memory allocation.
 */
#define	DEVCTL_MAX_NVL_USERSZ	0x10000

/*
 * State of receptacle for an Attachment Point.
 */
typedef enum {
	AP_RSTATE_EMPTY,
	AP_RSTATE_DISCONNECTED,
	AP_RSTATE_CONNECTED
} ap_rstate_t;

/*
 * State of occupant for an Attachment Point.
 */
typedef enum {
	AP_OSTATE_UNCONFIGURED,
	AP_OSTATE_CONFIGURED
} ap_ostate_t;

/*
 * condition of an Attachment Point.
 */
typedef enum {
	AP_COND_UNKNOWN,
	AP_COND_OK,
	AP_COND_FAILING,
	AP_COND_FAILED,
	AP_COND_UNUSABLE
} ap_condition_t;

/*
 * structure used to return the state of Attachment Point (AP) thru
 * devctl_ap_getstate() interface.
 */

typedef struct devctl_ap_state {
	ap_rstate_t	ap_rstate; 	/* receptacle state */
	ap_ostate_t	ap_ostate;	/* occupant state */
	ap_condition_t	ap_condition;	/* condition of AP */
	time_t		ap_last_change;
	uint32_t	ap_error_code;	/* error code */
	uint8_t		ap_in_transition;
} devctl_ap_state_t;

#if defined(_SYSCALL32)
/*
 * Structure to pass/return data from 32-bit program's.
 */
typedef struct devctl_ap_state32 {
	ap_rstate_t	ap_rstate; 	/* receptacle state */
	ap_ostate_t	ap_ostate;	/* occupant state */
	ap_condition_t	ap_condition;	/* condition of AP */
	time32_t	ap_last_change;
	uint32_t	ap_error_code;	/* error code */
	uint8_t		ap_in_transition;
} devctl_ap_state32_t;
#endif

#define	DEVCTL_IOC		(0xDC << 16)
#define	DEVCTL_IOC_MAX		(DEVCTL_IOC | 0xFFFF)
#define	DEVCTL_BUS_QUIESCE	(DEVCTL_IOC | 1)
#define	DEVCTL_BUS_UNQUIESCE	(DEVCTL_IOC | 2)
#define	DEVCTL_BUS_RESETALL	(DEVCTL_IOC | 3)
#define	DEVCTL_BUS_RESET	(DEVCTL_IOC | 4)
#define	DEVCTL_BUS_GETSTATE	(DEVCTL_IOC | 5)
#define	DEVCTL_DEVICE_ONLINE	(DEVCTL_IOC | 6)
#define	DEVCTL_DEVICE_OFFLINE	(DEVCTL_IOC | 7)
#define	DEVCTL_DEVICE_GETSTATE	(DEVCTL_IOC | 9)
#define	DEVCTL_DEVICE_RESET	(DEVCTL_IOC | 10)
#define	DEVCTL_BUS_CONFIGURE	(DEVCTL_IOC | 11)
#define	DEVCTL_BUS_UNCONFIGURE	(DEVCTL_IOC | 12)
#define	DEVCTL_DEVICE_REMOVE	(DEVCTL_IOC | 13)
#define	DEVCTL_AP_CONNECT	(DEVCTL_IOC | 14)
#define	DEVCTL_AP_DISCONNECT	(DEVCTL_IOC | 15)
#define	DEVCTL_AP_INSERT	(DEVCTL_IOC | 16)
#define	DEVCTL_AP_REMOVE	(DEVCTL_IOC | 17)
#define	DEVCTL_AP_CONFIGURE	(DEVCTL_IOC | 18)
#define	DEVCTL_AP_UNCONFIGURE	(DEVCTL_IOC | 19)
#define	DEVCTL_AP_GETSTATE	(DEVCTL_IOC | 20)
#define	DEVCTL_AP_CONTROL	(DEVCTL_IOC | 21)
#define	DEVCTL_BUS_DEV_CREATE	(DEVCTL_IOC | 22)
#define	DEVCTL_PM_BUSY_COMP	(DEVCTL_IOC | 23)
#define	DEVCTL_PM_IDLE_COMP	(DEVCTL_IOC | 24)
#define	DEVCTL_PM_RAISE_PWR	(DEVCTL_IOC | 25)
#define	DEVCTL_PM_LOWER_PWR	(DEVCTL_IOC | 26)
#define	DEVCTL_PM_CHANGE_PWR_LOW	(DEVCTL_IOC | 27)
#define	DEVCTL_PM_CHANGE_PWR_HIGH	(DEVCTL_IOC | 28)
#define	DEVCTL_PM_POWER		(DEVCTL_IOC | 29)
#define	DEVCTL_PM_PROM_PRINTF	(DEVCTL_IOC | 30)
#define	DEVCTL_PM_FAIL_SUSPEND	(DEVCTL_IOC | 31)
#define	DEVCTL_PM_PWR_HAS_CHANGED_ON_RESUME	(DEVCTL_IOC | 32)
#define	DEVCTL_PM_PUP_WITH_PWR_HAS_CHANGED	(DEVCTL_IOC | 34)
#define	DEVCTL_PM_BUSY_COMP_TEST	(DEVCTL_IOC | 35)
#define	DEVCTL_PM_BUS_STRICT_TEST	(DEVCTL_IOC | 36)
#define	DEVCTL_PM_NO_LOWER_POWER	(DEVCTL_IOC | 37)
#define	DEVCTL_PM_BUS_NO_INVOL		(DEVCTL_IOC | 38)
#define	DEVCTL_SET_LED		(DEVCTL_IOC | 39)
#define	DEVCTL_GET_LED		(DEVCTL_IOC | 40)
#define	DEVCTL_NUM_LEDS		(DEVCTL_IOC | 41)


/*
 * is (c) in the range of possible devctl IOCTL commands?
 */
#define	IS_DEVCTL(c) (((c) >= DEVCTL_IOC) && ((c) <= DEVCTL_IOC_MAX))

/*
 * Device and Bus State definitions
 *
 * Device state is returned as a set of bit-flags that indicate the current
 * operational state of a device node.
 *
 * Device nodes for leaf devices only contain state information for the
 * device itself.  Nexus device nodes contain both Bus and Device state
 * information.
 *
 * 	DEVICE_ONLINE  - Device is available for use by the system.  Mutually
 *                       exclusive with DEVICE_OFFLINE.
 *
 *	DEVICE_OFFLINE - Device is unavailable for use by the system.
 *			 Mutually exclusive with DEVICE_ONLINE and DEVICE_BUSY.
 *
 *	DEVICE_DOWN    - Device has been placed in the "DOWN" state by
 *			 its controlling driver.
 *
 *	DEVICE_BUSY    - Device has open instances or nexus has INITALIZED
 *                       children (nexi).  A device in this state is by
 *			 definition Online.
 *
 * Bus state is returned as a set of bit-flags which indicates the
 * operational state of a bus associated with the nexus dev_info node.
 *
 * 	BUS_ACTIVE     - The bus associated with the device node is Active.
 *                       I/O requests from child devices attached to the
 *			 are initiated (or queued for initiation) as they
 *			 are received.
 *
 *	BUS_QUIESCED   - The bus associated with the device node has been
 *			 Quieced. I/O requests from child devices attached
 *			 to the bus are held pending until the bus nexus is
 *			 Unquiesced.
 *
 *	BUS_SHUTDOWN   - The bus associated with the device node has been
 *			 shutdown by the nexus driver.  I/O requests from
 *			 child devices are returned with an error indicating
 *			 the requested operation failed.
 */
#define	DEVICE_ONLINE	0x1
#define	DEVICE_BUSY	0x2
#define	DEVICE_OFFLINE  0x4
#define	DEVICE_DOWN	0x8

#define	BUS_ACTIVE	0x10
#define	BUS_QUIESCED	0x20
#define	BUS_SHUTDOWN	0x40

#define	DEVICE_STATES_ASCII	"Dev_Online", "Dev_Busy", "Dev_Offline", \
	"Dev_Down", "Bus_Active", "Bus_Quiesced", "Bus_Shutdown"

#define	DC_DEVI_NODENAME	"ndi_dc.devi_nodename"

#define	DEVCTL_CONSTRUCT	0x1
#define	DEVCTL_OFFLINE		0x2

/*
 * Drive status LED control
 */
struct dc_led_ctl {
	uint32_t	led_number : 16;	/* LED/device number */
	uint32_t	led_ctl_active : 1;	/* Control active */
	uint32_t	led_type : 9;		/* LED type */
	uint32_t	led_state : 6;		/* LED ON/OFF/Blink state */
};

/* Control active field */
#define	DCL_CNTRL_OFF		0	/* Control inactive */
#define	DCL_CNTRL_ON		1	/* Control active */

/* LED type field */
#define	DCL_TYPE_DEVICE_FAIL	1	/* Device FAIL LED type */
#define	DCL_TYPE_DEVICE_OK2RM	2	/* Device OK2RM LED type */

/* LED state field */
#define	DCL_STATE_OFF		0	/* LED state OFF */
#define	DCL_STATE_ON		1	/* LED state ON */
#define	DCL_STATE_SLOW_BLNK	2	/* LED slow blink */
#define	DCL_STATE_FAST_BLNK	3	/* LED fast blink */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DEVCTL_H */
