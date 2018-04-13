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
 * Copyright (c) 2018 Joyent, Inc.
 */

#ifndef _AHCIEM_H
#define	_AHCIEM_H

/*
 * Private interface to AHCI Enclosure services
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	AHCI_EM_IOC	(('a' << 24) | ('e' << 16) | ('m' << 8))
#define	AHCI_EM_IOC_GET	(AHCI_EM_IOC | 0x00)
#define	AHCI_EM_IOC_SET	(AHCI_EM_IOC | 0x01)

#define	AHCI_EM_IOC_MAX_PORTS	32

/*
 * The default state for LEDs is to have ident and fault disabled and activity
 * enabled, if in hardware control.
 */
typedef enum ahci_em_led_state {
	AHCI_EM_LED_IDENT_ENABLE	= 1 << 0,
	AHCI_EM_LED_FAULT_ENABLE	= 1 << 1,
	AHCI_EM_LED_ACTIVITY_DISABLE	= 1 << 2
} ahci_em_led_state_t;

#define	AHCI_EM_FLAG_CONTROL_ACTIVITY	0x01

typedef struct ahci_ioc_em_get {
	uint_t	aiemg_nports;
	uint_t	aiemg_flags;
	uint_t	aiemg_status[AHCI_EM_IOC_MAX_PORTS];
} ahci_ioc_em_get_t;


/*
 * Values set in aiems_op that control the behavior of the ioctl. If ADD is set,
 * the listed flags are added to the current set. If, REM is set, then the flags
 * are removed. If SET is set, then the flags are replaced.
 */
#define	AHCI_EM_IOC_SET_OP_ADD		0x01
#define	AHCI_EM_IOC_SET_OP_REM		0x02
#define	AHCI_EM_IOC_SET_OP_SET		0x03

typedef struct ahci_ioc_em_set {
	uint_t	aiems_port;
	uint_t	aiems_op;
	uint_t	aiems_leds;
	uint_t	aiems_pad;
} ahci_ioc_em_set_t;

#ifdef __cplusplus
}
#endif

#endif /* _AHCIEM_H */
