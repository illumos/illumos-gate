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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_ENVCTRL_GEN_H
#define	_SYS_ENVCTRL_GEN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * envctrl_gen.h
 *
 * This header file holds the environmental control definitions that
 * are common to all workgroup server platforms. Typically, all IOCTLs,
 * kstat structures, and the generic constants are defined here.
 * The platform specific definitions belong in header files which contain
 * the platform name as part of the file name eg. envctrl_ue250.h for the
 * UltraEnterprise-250 platform.
 */

#define	ENVCTRL_NORMAL_MODE 0x01
#define	ENVCTRL_DIAG_MODE 0x02
#define	ENVCTRL_CHAR_ZERO 0x00
#define	ENVCTRL_PS_550	550
#define	ENVCTRL_PS_650	650
#define	ENVCTRL_INIT_TEMPR	20
#define	ENVCTRL_ULTRA1CPU_STRING	"SUNW,UltraSPARC"
#define	ENVCTRL_ULTRA2CPU_STRING	"SUNW,UltraSPARC-II"

#define	ENVCTRL_MAX_CPUS	8
#define	ENVCTRL_CPU0		0
#define	ENVCTRL_CPU1		1
#define	ENVCTRL_CPU2		2
#define	ENVCTRL_CPU3		3
#define	ENVCTRL_CPU4		4
#define	ENVCTRL_CPU5		5
#define	ENVCTRL_CPU6		6
#define	ENVCTRL_CPU7		7

/*
 * I2C Sensor Types
 */

#define	ENVCTRL_PCD8584		0x00	/* Bus Controller Master */
#define	ENVCTRL_PCF8591		0x01	/* Temp Sensor 8bit A/D, D/A */
#define	ENVCTRL_PCF8574		0x02	/* PS, FAN, LED, Fail and Control */
#define	ENVCTRL_TDA8444T	0x03	/* Fan Speed Control, 8 bit D/A */
#define	ENVCTRL_PCF8574A	0x04	/* 8574A chip */
#define	ENVCTRL_PCF8583		0x05	/* PCF8583 clock chip */
#define	ENVCTRL_LM75		0x06	/* LM75 chip */

/*
 * I2C device address offsets
 */
#define	ENVCTRL_DEV0		0x0
#define	ENVCTRL_DEV1		0x2
#define	ENVCTRL_DEV2		0x4
#define	ENVCTRL_DEV3		0x6
#define	ENVCTRL_DEV4		0x8
#define	ENVCTRL_DEV5		0xA
#define	ENVCTRL_DEV6		0xC
#define	ENVCTRL_DEV7		0xE

/*
 * I2C ports
 */
#define	ENVCTRL_PORT0		0x00
#define	ENVCTRL_PORT1		0x01
#define	ENVCTRL_PORT2		0x02
#define	ENVCTRL_PORT3		0x03
#define	ENVCTRL_PORT4		0x04
#define	ENVCTRL_PORT5		0x05
#define	ENVCTRL_PORT6		0x06
#define	ENVCTRL_PORT7		0x07

/*
 * Max number of a particular
 * device on one bus.
 */
#define	ENVCTRL_MAX_DEVS	0x10
#define	ENVCTRL_I2C_NODEV	0xFF
#define	ENVCTRL_INSTANCE_0	0x00

/* Disk Fault bit fields */
#define	ENVCTRL_DISK_0 0x01
#define	ENVCTRL_DISK_1 0x02
#define	ENVCTRL_DISK_2 0x04
#define	ENVCTRL_DISK_3 0x08
#define	ENVCTRL_DISK_4 0x10
#define	ENVCTRL_DISK_5 0x20
#define	ENVCTRL_DISK_6 0x40
#define	ENVCTRL_DISK_7 0x80

#define	ENVCTRL_4SLOT_BACKPLANE	0x0F
#define	ENVCTRL_8SLOT_BACKPLANE	0xFF

#define	ENVCTRL_DISK4LED_ALLOFF	0xF0
#define	ENVCTRL_DISK6LED_ALLOFF	0xFC
#define	ENVCTRL_DISK8LED_ALLOFF	0xFF

#define	ENVCTRL_MAXSTRLEN	256

/* Kstat Structures and defines */
#define	ENVCTRL_FAN_TYPE_CPU	0x00
#define	ENVCTRL_FAN_TYPE_PS	0x01
#define	ENVCTRL_FAN_TYPE_AFB	0x02
#define	ENVCTRL_FAN_TYPE_UE250	0x03

#define	ENVCTRL_MODULE_NAME		"envctrl"
#define	ENVCTRL_KSTAT_NUMPS		"envctrl_numps"
#define	ENVCTRL_KSTAT_PSNAME		"envctrl_pwrsupply"
#define	ENVCTRL_KSTAT_PSNAME2		"envctrl_pwrsupply2"
#define	ENVCTRL_KSTAT_NUMFANS		"envctrl_numfans"
#define	ENVCTRL_KSTAT_FANSTAT		"envctrl_fanstat"
#define	ENVCTRL_KSTAT_NUMENCLS		"envctrl_numencls"
#define	ENVCTRL_KSTAT_ENCL		"envctrl_enclosure"
#define	ENVCTRL_KSTAT_TEMPERATURE	"envctrl_temp"
#define	ENVCTRL_KSTAT_DISK		"envctrl_disk"

/*
 * Kstat structure definitions (PSARC 1996/159)
 */
typedef struct envctrl_ps {
	int instance;			/* instance of this type */
	ushort_t ps_tempr;		/* temperature */
	int ps_rating;			/* type in watts */
	boolean_t ps_ok;		/* normal state or not. */
	boolean_t curr_share_ok;	/* current share imbalance */
	boolean_t limit_ok;		/* overlimit warning */
} envctrl_ps_t;

typedef struct envctrl_fan {
	int instance;			/* instance of this type */
	int type;			/* CPU, PS or AMBIENT fan */
	boolean_t fans_ok;		/* are the fans okay */
	int fanflt_num;			/* if not okay, which fan faulted */
	uint_t fanspeed;			/* chip to set speed of fans */
} envctrl_fan_t;

typedef struct envctrl_encl {
	int instance;
	int type;
	uint_t value;
} envctrl_encl_t;

/*
 * Kstat structure defintions (PSARC 1997/245)
 */
typedef struct envctrl_chip {
	int type;			/* chip type */
	uchar_t chip_num;		/* chip num */
	uchar_t index;			/* chip index */
	uchar_t val;			/* chip reading */
} envctrl_chip_t;

typedef struct envctrl_ps2 {
	ushort_t ps_tempr;		/* temperature */
	int ps_rating;			/* type in watts */
	boolean_t ps_ok;		/* normal state or not */
	boolean_t curr_share_ok;	/* current share imbalance */
	boolean_t limit_ok;		/* overlimit warning */
	int type;			/* power supply type */
	int slot;			/* power supply slot occupied */
} envctrl_ps2_t;

typedef struct envctrl_temp {
	char label[ENVCTRL_MAXSTRLEN];	/* indicates temp. sensor location */
	int type;			/* Temperature sensor type */
	uint_t value;			/* temperature value */
	uint_t min;			/* minimum tolerable temperature */
	uint_t warning_threshold;	/* warning threshold */
	uint_t shutdown_threshold;	/* shutdown threshold */
} envctrl_temp_t;

typedef struct envctrl_disk {
	int slot;			/* slot number of disk */
	boolean_t disk_ok;		/* disk fault LED off or on */
} envctrl_disk_t;

#define	ENVCTRL_PANEL_LEDS_PR		"panel-leds-present"
#define	ENVCTRL_PANEL_LEDS_STA		"panel-leds-state"
#define	ENVCTRL_DISK_LEDS_PR		"disk-leds-present"
#define	ENVCTRL_DISK_LEDS_STA		"disk-leds-state"
#define	ENVCTRL_LED_BLINK		"activity-led-blink?"

/*
 * IOCTL defines (PSARC 1996/159)
 */
#define	ENVCTRL_IOC_RESETTMPR	(int)(_IOW('p', 76, uchar_t))
#define	ENVCTRL_IOC_SETMODE	(int)(_IOW('p', 77, uchar_t))
#define	ENVCTRL_IOC_SETTEMP	(int)(_IOW('p', 79, uchar_t))
#define	ENVCTRL_IOC_SETFAN (int)(_IOW('p', 80, struct envctrl_tda8444t_chip))
#define	ENVCTRL_IOC_SETWDT	(int)(_IOW('p', 81, uchar_t))
#define	ENVCTRL_IOC_GETFAN (int)(_IOR('p', 81, struct envctrl_tda8444t_chip))
#define	ENVCTRL_IOC_GETTEMP (int)(_IOR('p', 82, struct envctrl_pcf8591_chip))
#define	ENVCTRL_IOC_GETFANFAIL (int)(_IOR('p', 83, struct envctrl_pcf8574_chip))
#define	ENVCTRL_IOC_SETFSP	(int)(_IOW('p', 84, uchar_t))
#define	ENVCTRL_IOC_SETDSKLED (int)(_IOW('p', 85, struct envctrl_pcf8574_chip))
#define	ENVCTRL_IOC_GETDSKLED (int)(_IOR('p', 86, struct envctrl_pcf8574_chip))

/*
 * IOCTL defines (PSARC 1997/245)
 */
#define	ENVCTRL_IOC_GETMODE	(int)(_IOR('p', 87, uchar_t))
#define	ENVCTRL_IOC_SETTEMP2	(int)(_IOW('p', 88, struct envctrl_chip))
#define	ENVCTRL_IOC_SETFAN2 	(int)(_IOW('p', 89, struct envctrl_chip))
#define	ENVCTRL_IOC_GETFAN2 	(int)(_IOR('p', 90, struct envctrl_chip))
#define	ENVCTRL_IOC_GETTEMP2 	(int)(_IOR('p', 91, struct envctrl_chip))
#define	ENVCTRL_IOC_SETFSP2	(int)(_IOW('p', 92, struct envctrl_chip))
#define	ENVCTRL_IOC_GETFSP2	(int)(_IOR('p', 93, struct envctrl_chip))
#define	ENVCTRL_IOC_SETDSKLED2 	(int)(_IOW('p', 94, struct envctrl_chip))
#define	ENVCTRL_IOC_GETDSKLED2 	(int)(_IOR('p', 95, struct envctrl_chip))
#define	ENVCTRL_IOC_SETRAW 	(int)(_IOW('p', 96, struct envctrl_chip))
#define	ENVCTRL_IOC_GETRAW 	(int)(_IOR('p', 97, struct envctrl_chip))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ENVCTRL_GEN_H */
