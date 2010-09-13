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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_PCF8574_H
#define	_PCF8574_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PCF8574_NODE_TYPE  "adc_i2c:gpio"
#define	I2C_PCF8574_NAME "gpio"

#define	I2C_KSTAT_CPUVOLTAGE 	"gpio_cpuvoltage"
#define	I2C_KSTAT_PWRSUPPLY  	"gpio_pwrsupply"
#define	I2C_KSTAT_FANTRAY		"gpio_fantray"

/*
 * PCF8574 ioctls for fantray and powersupplies.
 */

#define	ENVC_IOC_GETTEMP	0x10
#define	ENVC_IOC_SETFAN 	0x11
#define	ENVC_IOC_GETFAN 	0x12
#define	ENVC_IOC_GETSTATUS	0x15
#define	ENVC_IOC_GETTYPE	0x16
#define	ENVC_IOC_GETFAULT	0x17
#define	ENVC_IOC_PSTEMPOK	0x18
#define	ENVC_IOC_PSFANOK	0x1A
#define	ENVC_IOC_PSONOFF	0x1B
#define	ENVC_IOC_SETSTATUS	0x1C

#define	ENVC_IOC_INTRMASK	0x1D

#define	ENVCTRL_INTRMASK_SET	1
#define	ENVCTRL_INTRMASK_CLEAR	0

#define	ENVCTRL_FANSPEED_LOW	0
#define	ENVCTRL_FANSPEED_HIGH	1

/*
 * Could not find a definition for CPU voltage monitoring in Javelin
 * Code. So writing a structure here.
 */

typedef struct envctrl_cpuvoltage {
	int value;
} envctrl_cpuvoltage_t;

/*
 * ps_present and fan_present fields modified for FRU callback and status
 * See sys/scsb_cbi.h and definitions in scsb.c
 */
typedef struct envctrl_pwrsupply {
	scsb_fru_status_t ps_present; /* Is powersupply present */
	boolean_t ps_ok;	/* Is powersupply ok */
	boolean_t temp_ok;	/* Is temperature ok */
	boolean_t psfan_ok;	/* Is fan ok */
	boolean_t on_state;	/* Powersupply on/off */
	int ps_ver;			/* Pwr supply version and type */
} envctrl_pwrsupp_t;

typedef struct envctrl_fantray {
	scsb_fru_status_t fan_present;	/* fan1 present */
	boolean_t fan_ok;	/* fan1 ok */
	boolean_t fanspeed;		/* to set speed, input */
	int fan_ver;		/* Fan version and type */
} envctrl_fantray_t;

#ifdef	_KERNEL

#ifndef	I2CDEV_TRAN
#define	I2CDEV_TRAN 1
#endif

#define	PCF8574_MAX_DEVS	0x08
#define	PCF8574_MAX_CHANS	0x01
#define	PCF8574_BUSY		0x01
#define	PCF8574_NAMELEN		12
#define	PCF8574_INTR_ON		0x1
#define	PCF8574_INTR_ENABLED	0x2

#define	PCF8574_MINOR_TO_DEVINST(x) (((x) & 0x700) >> 8)
#define	PCF8574_MINOR_TO_CHANNEL(x) ((x) & 0x3)

#define	PCF8574_CHANNEL_TO_MINOR(x) ((x) & 0x3)
#define	PCF8574_DEVINST_TO_MINOR(x) ((x) << 8)


#define	PCF8574_TRAN_SIZE 1
#ifndef	PCF8574
#define	PCF8574 0
#endif

#ifndef	PCF8574A
#define	PCF8574A 1
#endif

#define	PCF8574_SET	('A' << 8)
#define	PCF8574_GET	('B' << 8)

#define	NUM_OF_PCF8574_DEVICES	8
#define	PCF8574_MAXPORTS	8

#define	PCF8574_TYPE_CPUVOLTAGE 	0
#define	PCF8574_TYPE_FANTRAY		1
#define	PCF8574_TYPE_PWRSUPP		2

#define	PCF8574_ADR_CPUVOLTAGE 	0x70
#define	PCF8574_ADR_PWRSUPPLY1 	0x7C
#define	PCF8574_ADR_PWRSUPPLY2 	0x7E
#define	PCF8574_ADR_FANTRAY1	0x74
#define	PCF8574_ADR_FANTRAY2	0x76

/*
 * PCF8574 Fan Fail, Power Supply Fail Detector
 * This device is driven by interrupts. Each time it interrupts
 * you must look at the CSR to see which ports caused the interrupt
 * they are indicated by a 1.
 *
 * Address map of this chip
 *
 * -------------------------------------------
 * | 0 | 1 | 1 | 1 | A2 | A1 | A0 | 0 |
 * -------------------------------------------
 *
 */
#define	I2C_PCF8574_PORT0	0x01
#define	I2C_PCF8574_PORT1	0x02
#define	I2C_PCF8574_PORT2	0x04
#define	I2C_PCF8574_PORT3	0x08
#define	I2C_PCF8574_PORT4	0x10
#define	I2C_PCF8574_PORT5	0x20
#define	I2C_PCF8574_PORT6	0x40
#define	I2C_PCF8574_PORT7	0x80

#define	MAX_WLEN	64
#define	MAX_RLEN	64

/*
 * Following property information taken from the
 *   "SPARCengine ASM Reference Manual"
 * Property pointers are to DDI allocated space
 *  which must be freed in the detach() routine.
 */
/*
 * for pcf8574_properties_t.channels_in_use->io_dir
 */
#define	I2C_PROP_IODIR_IN	0
#define	I2C_PROP_IODIR_OUT	1
#define	I2C_PROP_IODIR_INOUT	2

/*
 * for pcf8574_properties_t.channels_in_use->type
 */
#define	I2C_PROP_TYPE_NOCARE	0
#define	I2C_PROP_TYPE_TEMP	1
#define	I2C_PROP_TYPE_VOLT	2
#define	I2C_PROP_TYPE_FANSTATS	3
#define	I2C_PROP_TYPE_FANSPEED	4

/*
 * These are now defined in sys/netract_gen.h
 *
 * #define	ENVC_IOC_GETMODE	0x1C
 * #define	ENVC_IOC_SETMODE	0x1D
 */


/*
 * Bit positions for the pcf8574 registers.
 */

#define	PCF8574_PS_TYPE(X) 		((X) & 0x3)
#define	PCF8574_PS_INTMASK(X) 	(((X) >> 2) & 0x1)
#define	PCF8574_PS_ONOFF(X)		(((X) >> 3)& 0x1)
#define	PCF8574_PS_FANOK(X)		(((X) >> 4) & 0x1)
#define	PCF8574_PS_TEMPOK(X)	(((X) >> 6) & 0x1)
#define	PCF8574_PS_FAULT(X)		(((X) >> 7) & 0x1)

#define	PCF8574_FAN_TYPE(X) 	((X) & 0x3)
#define	PCF8574_FAN_INTMASK(X)	(((X) >> 2) & 0x1)
#define	PCF8574_FAN_FANSPD(X)	(((X) >> 3) & 0x1)
#define	PCF8574_FAN_FAULT(X)	(((X) >> 7) & 0x1)

/* Constructs the reg byte from bit value */
#define	PCF8574_FAN_SPEED(bit)	((bit) << 3)
#define	PCF8574_INT_MASK(bit)	((bit) << 2)

/*
 * To tell the write_chip routine which bits to modify, a
 * 1 in the corresponding position selects that bit for
 * writing, a 0 ignores it.
 */
#define	PCF8574_FANSPEED_BIT	0x08
#define	PCF8574_INTRMASK_BIT	0x04

/*
 * Read and write masks for the fan and power supply.
 * These masks indicate which ports attached to the
 * PCF8574/A are input/output. We should construct the
 * read and writemasks from the channels-in-use property
 * for each pcf8574 device. In case the property is
 * absent, we can assign them with these default values.
 * While writing to the chip, we must or with the readmask,
 * else that port will be disabled.
 */

#define	PCF8574_FAN_WRITEMASK 0x0c
#define	PCF8574_FAN_READMASK  0xff
#define	PCF8574_PS_WRITEMASK  0x04
#define	PCF8574_PS_READMASK   0xff
#define	PCF8584_CPUVOLTAGE_WRITEMASK 0x88
#define	PCF8584_CPUVOLTAGE_READMASK  0x41

/*
 * Default values of the Fan and PS registers.
 * interrupt enabled.
 */
#define	PCF8574_FAN_DEFAULT 0xfb
#define	PCF8574_PS_DEFAULT  0xfb

#define	PCF8574_FAN_MASKINTR 0x04

#define	PCF8574_PS_MASKINTR	 0x04

#define	PCF8574_FAN_SPEED60  0x00
#define	PCF8574_FAN_SPEED100 0x80

#define	PCF8574_NUM_FANTRAY 2
#define	PCF8574_NUM_PWRSUPP 2

#define	PCF8574_FAN_SPEED_LOW  0
#define	PCF8574_FAN_SPEED_HIGH 1

/*
 * Stage of attachment.
 */
#define	PCF8574_SOFT_STATE_ALLOC	0x0001
#define	PCF8574_PROPS_READ		0x0002
#define	PCF8574_MINORS_CREATED		0x0004
#define	PCF8574_ALLOC_TRANSFER		0x0008
#define	PCF8574_REGISTER_CLIENT		0x0010
#define	PCF8574_LOCK_INIT		0x0020
#define	PCF8574_INTR_MUTEX		0x0040
#define	PCF8574_INTR_ADDED		0x0080
#define	PCF8574_KSTAT_INIT		0x0100

/*
 * PCF8574 ioctls for CPU Voltage (Nordica).
 */


typedef struct {
	uint8_t			port;
	uint8_t			io_dir;
	uint8_t			type;
	uint8_t			last_data;	/* N/A */
} pcf8574_channel_t;

typedef struct {
	char 			*name;
	uint16_t		i2c_bus;
	uint16_t		slave_address;
	uint_t			num_chans_used;
	char			**channels_description;
	pcf8574_channel_t	*channels_in_use;
} pcf8574_properties_t;

struct pcf8574_unit {
	kmutex_t		umutex;
	int				instance;
	dev_info_t		*dip;
	kcondvar_t		pcf8574_cv;
	i2c_transfer_t	*i2c_tran;
	i2c_client_hdl_t    pcf8574_hdl;
	char			pcf8574_name[PCF8574_NAMELEN];
	pcf8574_properties_t	props;
	uint8_t			pcf8574_flags;
	int				pcf8574_oflag;
	uint8_t			readmask;
	uint8_t			writemask;
	ddi_iblock_cookie_t	iblock;
	kmutex_t		intr_mutex;
	uint8_t			pcf8574_canintr;
	void 			*envctrl_kstat;
	uint8_t			current_mode;
	int				sensor_type;
	int				pcf8574_type;
	struct pollhead poll;
	int				poll_event;
	uint_t			attach_flag;
	kstat_t			*kstatp;
	int				i2c_status;
};

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _PCF8574_H */
