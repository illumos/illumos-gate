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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_PCF8591_H
#define	_PCF8591_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PCF8591 Chip Used for temperature sensors
 *
 * Addressing Register definition.
 * A0-A2 valid range is 0-7
 *
 * ------------------------------------------------
 * | 1 | 0 | 0 | 1 | A2 | A1 | A0 | R/W |
 * ------------------------------------------------
 */

#define	PCF8591_MAX_DEVS	0x08
#define	PCF8591_MAX_CHANS	0x04
#define	PCF8591_BUSY		0x01
#define	PCF8591_NAMELEN		12

#define	PCF8591_MINOR_TO_DEVINST(x) (((x) & 0x700) >> 8)
#define	PCF8591_MINOR_TO_CHANNEL(x) ((x) & 0x3)

#define	PCF8591_CHANNEL_TO_MINOR(x) ((x) & 0x3)
#define	PCF8591_DEVINST_TO_MINOR(x) ((x) << 8)
#define	PCF8591_MINOR_NUM(i, c) (((i) << 8)|((c) & 0x3))

#define	PCF8591_NODE_TYPE "ddi_i2c:adc"

#define	PCF8591_TRAN_SIZE 1
#define	I2C_PCF8591_NAME "adc-dac"
#define	I2C_KSTAT_CPUTEMP "adc_temp"
#define	I2C_TYPE_PCF8591 0

#define	ENVC_NETRACT_CPU_SENSOR 0

#define	I2C_DEV0	0x00
#define	I2C_DEV1	0x02
#define	I2C_DEV2	0x04
#define	I2C_DEV3	0x06
#define	I2C_DEV4	0x08
#define	I2C_DEV5	0x0A
#define	I2C_DEV6    0x0C
#define	I2C_DEV7	0x0E

#define	MAX_WLEN	64
#define	MAX_RLEN	64

#ifndef	I2CDEV_TRAN
#define	I2CDEV_TRAN 1
#endif
#define	I2CDEV_GETTEMP		82
#define	I2CDEV_GETTABLES	256

#define	ENVC_IOC_GETTEMP	0x10
/*
 * These are now defined in sys/netract_gen.h
 *
 * #define	ENVC_IOC_GETMODE	0x1C
 * #define	ENVC_IOC_SETMODE	0x1D
 */

/*
 * 		CONTROL OF CHIP
 * PCF8591 Temp sensing control register definitions
 *
 * ---------------------------------------------
 * | 0 | AOE | X | X | 0 | AIF | X | X |
 * ---------------------------------------------
 * AOE = Analog out enable.. not used on out implementation
 * 5 & 4 = Analog Input Programming.. see data sheet for bits..
 *
 * AIF = Auto increment flag
 * bits 1 & 0 are for the Channel number.
 */

/*
 * We should be able to select the alalog input
 * programming of our choice. By default, the
 * alanog input programming is set to Single
 * ended. The programmer can issue an ioctl to
 * set the input programming mode. We will set
 * the auto increment flag set to off, so the lower
 * nibble in the control byte will be set to the
 * channel number.
 */

#define	PCF8591_4SINGLE		0x00	/* 4 single ended inputs */
#define	PCF8591_3DIFF		0x10	/* 3 differential inputs */
#define	PCF8591_MIXED		0x20	/* single ended and diff mixed */
#define	PCF8591_2DIFF		0x30	/* 2 differential inputs */

#define	PCF8591_WARNING_TEMP 0x0
#define	PCF8591_SHUTDOWN_TEMP 0x3

#define	PCF8591_ANALOG_OUTPUT_EN	0x40
#define	PCF8591_ANALOG_INPUT_EN		0x00
#define	PCF8591_READ_BIT			0x01


#define	PCF8591_AUTO_INCR 0x04
#define	PCF8591_OSCILATOR 0x40

#define	PCF8591_CH_0	0x00
#define	PCF8591_CH_1	0x01
#define	PCF8591_CH_2	0x02
#define	PCF8591_CH_3	0x03

/*
 * Stage of attachment.
 */
#define	PCF8591_SOFT_STATE_ALLOC 0x0001
#define	PCF8591_PROPS_READ		0x0002
#define	PCF8591_MINORS_CREATED	0x0004
#define	PCF8591_ALLOC_TRANSFER	0x0008
#define	PCF8591_REGISTER_CLIENT	0x0010
#define	PCF8591_LOCK_INIT		0x0020
#define	PCF8591_KSTAT_INIT		0x0040

#define	MAX_REGS_8591		2

struct	pcf8591	{
	unsigned int	reg_num;
	unsigned int	reg_value;
};

/*
 * Following property information taken from the
 * "SPARCengine ASM Reference Manual"
 * Property pointers are to DDI allocated space
 * which must be freed in the detach() routine.
 */

/*
 * for pcf8591_properties_t.channels_in_use->io_dir
 */
#define	I2C_PROP_IODIR_IN		0
#define	I2C_PROP_IODIR_OUT		1
#define	I2C_PROP_IODIR_INOUT	2

/*
 * for pcf8591_properties_t.channels_in_use->type
 */
#define	I2C_PROP_TYPE_NOCARE	0
#define	I2C_PROP_TYPE_TEMP		1
#define	I2C_PROP_TYPE_VOLT		2
#define	I2C_PROP_TYPE_FANSTATS	3
#define	I2C_PROP_TYPE_FANSPEED	4

typedef struct {
	uint8_t		port;
	uint8_t		io_dir;
	uint8_t		type;
	uint8_t		last_data;
} pcf8591_channel_t;

typedef struct {
	char		*name;
	uint16_t	i2c_bus;
	uint16_t	slave_address;
	uint_t		num_chans_used;
	char		**channels_description;
	pcf8591_channel_t		*channels_in_use;
} pcf8591_properties_t;

struct pcf8591_unit {
	int					instance;
	kmutex_t			umutex;
	dev_info_t			*dip;
	kcondvar_t			pcf8591_cv;
	uint8_t				pcf8591_flags;
	uint8_t				pcf8591_inprog;
	struct envctrl_temp temp_kstats;
	kstat_t 			*tempksp;
	uint_t				attach_flag;
	int				pcf8591_oflag[PCF8591_MAX_CHANS];
	i2c_transfer_t		*i2c_tran;
	i2c_client_hdl_t    pcf8591_hdl;
	char				pcf8591_name[PCF8591_NAMELEN];
	uint8_t				current_mode;
	uint8_t				readmask;
	pcf8591_properties_t props;		/* device properties */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _PCF8591_H */
