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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NEXUS_I2BSC_IMPL_H
#define	_NEXUS_I2BSC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/modctl.h>
#include <sys/promif.h>
#include <sys/lom_ebuscodes.h>
#include <sys/bscbus.h>

/*
 * When "#address-cells" is 1, it means we aren't multiplexing i2c busses.  We
 * therefore mark the bus number to I2BSC_DEFAULT_BUS.
 */
#define	I2BSC_DEFAULT_BUS		0

/*
 * Since i2c transfers are slow and take up lots of time, we limit our i2c
 * transfer size to an advertised limit, I2BSC_MAX_TRANSFER_SZ bytes.
 * The value was derived from an EEPROM page size of 32 bytes + 2 bytes to
 * denote the address offset within the EEPROM.
 */
#define	I2BSC_MAX_TRANSFER_SZ		34

/*
 * Address Space Accessors
 */
#define	I2BSC_NEXUS_ADDR(ssp, as, index) \
	(&((ssp)->bscbus_regs[((as) * 256) + (index)]))

/*
 * Re-try limit on Accessors was determined empircally.  During a firmware
 * download (the most heavy use of the comms channel), retries of up to 21
 * attempts have been seen.  The next power of 2 up is 32; the chosen retry
 * limit.
 */
#define	I2BSC_RETRY_LIMIT		32

/*
 * During attach processing we need to figure out if the firmware is broken
 * from the start.  If our re-try strategy is too aggressive we get poor
 * boot times.  Therefore, the initial broken firmware check done during attach
 * is given a relatively low retry threshold.
 */
#define	I2BSC_SHORT_RETRY_LIMIT		4


/*
 * strace(1M) prints out the debug data once the debug value is set in
 * the i2bsc.conf file and the debug driver is installed.
 *
 * Debug flags
 *
 * '@' - Register (@)ccess
 * 'A' - (A)ttach
 * 'D' - (D)ettach
 * 'S' - (S)ession
 * 'T' - I2C (T)ransfer
 * 'U' - (U)pload
 */

/*
 * Debug tips :
 *
 * strace(1M) prints out the debug data.
 * A nice way to work out the debug value set in i2bsc.conf is to use mdb
 * Say we want to show 'T' i2c transfer and 'U' upload processing,
 * you calculate the debug value with the following mdb session :
 *	# mdb
 *	> 1<<('T'-'@') | 1<<('U'-'@') = X
 *	                300000
 *
 *      > $q
 * When you explicitly set "debug=0x300000;" in i2bsc.conf, it causes the
 * debug driver to log Transfer and upload messages for strace(1M).
 */

typedef struct i2bsc {
	uint64_t		debug;		/* debugging turned on */
	short			majornum;	/* debugging - major number */
	short			minornum;	/* debugging - minor number */

	int			i2c_proxy_support;

	ddi_device_acc_attr_t	bscbus_attr;	/* bscbus attributes */
	ddi_acc_handle_t	bscbus_handle;	/* bscbus opaque handle */
	uint32_t		bscbus_fault;	/* 0 => okay		*/

	/*
	 * A session is a set of contigious gets/puts marked either as
	 * successful or failed.
	 */
	int			bscbus_session_failure;
	uint8_t			*bscbus_regs;	/* bscbus register space */

	dev_info_t		*i2bsc_dip;
	int			i2bsc_attachflags;
	kmutex_t		i2bsc_imutex;
	kcondvar_t		i2bsc_icv;
	int			i2bsc_open;
	int			i2bsc_busy;
	int			i2bsc_bus;
	i2c_transfer_t		*i2bsc_cur_tran;
	dev_info_t		*i2bsc_cur_dip;
	char			i2bsc_name[MODMAXNAMELEN];
} i2bsc_t;

/*
 * i2c_parent_pvt contains info that is chip specific
 * and is stored on the child's devinfo parent private data.
 */
typedef struct i2bsc_ppvt {
	int i2bsc_ppvt_bus; /* multiple I2C busses on a single set of */
			    /* registers.  this tells it what bus to */
			    /* use  */
	int i2bsc_ppvt_addr; /* address of I2C device */
} i2bsc_ppvt_t;

#define	I2BSC_INITIAL_SOFT_SPACE	1

/*
 * Attach flags
 */
#define	SETUP_REGS	0x01
#define	NEXUS_REGISTER	0x02
#define	IMUTEX		0x04
#define	MINOR_NODE	0x08
#define	FIRMWARE_ALIVE	0x10
#define	TRANSFER_SZ	0x20

#ifdef	__cplusplus
}
#endif

#endif /* _NEXUS_I2BSC_IMPL_H */
