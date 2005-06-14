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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBUS_H
#define	_SMBUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/promif.h>

/*
 * Attach flags
 */
#define	SETUP_REGS	0x01
#define	NEXUS_REGISTER	0x02
#define	IMUTEX		0x04
#define	ADD_INTR	0x08
#define	INTERRUPT_PRI	0x10

/*
 * Register offsets
 */
#define	SMB_STS		0x00
#define	SMB_TYP		0x01
#define	STR_PORT	0x02
#define	DEV_ADDR	0x03
#define	DEV_DATA0	0x04
#define	DEV_DATA1	0x05
#define	BLK_DATA	0x06
#define	SMB_CMD		0x07

/*
 * Bit values for SMB_STS (status) register
 */
#define	FAILED		0x80
#define	BUS_ERR		0x40
#define	DRV_ERR		0x20
#define	CMD_CMPL	0x10
#define	HOST_BSY	0x08
#define	IDLE		0x04
#define	INDEX		0x04
#define	TENBITS		0x02
#define	ALERT		0x01

/*
 * Bit values for the SMB_TYP (command type) register
 */
#define	DEV10B_EN	0x80
#define	QUICK_CMD	0x00
#define	SEND_BYTE	0x10
#define	RCV_BYTE	0x10
#define	WR_BYTE		0x20
#define	RD_BYTE		0x20
#define	WR_WORD		0x30
#define	RD_WORD		0x30
#define	WR_BLK		0x40
#define	RD_BLK		0x40
#define	PRC_CALL	0x50
#define	T_OUT		0x08
#define	KILL		0x04

#define	SMBUS_PIL	4

#define	MAX_BLK_SEND	32

/*
 * Used to or in bit 0 to be 1 for I2C read address.
 */
#define	I2C_READ	0x01

/*
 * The maximum number of times to retry in event of
 * a failure.
 */
#define	SMBUS_MAX_RETRIES	10

/*
 * If smbus_put() should make sure the buffer is flushed.
 */
#define	SMBUS_FLUSH 0x01

/*
 * The time in microseconds to wait before the timeout fires
 * to protect against an interrupt never arriving.
 */
#define	INTR_TIMEOUT 100000

/*
 * Time to wait in microseconds for any transaction before giving up
 * ie 10 seconds.
 */
#define	SMBUS_TRANS_TIMEOUT 10000000

/*
 * smbus event mode selection. select poll or interrupt mode
 */

#define	SMBUS_POLL_MODE		1	/* polling mode */
#define	SMBUS_POLL_TIMEOUT	50000
					/*
					 * how long to wait(us) for
					 * command completion.
					 */
#define	SMBUS_POLL_INTERVAL	1
					/*
					 * time (us) to wait between
					 * polls: must be small in comparison
					 * to the time an an i2c transaction
					 * takes.
					 */
/*
 * Scale polling retries so that the total timeout is "SMBUS_POLL_TIMEOUT"
 */
#define	SMBUS_POLL_MAX_RETRIES	(SMBUS_POLL_TIMEOUT/SMBUS_POLL_INTERVAL)


/*
 * smbus_ppvt_t contains info that is chip specific
 * and is stored on the child's devinfo parent private data.
 */
typedef struct smbus_ppvt {
	int	smbus_ppvt_addr; /* address of I2C device */
} smbus_ppvt_t;

typedef struct smbus {
	dev_info_t		*smbus_dip;
	int			smbus_attachflags;
	kmutex_t		smbus_mutex;
	kmutex_t		smbus_imutex;
	kcondvar_t		smbus_icv;
	kcondvar_t		smbus_cv;
	kcondvar_t		smbus_intr_cv;
	ddi_iblock_cookie_t	smbus_icookie;
	int			smbus_busy;
	int			smbus_wait;
	int			smbus_bus;
	i2c_transfer_t		*smbus_cur_tran;
	dev_info_t		*smbus_cur_dip;
	char			smbus_name[12];
	uint8_t			*smbus_regaddr;
	ddi_acc_handle_t	smbus_rhandle;
	uint8_t			*smbus_configregaddr;
	ddi_acc_handle_t	smbus_confighandle;
	timeout_id_t		smbus_timeout;
	int		smbus_saved_w_resid;
	int		smbus_retries;
	int		smbus_bytes_to_read;
	int		smbus_poll_complete;
							/*
							 * Boolean:true if
							 * polling is complete
							 */
	int		smbus_polling;
							/*
							 * Boolean: true if
							 * driver is polling
							 */
	int		smbus_poll_retries;
								/*
								 * How many
								 * times we
								 * have polled
								 * the status
								 * register. Not
								 * to be
								 * confused with
								 * "retries",
								 * which is how
								 * many times we
								 * tried after
								 * an error
								 */
} smbus_t;

#define	PRT_INIT	0x01
#define	PRT_WR		0x02
#define	PRT_RD		0x04
#define	PRT_PUT		0x08
#define	PRT_GET		0x10
#define	PRT_ATTACH	0x20
#define	PRT_INTR	0x40
#define	PRT_INTR_ERR	0x80
#define	PRT_TRANS	0x100
#define	PRT_SPEC	0x200
#define	PRT_BUFFONLY	0x1000
#define	PRT_PROM	0x2000

/*
 * smbus_switch return status
 */
#define	SMBUS_PENDING	0x01
#define	SMBUS_COMPLETE	0x02
#define	SMBUS_FAILURE	0x03

#define	SMBUS_SUCCESS	0x04

#define	SMBUS_SRC_STATUS	0x48
#define	SMBUS_SRC_ENA		0x44
#define	SMBUS_SMI		0x80000
#define	SMBUS_SMB_INTR_STATUS	0x80000

#define	SMBUS_INTR	"smbus_intr"
#define	SMBUS_TIMEOUT	"smbus_timeout"
#define	SMBUS_POLL	"smbus_poll"

#ifdef	DEBUG
#define	SMBUS_PRINT(a)	smbus_print a
#else
#define	SMBUS_PRINT(a)
#endif


/*
 * Other function delcarations
 */
int smbus_transfer(dev_info_t *, i2c_transfer_t *);
void smbus_print(int flags, const char *fmt, ...);

#ifdef	__cplusplus
}
#endif

#endif /* _SMBUS_H */
