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

#ifndef	_SYS_BPP_VAR_H
#define	_SYS_BPP_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Local variables header file for the bidirectional parallel port
 *	driver (bpp) for the Zebra SBus card.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*	#defines (not struct elements) below */

/* Other external ioctls are defined in bpp_io.h	*/
	/* FOR TEST - request fakeout simulate partial data transfer	*/
#define	BPPIOC_SETBC		_IOW('b', 7, uint_t)
	/* FOR TEST - request value of DMA_BCNT at end of last data transfer */
#define	BPPIOC_GETBC		_IOR('b', 8, uint_t)
	/* FOR TEST - get contents of device registers */
#define	BPPIOC_GETREGS		_IOR('b', 9, struct bpp_regs)
	/* FOR TEST - set special error code to simulate errors */
#define	BPPIOC_SETERRCODE	_IOW('b', 10, int)
	/* FOR TEST - get pointer to (fakely) "transferred" data */
#define	BPPIOC_GETFAKEBUF	_IOW('b', 11, uchar_t *)
	/* FOR TEST - test nested timeout  calls */
#define	BPPIOC_TESTTIMEOUT	_IO('b', 12)


/*	Structure definitions and locals #defines below */

struct bpp_unit				/* Unit structure - one per unit */
{
	kmutex_t	bpp_mutex;		/* mutex for any bpp op	*/
	kcondvar_t	wr_cv;			/* multiple read write lock */
	int		flags;			/* bpp flags		*/
	int		openflags;		/* read-write flags	*/
						/* this unit opened with */
	timeout_id_t	bpp_transfer_timeout_ident;
						/* returned from timeout() */
						/* passed to untimeout() */
	timeout_id_t	bpp_fakeout_timeout_ident;
						/* returned from timeout() */
						/* passed to untimeout() */
	uchar_t		timeouts;		/* encoded pending timeouts */
	int		sbus_clock_cycle;	/* SBus clock cycle time */
						/* for this unit	*/
	enum	trans_type {			/* saves state last transfer */
	read_trans, 				/* on this unit - needed for */
	write_trans 				/* scanners		*/
	}		last_trans;

	ddi_iblock_cookie_t	bpp_block_cookie;
						/* interrupt block cookie */
						/* from ddi_add_intr */
	ddi_dma_handle_t	bpp_dma_handle;
						/* DMA handle given by */
						/* ddi_dma_buf_setup() */
	long		transfer_remainder;	/* number of bytes which */
						/* were not transferred */
						/* since they were across */
						/* the max DVMA boundary. */
						/* value is (0) when transfer */
						/* is within the boundary */
	dev_info_t		*dip;		/* Opaque devinfo info. */
	struct buf *bpp_buffer;			/* save address of buf  */
						/* for bpp_intr */
	volatile struct bpp_regs 	*bpp_regs_p;
						/* Device control regs. */
	ddi_acc_handle_t	bpp_acc_handle;	/* registers access handle */
	struct bpp_transfer_parms transfer_parms;
						/* handshake and timing */
	struct bpp_pins		pins;		/* control pins 	*/
	struct bpp_error_status	error_stat;	/* snapshotted error cond */
	kstat_t		*intrstats;		/* interrupt statistics */
};

/* defines for the flags field */
#define	BPP_ISOPEN		0x01		/* open is complete	*/
#define	BPP_SUSPENDED		0x02		/* suspended		*/
#define	BPP_VERSATEC		0x04		/* versatec handshake	*/
#define	BPP_BUSY		0x08		/* busy			*/
#define	BPP_ISWAITING		0x10		/* waiting		*/

/* defines for the timeouts field */
#define	NO_TIMEOUTS		0x00		/* No timeouts pending	*/
#define	TRANSFER_TIMEOUT	0x01		/* DVMA transfer */
#define	FAKEOUT_TIMEOUT		0x10		/* Hardware simulation	*/
#define	TEST1_TIMEOUT		0x20		/* Test timeout #1	*/
#define	TEST2_TIMEOUT		0x40		/* Test timeout #2	*/


/* lint garbage */
#ifdef __lint

#define	IFLINT	IFTRUE

int _ZERO_;	/* "constant in conditional context" workaround */
#define	_ONE_	(!_ZERO_)

#else	/* __lint */

#define	IFLINT	IFFALSE

#define	_ZERO_	0
#define	_ONE_	1

#endif	/* __lint */

/* statement macro */
#define	_STMT(op)	do { op } while (_ZERO_)

#ifdef __cplusplus
}
#endif

#endif /* !_SYS_BPP_VAR_H */
