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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _I2O_BS_H
#define	_I2O_BS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	ROUNDUP(a, n)	(((a) + ((n) - 1)) & ~((n) - 1))
#define	UNIT(dev) (getminor((dev)) >> UNITSHF)
#define	BSA_SETMINOR(skt, part)	((skt << UNITSHF) | (part))

#if defined(_SUNOS_VTOC_16)
#define	UNITSHF	6
#define	MAXPART	(1 << UNITSHF)
#define	LPART(dev) (getminor((dev)) & (MAXPART - 1))
#elif defined(_SUNOS_VTOC_8)
#define	UNITSHF	3
#define	PART_MASK	7
#define	LPART(dev)	(getminor((dev)) & PART_MASK)
#else
#error No VTOC format defined.
#endif


#define	V_INVALID	0x80
#define	FDISK_OFFSET	MAX_SLICES
#if defined(_SUNOS_VTOC_16)
#define	MAX_SLICES	16
#define	VTOC_OFFSET	1
#elif defined(_SUNOS_VTOC_8)
#define	VTOC_OFFSET	0
#define	MAX_SLICES	8
#else
#error No VTOC format defined.
#endif
#define	USLICE_WHOLE	2
#define	FPART_WHOLE	0
#define	NUM_PARTS	(MAX_SLICES + FD_NUMPART + 1)

#define	REPLY_DONE	1	/* The reply is done */
#define	STATE_CHANGE	0x0001	/* STATE has changned */
#define	CLAIMED		0x0002	/* device is claimed */
#define	I2O_BSA_NAME	"i2o_bs"


#define	ISCD(p)	((p)->unitp.au_type == DKC_CDROM)
#define	ISREMOVABLE(p) \
	((p)->unitp.au_devicecapability &  I2O_BSA_DEV_CAP_REMOVABLE_MEDIA)

#define	ISWRITEPROTECT(p) \
	((p)->unitp.au_devicecapability & I2O_BSA_DEV_CAP_READ_ONLY)



typedef struct dsk_label {
	struct	dk_label	ondsklbl;
	struct	partition	pmap[NUM_PARTS];
	struct	dk_map		un_map[NDKMAP];	/* logical partitions */
	int	uidx;
	int	fdiskpresent;
	int	vtocread;
	int	geomread;
	kmutex_t		mutex;

} dsk_label_t;


struct	bsa_unit {
	int		au_cyl;
	int		au_acyl;
	int		au_hd;
	int		au_sec;
	long		au_blksize;
	short		au_bytes_per_block;
	int		au_type;
	uint64_t	au_capacity;
	long		au_devicecapability;
};

typedef struct bsa_data  {
	int 	flags;			/* misc state info		*/
	int 	tid;			/* local targer id ( From LCT)	*/
	int	instance;		/* instantiation of ourselves	*/
	int	open_flag;		/* open flag used for rem media */
	unsigned long	state;		/* State of removable media */
	struct	buf	*crashbuf;	/* used when dumping to root device */
	i2o_iop_handle_t	iop;	/* IOP access handle		*/
	dev_info_t		*dip;	/* pointer to our own device node */
	dsk_label_t		lbl;	/* per targer label information */
	struct bsa_unit		unitp;	/* phsyical characteristics */
	kcondvar_t		reply_cv;	/* conditional variable	    */
	kcondvar_t		rwreply_cv;	/* read/write cond variable */
	kcondvar_t		state_cv;	/* state cond variable */
	kmutex_t		bsa_mutex;	/* bs mutex		*/
} bsa_data_t;


typedef struct bsa_context  {
	struct bsa_data		*bsadata;
	int	deterror;		/* detail error */
	int	retval;			/* return value from reply */
	int	replyflag;		/* reply flag */
	int	rwreplyflag;		/* reply flag */
	ddi_dma_handle_t 	dma_handle; /* DMA Handle */
	ddi_acc_handle_t 	acc_handle; /* DMA Handle */
	ddi_dma_handle_t 	dma_sghandle; /* DMA Handle */
	ddi_acc_handle_t 	acc_sghandle; /* DMA Handle */
	ddi_dma_handle_t 	dma_sg2handle; /* DMA Handle */
	ddi_acc_handle_t 	acc_sg2handle; /* DMA Handle */
} bsa_context_t;

typedef struct i2o_common_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
} i2o_common_message_t;

typedef struct i2o_reassign_addr_message {
    uint32_t			ByteCount;
    uint64_t			LogicalByteAddress;
} i2o_reassign_addr_message_t;



#ifdef	__cplusplus
}
#endif

#endif /* _I2O_BS_H */
