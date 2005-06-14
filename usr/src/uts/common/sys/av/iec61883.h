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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_AV_IEC61883_H
#define	_SYS_AV_IEC61883_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IEC 61883 interfaces
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* current interface version */
#define	IEC61883_IMPL_MKVER(major, minor) (((major) << 8) | (minor))
#define	IEC61883_IMPL_VER_MAJOR(ver)	(((ver) >> 8) & 0xff)
#define	IEC61883_IMPL_VER_MINOR(ver)	((ver) & 0xff)
#define	IEC61883_V1_0			IEC61883_IMPL_MKVER(1, 0)

/*
 * asyncronous request (ARQ)
 */
typedef struct iec61883_arq {
	int		arq_type;	/* type */
	int		arq_len;	/* length */
	union {
		uint32_t	quadlet;
		uint64_t	octlet;
		uint8_t		buf[8];
	} arq_data;			/* data */
} iec61883_arq_t;

/* ARQ types (arq_type) */
enum {
	IEC61883_ARQ_FCP_CMD,
	IEC61883_ARQ_FCP_RESP,
	IEC61883_ARQ_BUS_RESET
};

/*
 * IEC61883_ISOCH_INIT argument
 */
typedef struct iec61883_isoch_init {
	int		ii_version;	/* interface version */
	int		ii_pkt_size;	/* packet size */
	int		ii_frame_size;	/* packets/frame */
	int		ii_frame_cnt;	/* # of frames */
	int		ii_direction;	/* xfer direction */
	int		ii_bus_speed;	/* bus speed */
	uint64_t	ii_channel;	/* channel mask */
	int		ii_dbs;		/* DBS */
	int		ii_fn;		/* FN */
	int		ii_rate_n;	/* rate numerator */
	int		ii_rate_d;	/* rate denominator */
	int		ii_ts_mode;	/* timestamp mode */
	int		ii_flags;	/* flags */
	int		ii_handle;	/* isoch handle */
	int		ii_frame_rcnt;	/* # of frames */
	off_t		ii_mmap_off;	/* mmap offset */
	int		ii_rchannel;	/* channel */
	int		ii_error;	/* error code */
} iec61883_isoch_init_t;

/* xfer directions (ii_direction) */
enum {
	IEC61883_DIR_RECV,
	IEC61883_DIR_XMIT
};

/* bus speeds (ii_bus_speed) */
enum {
	IEC61883_S100,
	IEC61883_S200,
	IEC61883_S400
};

/* special rate coefficients (ii_rate_n, ii_rate_d) */
#define	IEC61883_RATE_N_DV_NTSC		1
#define	IEC61883_RATE_D_DV_NTSC		0
#define	IEC61883_RATE_N_DV_PAL		2
#define	IEC61883_RATE_D_DV_PAL		0

/* timestamp modes (ii_ts_mode) */
enum {
	IEC61883_TS_NONE	= 0,
	IEC61883_TS_SYT		= 0x0206
};

/* error codes (ii_error) */
enum {
	IEC61883_ERR_NOMEM	= 1,
	IEC61883_ERR_NOCHANNEL,
	IEC61883_ERR_PKT_SIZE,
	IEC61883_ERR_VERSION,
	IEC61883_ERR_INVAL,
	IEC61883_ERR_OTHER
};

/*
 * data transfer strusture
 */
typedef struct iec61883_xfer {
	int	xf_empty_idx;	/* first empty frame */
	int	xf_empty_cnt;	/* empty frame count */
	int	xf_full_idx;	/* first full frame */
	int	xf_full_cnt;	/* full frame count */
	int	xf_error;	/* error */
} iec61883_xfer_t;

/*
 * IEC61883_RECV argument
 */
typedef struct iec61883_recv {
	int		rx_handle;	/* isoch handle */
	int		rx_flags;	/* flags */
	iec61883_xfer_t	rx_xfer;	/* xfer params */
} iec61883_recv_t;

/*
 * IEC61883_XMIT argument
 */
typedef struct iec61883_xmit {
	int		tx_handle;	/* isoch handle */
	int		tx_flags;	/* flags */
	iec61883_xfer_t	tx_xfer;	/* xfer params */
	int		tx_miss_cnt;	/* missed cycles */
} iec61883_xmit_t;

/*
 * IEC61883_PLUG_INIT argument
 */
typedef struct iec61883_plug_init {
	int		pi_ver;		/* interface version */
	int		pi_loc;		/* plug location */
	int		pi_type;	/* plug type */
	int		pi_num;		/* plug number */
	int		pi_flags;	/* flags */
	int		pi_handle;	/* plug handle */
	int		pi_rnum;	/* plug number */
} iec61883_plug_init_t;

/* plug locations (pi_loc) */
enum {
	IEC61883_LOC_LOCAL,
	IEC61883_LOC_REMOTE
};

/* plug types (pi_type) */
enum {
	IEC61883_PLUG_IN,
	IEC61883_PLUG_OUT,
	IEC61883_PLUG_MASTER_IN,
	IEC61883_PLUG_MASTER_OUT
};

/* special plug number (pi_num) */
enum {
	IEC61883_PLUG_ANY	= -1
};

/*
 * IEC61883_PLUG_REG_READ argument
 */
typedef struct iec61883_plug_reg_val {
	int		pr_handle;	/* plug handle */
	uint32_t	pr_val;		/* register value */
} iec61883_plug_reg_val_t;

/*
 * IEC61883_PLUG_REG_CAS argument
 */
typedef struct iec61883_plug_reg_lock {
	int		pl_handle;	/* plug handle */
	uint32_t	pl_arg;		/* compare arg */
	uint32_t	pl_data;	/* write value */
	uint32_t	pl_old;		/* original value */
} iec61883_plug_reg_lock_t;

/*
 * IEC61883_NODE_GET_TEXT_LEAF argument
 */
typedef struct iec61883_node_text_leaf {
	int		tl_parent;	/* ROM parent */
	int		tl_num;		/* leaf number */
	int		tl_len;		/* buffer length */
	uint32_t	*tl_data;	/* data buffer */
	int		tl_cnt;		/* leaf count */
	int		tl_rlen;	/* real length */
	uint32_t	tl_spec;	/* specifier */
	uint32_t	tl_lang_id;	/* language id */
	uint32_t	tl_desc_entry;	/* entry described by this leaf */
} iec61883_node_text_leaf_t;

/* ROM parent types (tl_parent) */
enum {
	IEC61883_ROM_ROOT,	/* leaf in the root directory */
	IEC61883_ROM_UNIT	/* leaf in the unit directory */
};

/* ioctl codes */
#define	IEC61883_IMPL_IOC		('i' << 8)
#define	IEC61883_IMPL_MKIOC(c)		(c | IEC61883_IMPL_IOC)

#define	IEC61883_ISOCH_INIT		IEC61883_IMPL_MKIOC(0x01)
#define	IEC61883_ISOCH_FINI		IEC61883_IMPL_MKIOC(0x02)
#define	IEC61883_START			IEC61883_IMPL_MKIOC(0x03)
#define	IEC61883_STOP			IEC61883_IMPL_MKIOC(0x04)
#define	IEC61883_RECV			IEC61883_IMPL_MKIOC(0x05)
#define	IEC61883_XMIT			IEC61883_IMPL_MKIOC(0x06)
#define	IEC61883_PLUG_INIT		IEC61883_IMPL_MKIOC(0x07)
#define	IEC61883_PLUG_FINI		IEC61883_IMPL_MKIOC(0x08)
#define	IEC61883_PLUG_REG_READ		IEC61883_IMPL_MKIOC(0x09)
#define	IEC61883_PLUG_REG_CAS		IEC61883_IMPL_MKIOC(0x0A)
#define	IEC61883_ARQ_GET_IBUF_SIZE	IEC61883_IMPL_MKIOC(0x0B)
#define	IEC61883_ARQ_SET_IBUF_SIZE	IEC61883_IMPL_MKIOC(0x0C)
#define	IEC61883_NODE_GET_BUS_NAME	IEC61883_IMPL_MKIOC(0x0D)
#define	IEC61883_NODE_GET_UID		IEC61883_IMPL_MKIOC(0x0E)
#define	IEC61883_NODE_GET_TEXT_LEAF	IEC61883_IMPL_MKIOC(0x0F)


/* 32-bit structures for the drivers */
#ifdef _KERNEL
typedef struct iec61883_isoch_init32 {
	int		ii_version;	/* interface version */
	int		ii_pkt_size;	/* packet size */
	int		ii_frame_size;	/* packets/frame */
	int		ii_frame_cnt;	/* # of frames */
	int		ii_direction;	/* xfer direction */
	int		ii_bus_speed;	/* bus speed */
	uint64_t	ii_channel;	/* channel mask */
	int		ii_dbs;		/* DBS */
	int		ii_fn;		/* FN */
	int		ii_rate_n;	/* rate numerator */
	int		ii_rate_d;	/* rate denominator */
	int		ii_ts_mode;	/* timestamp mode */
	int		ii_flags;	/* flags */
	int		ii_handle;	/* isoch handle */
	int		ii_frame_rcnt;	/* # of frames */
	int32_t		ii_mmap_off;	/* mmap offset */
	int		ii_rchannel;	/* channel */
	int		ii_error;	/* error code */
} iec61883_isoch_init32_t;

typedef struct iec61883_node_text_leaf32 {
	int		tl_parent;	/* ROM parent */
	int		tl_num;		/* leaf number */
	int		tl_len;		/* buffer length */
	caddr32_t	tl_data;	/* data buffer */
	int		tl_cnt;		/* leaf count */
	int		tl_rlen;	/* real length */
	uint32_t	tl_spec;	/* specifier */
	uint32_t	tl_lang_id;	/* language id */
	uint32_t	tl_desc_entry;	/* entry described by this leaf */
} iec61883_node_text_leaf32_t;
#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AV_IEC61883_H */
