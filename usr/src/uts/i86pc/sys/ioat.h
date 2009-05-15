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

#ifndef _SYS_IOAT_H
#define	_SYS_IOAT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/dcopy.h>
#include <sys/dcopy_device.h>


/* ioat ioctls */
#define	IOATIOC			('T'<< 8)
typedef enum {
	IOAT_IOCTL_WRITE_REG	= (IOATIOC | 0x0),
	IOAT_IOCTL_READ_REG	= (IOATIOC | 0x1),
	IOAT_IOCTL_TEST		= (IOATIOC | 0x2)
} ioat_ioctl_enum_t;

typedef struct ioat_ioctl_reg_s {
	uint_t		size;
	uint_t		addr;
	uint64_t	data;
} ioat_ioctl_reg_t;
typedef ioat_ioctl_reg_t ioat_ioctl_wrreg_t;
typedef ioat_ioctl_reg_t ioat_ioctl_rdreg_t;

#ifdef _KERNEL
/* *** Driver Private Below *** */

/* IOAT_DMACAPABILITY flags */
#define	IOAT_DMACAP_PAGEBREAK	0x1
#define	IOAT_DMACAP_CRC		0x2
#define	IOAT_DMACAP_MARKERSKIP	0x4
#define	IOAT_DMACAP_XOR		0x8
#define	IOAT_DMACAP_DCA		0x10

/* IOAT_INTRCTL bits */
#define	IOAT_INTRCTL_MASTER_EN	0x1
#define	IOAT_INTRCTL_INTR_STAT	0x2

/* MMIO Registers */
#define	IOAT_CHANCNT		0x0	/* 8-bit */
#define	IOAT_XFERCAP		0x1	/* 8-bit */
#define	IOAT_GENCTRL		0x2	/* 8-bit */
#define	IOAT_INTRCTL		0x3	/* 8-bit */
#define	IOAT_ATTNSTATUS		0x4	/* 32-bit */
#define	IOAT_CBVER		0x8	/* 8-bit */
#define	IOAT_PERPORT_OFF	0xA	/* 16-bit */
#define	IOAT_INTRDELAY		0xC	/* 16-bit */
#define	IOAT_CSSTATUS		0xE	/* 16-bit */
#define	IOAT_DMACAPABILITY	0x10	/* 32-bit */

#define	IOAT_CHANNELREG_OFFSET	0x80

/* Channel Registers */
#define	IOAT_CHAN_CTL		0x0	/* 16-bit */
#define	IOAT_CHAN_COMP		0x2	/* 16-bit */
#define	IOAT_CHAN_CMPL_LO	0x18	/* 32-bit */
#define	IOAT_CHAN_CMPL_HI	0x1C	/* 32-bit */
#define	IOAT_CHAN_ERR		0x28	/* 32-bit */
#define	IOAT_CHAN_ERRMASK	0x2C	/* 32-bit */
#define	IOAT_CHAN_DCACTRL	0x30	/* 32-bit */

#define	IOAT_V1_CHAN_STS_LO	0x4	/* 32-bit */
#define	IOAT_V1_CHAN_STS_HI	0x8	/* 32-bit */
#define	IOAT_V1_CHAN_ADDR_LO	0x0C	/* 32-bit */
#define	IOAT_V1_CHAN_ADDR_HI	0x10	/* 32-bit */
#define	IOAT_V1_CHAN_CMD	0x14	/* 8-bit */

#define	IOAT_V2_CHAN_CMD	0x4	/* 8-bit */
#define	IOAT_V2_CHAN_CNT	0x6	/* 16-bit */
#define	IOAT_V2_CHAN_STS_LO	0x8	/* 32-bit */
#define	IOAT_V2_CHAN_STS_HI	0xC	/* 32-bit */
#define	IOAT_V2_CHAN_ADDR_LO	0x10	/* 32-bit */
#define	IOAT_V2_CHAN_ADDR_HI	0x14	/* 32-bit */

#define	IOAT_CHAN_STS_ADDR_MASK		0xFFFFFFFFFFFFFFC0
#define	IOAT_CHAN_STS_XFER_MASK		0x3F
#define	IOAT_CHAN_STS_FAIL_MASK		0x6
#define	IOAT_CMPL_INDEX(channel)	\
	(((*channel->ic_cmpl & IOAT_CHAN_STS_ADDR_MASK) - \
	ring->cr_phys_desc) >> 6)
#define	IOAT_CMPL_FAILED(channel)	\
	(*channel->ic_cmpl & IOAT_CHAN_STS_FAIL_MASK)


typedef struct ioat_chan_desc_s {
	uint32_t	dd_res0;
	uint32_t	dd_ctrl;
	uint64_t	dd_res1;
	uint64_t	dd_res2;
	uint64_t	dd_next_desc;
	uint64_t	dd_res4;
	uint64_t	dd_res5;
	uint64_t	dd_res6;
	uint64_t	dd_res7;
} ioat_chan_desc_t;

/* dca dd_ctrl bits */
#define	IOAT_DESC_CTRL_OP_CNTX	((uint32_t)0xFF << 24)
#define	IOAT_DESC_CTRL_CNTX_CHNG	0x1
typedef struct ioat_chan_dca_desc_s {
	uint32_t	dd_cntx;
	uint32_t	dd_ctrl;
	uint64_t	dd_res1;
	uint64_t	dd_res2;
	uint64_t	dd_next_desc;
	uint64_t	dd_res4;
	uint64_t	dd_res5;
	uint64_t	dd_res6;
	uint64_t	dd_res7;
} ioat_chan_dca_desc_t;

/* dma dd_ctrl bits */
#define	IOAT_DESC_CTRL_OP_DMA	(0x0 << 24)
#define	IOAT_DESC_DMACTRL_NULL	0x20
#define	IOAT_DESC_CTRL_FENCE	0x10
#define	IOAT_DESC_CTRL_CMPL	0x8
#define	IOAT_DESC_CTRL_NODSTSNP	0x4
#define	IOAT_DESC_CTRL_NOSRCSNP	0x2
#define	IOAT_DESC_CTRL_INTR	0x1
typedef struct ioat_chan_dma_desc_s {
	uint32_t	dd_size;
	uint32_t	dd_ctrl;
	uint64_t	dd_src_paddr;
	uint64_t	dd_dest_paddr;
	uint64_t	dd_next_desc;
	uint64_t	dd_next_src_paddr;	/* v2 only */
	uint64_t	dd_next_dest_paddr;	/* v2 only */
	uint64_t	dd_res6;
	uint64_t	dd_res7;
} ioat_chan_dma_desc_t;


typedef enum {
	IOAT_CBv1,
	IOAT_CBv2
} ioat_version_t;

/* ioat private data per command */
typedef struct ioat_cmd_private_s {
	uint64_t	ip_generation;
	uint64_t	ip_index;
	uint64_t	ip_start;
	dcopy_cmd_t	ip_next;
} ioat_cmd_private_t;

/* descriptor ring state */
typedef struct ioat_channel_ring_s {
	/* protects cr_cmpl_gen & cr_cmpl_last */
	kmutex_t		cr_cmpl_mutex;

	/* desc ring generation for the last completion we saw */
	uint64_t		cr_cmpl_gen;

	/* last descriptor index we saw complete */
	uint64_t		cr_cmpl_last;

	/* protects cr_desc_* */
	kmutex_t		cr_desc_mutex;

	/*
	 * last descriptor posted. used to update its next pointer when we
	 * add a new desc. Also used to tack the completion (See comment for
	 * cr_desc_gen_prev).
	 */
	uint64_t		cr_desc_prev;

	/* where to put the next descriptor */
	uint64_t		cr_desc_next;

	/* what the current desc ring generation is */
	uint64_t		cr_desc_gen;

	/*
	 * used during cmd_post to track the last desc posted. cr_desc_next
	 * and cr_desc_gen will be pointing to the next free desc after
	 * writing the descriptor to the ring. But we want to track the
	 * completion for the last descriptor posted.
	 */
	uint64_t		cr_desc_gen_prev;

	/* the last desc in the ring (for wrap) */
	uint64_t		cr_desc_last;

	/* pointer to the head of the ring */
	ioat_chan_desc_t	*cr_desc;

	/* physical address of the head of the ring */
	uint64_t		cr_phys_desc;

	/* back pointer to the channel state */
	struct ioat_channel_s	*cr_chan;

	/* for CB v2, number of desc posted (written to IOAT_V2_CHAN_CNT) */
	uint_t			cr_post_cnt;
} ioat_channel_ring_t;

/* track channel state so we can handle a failure */
typedef enum {
	IOAT_CHANNEL_OK = 0,
	IOAT_CHANNEL_IN_FAILURE = 1
} ic_channel_state_t;

typedef struct ioat_channel_s *ioat_channel_t;
struct ioat_channel_s {
	/* channel's ring state */
	ioat_channel_ring_t	*ic_ring;

	/* IOAT_CBv1 || IOAT_CBv2 */
	ioat_version_t		ic_ver;

	/*
	 * state to determine if it's OK to post the the channel and if all
	 * future polls should return failure.
	 */
	ic_channel_state_t	ic_channel_state;

	/* channel command cache (*_cmd_alloc, *_cmd_free, etc) */
	kmem_cache_t		*ic_cmd_cache;

	/* dcopy state for dcopy_device_channel_notify() call */
	dcopy_handle_t		ic_dcopy_handle;

	/* location in memory where completions are DMA'ed into */
	volatile uint64_t	*ic_cmpl;

	/* channel specific registers */
	uint8_t			*ic_regs;

	/* if this channel is using DCA */
	boolean_t		ic_dca_active;

	/* DCA ID the channel is currently pointing to */
	uint32_t		ic_dca_current;

	/* devices channel number */
	uint_t			ic_chan_num;

	/* number of descriptors in ring */
	uint_t			ic_chan_desc_cnt;

	/* descriptor ring alloc state */
	ddi_dma_handle_t	ic_desc_dma_handle;
	size_t			ic_desc_alloc_size;
	ddi_acc_handle_t	ic_desc_handle;
	ddi_dma_cookie_t	ic_desc_cookies;

	/* completion buffer alloc state */
	ddi_dma_handle_t	ic_cmpl_dma_handle;
	size_t			ic_cmpl_alloc_size;
	ddi_acc_handle_t	ic_cmpl_handle;
	ddi_dma_cookie_t	ic_cmpl_cookie;
	uint64_t		ic_phys_cmpl;

	/* if inuse, we need to re-init the channel during resume */
	boolean_t		ic_inuse;

	/* backpointer to driver state */
	struct ioat_state_s	*ic_state;
};

typedef struct ioat_rs_s *ioat_rs_hdl_t;

/* driver state */
typedef struct ioat_state_s {
	dev_info_t		*is_dip;
	int			is_instance;

	kmutex_t		is_mutex;

	/* register handle and pointer to registers */
	ddi_acc_handle_t	is_reg_handle;
	uint8_t			*is_genregs;

	/* IOAT_CBv1 || IOAT_CBv2 */
	ioat_version_t		is_ver;

	/* channel state */
	ioat_channel_t		is_channel;
	size_t			is_chansize;
	ioat_rs_hdl_t		is_channel_rs;

	ddi_iblock_cookie_t	is_iblock_cookie;

	/* device info */
	uint_t			is_chanoff;
	uint_t			is_num_channels;
	uint_t			is_maxxfer;
	uint_t			is_cbver;
	uint_t			is_intrdelay;
	uint_t			is_status;
	uint_t			is_capabilities;

	/* dcopy_device_register()/dcopy_device_unregister() state */
	dcopy_device_handle_t	is_device_handle;
	dcopy_device_info_t	is_deviceinfo;
} ioat_state_t;


int ioat_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred,
    int *rval);

void ioat_rs_init(ioat_state_t *state, uint_t min_val, uint_t max_val,
    ioat_rs_hdl_t *handle);
void ioat_rs_fini(ioat_rs_hdl_t *handle);
int ioat_rs_alloc(ioat_rs_hdl_t handle, uint_t *rs);
void ioat_rs_free(ioat_rs_hdl_t handle, uint_t rs);

int ioat_channel_init(ioat_state_t *state);
void ioat_channel_fini(ioat_state_t *state);
void ioat_channel_suspend(ioat_state_t *state);
int ioat_channel_resume(ioat_state_t *state);
void ioat_channel_quiesce(ioat_state_t *);

int ioat_channel_alloc(void *device_private, dcopy_handle_t handle, int flags,
    uint_t size, dcopy_query_channel_t *info, void *channel_private);
void ioat_channel_free(void *channel_private);
void ioat_channel_intr(ioat_channel_t channel);
int ioat_cmd_alloc(void *channel, int flags, dcopy_cmd_t *cmd);
void ioat_cmd_free(void *channel, dcopy_cmd_t *cmd);
int ioat_cmd_post(void *channel, dcopy_cmd_t cmd);
int ioat_cmd_poll(void *channel, dcopy_cmd_t cmd);
void ioat_unregister_complete(void *device_private, int status);


#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IOAT_H */
