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

#ifndef _SYS_1394_TARGETS_AV1394_IMPL_H
#define	_SYS_1394_TARGETS_AV1394_IMPL_H

/*
 * av1394 driver definitions
 */

#include <sys/note.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/mkdev.h>
#include <sys/tnf_probe.h>
#include <sys/av/iec61883.h>
#include <sys/1394/t1394.h>
#include <sys/1394/targets/av1394/av1394_isoch.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * byte swapping support, stolen from SBP2
 */
#ifdef _LITTLE_ENDIAN
#define	AV_SWAP16(data) \
	((((data) & 0xff) << 8) | ((data) >> 8))

#define	AV_SWAP32(data) \
	(((uint32_t)AV_SWAP16((uint16_t)((data) & 0xffff)) << 16) |   \
	(uint32_t)AV_SWAP16((uint16_t)((data) >> 16)))
#else
#define	AV_SWAP16(data)	(data)
#define	AV_SWAP32(data)	(data)
#endif


/*
 * double-linked list
 */
typedef struct av1394_list_item_s {
	struct av1394_list_item_s	*i_next;
	struct av1394_list_item_s	*i_prev;
} av1394_list_item_t;

typedef struct av1394_list_s {
	av1394_list_item_t	*l_head;	/* first item */
	av1394_list_item_t	*l_tail;	/* last item */
	int			l_cnt;		/* number of items */
} av1394_list_t;


/*
 * queue
 */
typedef struct av1394_queue_s {
	kmutex_t	q_mutex;	/* mutex */
	av1394_list_t	q_list;		/* list of mblk's */
	int		q_size;		/* current data size */
	int		q_max;		/* max data size */
	kcondvar_t	q_cv;		/* data cv */
} av1394_queue_t;

_NOTE(MUTEX_PROTECTS_DATA(av1394_queue_s::q_mutex, av1394_queue_s))

#define	AV1394_ENTERQ(q)	mutex_enter(&(q)->q_mutex)
#define	AV1394_LEAVEQ(q)	mutex_exit(&(q)->q_mutex)


/*
 * asynchronous module definitions
 *
 *
 * command structure
 */
typedef struct av1394_fcp_cmd_s {
	cmd1394_cmd_t	*fc_cmd;	/* 1394 command */
	boolean_t	fc_busy;	/* command is in use */
	kcondvar_t	fc_busy_cv;	/* busy cv */
	boolean_t	fc_xmit;	/* transmit in progress */
	kcondvar_t	fc_xmit_cv;	/* transmit completion cv */
} av1394_fcp_cmd_t;

/*
 * per-instance FCP structure
 */
typedef struct av1394_fcp_s {
	av1394_fcp_cmd_t	fcp_cmd;	/* outgoing FCP command */
	av1394_fcp_cmd_t	fcp_resp;	/* outgoing FCP response */
} av1394_fcp_t;

enum {
	AV1394_FCP_ARQ_LEN_MAX	 = 0x200	/* maximum FCP ARQ length */
};


/*
 * configuration ROM
 */
#define	AV1394_CFGROM_INFO_LEN_ADDR	(IEEE1394_CONFIG_ROM_ADDR + 0x00)
#define	AV1394_CFGROM_BUS_NAME_ADDR	(IEEE1394_CONFIG_ROM_ADDR + 0x04)
#define	AV1394_CFGROM_EUI64_HI_ADDR	(IEEE1394_CONFIG_ROM_ADDR + 0x0c)
#define	AV1394_CFGROM_EUI64_LO_ADDR	(IEEE1394_CONFIG_ROM_ADDR + 0x10)

/* offsets in quadlets */
#define	AV1394_CFGROM_BUS_NAME_OFF	1
#define	AV1394_CFGROM_EUI64_HI_OFF	3
#define	AV1394_CFGROM_EUI64_LO_OFF	4

typedef struct av1394_cfgrom_text_leaf_s {
	uint64_t	tl_addr;	/* leaf entry address */
	uint32_t	tl_desc_entry;	/* entry described by this leaf */
} av1394_cfgrom_text_leaf_t;

typedef struct av1394_cfgrom_parsed_dir_s {
	av1394_cfgrom_text_leaf_t *pd_tl;	/* text leaf array */
	int			pd_tl_size;	/* total # of array entries */
	int			pd_tl_next;	/* first unused entry index */
} av1394_cfgrom_parsed_dir_t;

typedef struct av1394_cfgrom_parse_arg_s {
	int			pa_depth;	/* parser depth */
	uint32_t		pa_desc_entry;	/* described entry */
	uint8_t			pa_parent_k;	/* parent entry's key value */
	uint64_t		pa_addr;	/* directory address */
	uint16_t		pa_len;		/* directory length */
	av1394_cfgrom_parsed_dir_t *pa_dir;	/* current directory */
} av1394_cfgrom_parse_arg_t;

enum {
	AV1394_CFGROM_PARSE_MAX_DEPTH	= 5	/* maximum parse depth */
};

typedef struct av1394_cfgrom_s {
	krwlock_t		cr_rwlock;	/* structure lock */
	boolean_t		cr_parsed;	/* node ConfigROM was parsed */
	av1394_cfgrom_parsed_dir_t cr_root_dir;	/* root directory */
	av1394_cfgrom_parsed_dir_t cr_unit_dir;	/* unit directory */
} av1394_cfgrom_t;


/*
 * async command
 */
typedef struct av1394_async_cmd_s {
	kmutex_t	ac_mutex;
	boolean_t	ac_busy;
	kcondvar_t	ac_cv;
	cmd1394_cmd_t	*ac_cmd;
} av1394_async_cmd_t;

/*
 * per-instance soft state structure
 */
typedef struct av1394_async_s {
	kmutex_t		a_mutex;	/* structure mutex */
	int			a_nopen;	/* number of opens */
	int			a_oflag;	/* open flags */
	t1394_targetinfo_t	a_targetinfo;	/* target info */
	uint_t			a_bus_generation; /* bus generation */
	av1394_fcp_t		a_fcp;		/* FCP module */
	av1394_cfgrom_t		a_cfgrom;	/* config ROM module */
	av1394_queue_t		a_rq;		/* read queue */
	struct pollhead		a_pollhead;	/* poll(2) support */
	short			a_pollevents;	/* polled events */
} av1394_async_t;

_NOTE(MUTEX_PROTECTS_DATA(av1394_async_s::a_mutex, av1394_async_s))
_NOTE(DATA_READABLE_WITHOUT_LOCK(av1394_async_s::{
	a_oflag
}))


/* we use special message types for the read queue */
enum {
	AV1394_M_FCP_RESP	= 0x01,	/* FCP response */
	AV1394_M_FCP_CMD	= 0x02,	/* FCP command */
	AV1394_M_BUS_RESET	= 0x03,	/* bus reset event */
	/*
	 * For efficiency, we only store 1394 request data on the read queue.
	 * ARQ headers (iec61883_arq_t) are generated when an application
	 * calls read(2). Because applications may read header separately
	 * from the data, we need to mark each mblk when its header was read
	 * but not the data - the following flag is used for this purpose.
	 */
	AV1394_M_NOHDR		= 0x80
};

#define	AV1394_DBTYPE(bp)	(DB_TYPE(bp) & ~AV1394_M_NOHDR)
#define	AV1394_MARK_NOHDR(bp)	(DB_TYPE(bp) |= AV1394_M_NOHDR)
#define	AV1394_IS_NOHDR(bp)	(DB_TYPE(bp) & AV1394_M_NOHDR)


/*
 * device state:
 *
 *                     AV1394_DEV_DISCONNECTED
 *                     |                |   ^
 *                     |                |   |
 *                  detach       reconnect disconnect
 *                     |                |   |
 *                     v                v   |
 *       AV1394_DEV_INIT ----attach---> AV1394_DEV_ONLINE
 *      (initial state)  <---detach---  |   ^
 *                                      |   |
 *                             cpr suspend cpr resume
 *                                      |   |
 *                                      v   |
 *                        AV1394_DEV_SUSPENDED
 */
typedef enum {
	AV1394_DEV_INIT		= 0,
	AV1394_DEV_ONLINE,
	AV1394_DEV_SUSPENDED,
	AV1394_DEV_DISCONNECTED
} av1394_dev_state_t;

/*
 * per-instance soft state structure
 */
typedef struct av1394_inst_s {
	kmutex_t		av_mutex;	/* structure mutex */
	dev_info_t		*av_dip;	/* device information */
	int			av_instance;	/* instance number */
	av1394_dev_state_t	av_dev_state;	/* device state */
	av1394_dev_state_t	av_prev_dev_state; /* previous device state */
	t1394_attachinfo_t	av_attachinfo;	/* 1394 attach info */
	t1394_handle_t		av_t1394_hdl;	/* 1394 handle */
	av1394_async_t		av_a;		/* asynchronous module */
	av1394_isoch_t		av_i;		/* isochronous module */
	ddi_callback_id_t	av_reset_cb;	/* reset event cb id */
	ddi_callback_id_t	av_remove_cb; 	/* remove event cb id */
	ddi_callback_id_t	av_insert_cb;	/* insert event cb id */
} av1394_inst_t;

_NOTE(MUTEX_PROTECTS_DATA(av1394_inst_s::av_mutex, av1394_inst_s::{
	av_dip
	av_instance
	av_attachinfo
	av_t1394_hdl
}))
/* these are set during attach (single-threaded) and don't change afterwards */
_NOTE(DATA_READABLE_WITHOUT_LOCK(av1394_inst_s::{
	av_dip
	av_instance
	av_attachinfo
	av_t1394_hdl
}))

_NOTE(SCHEME_PROTECTS_DATA("one per call", msgb datab cmd1394_cmd
	iec61883_arq_t iec61883_isoch_init_t iec61883_plug_init_t))

/*
 * minor <-> instance mapping
 */
#define	AV1394_MINOR_TYPE_MASK		(1 << (NBITSMINOR32 - 1))
#define	AV1394_ISOCH_INST2MINOR(inst)	(inst)
#define	AV1394_ASYNC_INST2MINOR(inst)	((inst) | AV1394_MINOR_TYPE_MASK)
#define	AV1394_DEV_IS_ISOCH(dev)	\
		((getminor(dev) & AV1394_MINOR_TYPE_MASK) == 0)
#define	AV1394_DEV_IS_ASYNC(dev)	\
		((getminor(dev) & AV1394_MINOR_TYPE_MASK) != 0)
#define	AV1394_DEV2INST(dev)		\
		((getminor(dev)) & ~AV1394_MINOR_TYPE_MASK)

/* misc constants */
enum {
	AV1394_CLEANUP_LEVEL_MAX	= 256
};

/* current interface version */
#define	AV1394_IEC61883_VER		IEC61883_V1_0

/* TNF probes */
#define	AV1394_TNF_FCP			"1394 av1394 fcp "
#define	AV1394_TNF_FCP_STACK		"1394 av1394 fcp stacktrace "
#define	AV1394_TNF_FCP_ERROR		"1394 av1394 fcp error "
#define	AV1394_TNF_ASYNC		"1394 av1394 async "
#define	AV1394_TNF_ASYNC_STACK		"1394 av1394 async stacktrace "
#define	AV1394_TNF_ASYNC_ERROR		"1394 av1394 async error "
#define	AV1394_TNF_INST			"1394 av1394 inst "
#define	AV1394_TNF_INST_STACK		"1394 av1394 inst stacktrace "
#define	AV1394_TNF_INST_ERROR		"1394 av1394 inst error "

/* misc */
#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))


/* double-linked list */
void	av1394_list_init(av1394_list_t *lp);
void	*av1394_list_head(av1394_list_t *lp);
void	av1394_list_put_tail(av1394_list_t *lp, void *item);
void	av1394_list_put_head(av1394_list_t *lp, void *item);
void	*av1394_list_get_head(av1394_list_t *lp);

/* queue */
void	av1394_initq(av1394_queue_t *q, ddi_iblock_cookie_t ibc, int max);
void	av1394_destroyq(av1394_queue_t *q);
void	av1394_setmaxq(av1394_queue_t *q, int max);
int	av1394_getmaxq(av1394_queue_t *q);
void	av1394_flushq(av1394_queue_t *q);
int	av1394_putq(av1394_queue_t *q, mblk_t *bp);
int	av1394_putbq(av1394_queue_t *q, mblk_t *bp);
mblk_t	*av1394_getq(av1394_queue_t *q);
mblk_t	*av1394_peekq(av1394_queue_t *q);
mblk_t	*av1394_peekq_locked(av1394_queue_t *q);
int	av1394_qwait_sig(av1394_queue_t *q);

/* FCP */
int	av1394_fcp_attach(av1394_inst_t *);
void	av1394_fcp_detach(av1394_inst_t *);
int	av1394_fcp_open(av1394_inst_t *, int);
int	av1394_fcp_close(av1394_inst_t *, int);
int	av1394_fcp_write(av1394_inst_t *, iec61883_arq_t *, struct uio *);

/* config ROM */
int	av1394_cfgrom_init(av1394_inst_t *);
void	av1394_cfgrom_fini(av1394_inst_t *);
void	av1394_cfgrom_close(av1394_inst_t *);
int	av1394_ioctl_node_get_bus_name(av1394_inst_t *, void *, int);
int	av1394_ioctl_node_get_uid(av1394_inst_t *, void *, int);
int	av1394_ioctl_node_get_text_leaf(av1394_inst_t *, void *, int);

/* async module */
int	av1394_async_attach(av1394_inst_t *);
void	av1394_async_detach(av1394_inst_t *);
int	av1394_async_cpr_suspend(av1394_inst_t *);
int	av1394_async_cpr_resume(av1394_inst_t *);
void	av1394_async_bus_reset(av1394_inst_t *);
void	av1394_async_disconnect(av1394_inst_t *);
void	av1394_async_reconnect(av1394_inst_t *);
int	av1394_async_open(av1394_inst_t *, int);
int	av1394_async_close(av1394_inst_t *, int);
int	av1394_async_read(av1394_inst_t *, struct uio *);
int	av1394_async_write(av1394_inst_t *, struct uio *);
int	av1394_async_ioctl(av1394_inst_t *, int, intptr_t, int, int *);
int	av1394_async_poll(av1394_inst_t *, short, int, short *,
		struct pollhead **);
void	av1394_async_putq_rq(av1394_inst_t *, mblk_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_1394_TARGETS_AV1394_IMPL_H */
