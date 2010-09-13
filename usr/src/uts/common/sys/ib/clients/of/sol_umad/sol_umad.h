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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_IB_CLIENTS_OF_SOL_UMAD_SOL_UMAD_H
#define	_SYS_IB_CLIENTS_OF_SOL_UMAD_SOL_UMAD_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * map between minor node #s and HCA indexes and Port #s. This leaves
 * room for 16 boards with up to 16 ports each.
 */
#define	GET_UMAD_MINOR(node, port)   ((node << 4) | port)
#define	GET_ISSM_MINOR(node, port)   ((node << 4) | port | 0x8000)
#define	GET_NODE(minor) ((minor >> 4) & 0xf)
#define	GET_PORT(minor) ((minor) & 0xf)
#define	ISSM_MINOR(minor) (minor & 0x8000)
#define	GET_UCTX(minor) (minor >> 8)
#define	GET_NEW_UCTX_MINOR(minor, uctxnum) ((uctxnum << 8) | minor)

/* UMAD KA instance, only one instance allowed */
#define	UMAD_INSTANCE	0

#define	MAX_UCTX	16	/* Maximum number of contexts. */

typedef struct umad_port_info_s umad_port_info_t;

/*
 * User context. One per open file descriptor.
 */
typedef struct umad_uctx_s {
	kmutex_t		uctx_lock;	/* protects agent_list */
	umad_port_info_t	*uctx_port;
	struct pollhead		uctx_pollhead;
	llist_head_t		uctx_agent_list; /* list of agents registered */
	kmutex_t		uctx_recv_lock; /* protects recv_list below */
	genlist_t		uctx_recv_list; /* Queue of received MADs */
	kcondvar_t		uctx_recv_cv;	/* wait on for received data */
} umad_uctx_t;

typedef struct umad_agent_s {
	llist_head_t		agent_list;
	struct ib_user_mad_reg_req agent_req;	/* Params given during */
						/* registration */
	struct ibmf_reg_info	*agent_reg;	/* IBMF information */
	umad_uctx_t		*agent_uctx;	/* User context to which */
						/* this agent belongs. */
	int			agent_outstanding_msgs; /* # of msgs waiting */
							/* for a response */
	kmutex_t		agent_lock;	/* protects this structure */
	int			agent_flags;
	kcondvar_t		agent_cv;	/* used to wake up unregister */
} umad_agent_t;

enum umad_agent_flags {
	UMAD_AGENT_UNREGISTERING	= 1 << 0,
	UMAD_HANDLING_ASYNC		= 1 << 1
};

typedef struct umad_hca_info_s {
	ib_guid_t		hca_guid;
	ibt_hca_hdl_t		hca_handle;
	ibt_hca_attr_t		hca_attr;
	uint8_t			hca_nports;
	umad_port_info_t	*hca_ports;
} umad_hca_info_t;

struct umad_port_info_s {
	kmutex_t		port_lock;
	const umad_hca_info_t	*port_hca;	/* backpointer to hca */
	unsigned int		port_minor_name; /* number in device name. */
	uint8_t			port_num;
	ib_guid_t		port_guid;
	int			port_issm_open_cnt;
	ib_lid_t		port_lid;
	bool			port_has_umad_minor_node;
	bool			port_has_issm_minor_node;
	llist_head_t		port_ibmf_regs;
};

typedef struct umad_info_s {
	dev_info_t		*info_dip;	/* back pointer to devinfo */
	kmutex_t		info_mutex;	/* protects this device */
	ibt_clnt_hdl_t		info_clnt_hdl;
	uint32_t		info_hca_count;
	ib_guid_t		*info_hca_guids;
	umad_hca_info_t		*info_hcas;	/* hca list */
	umad_uctx_t		*info_uctx[MAX_UCTX];
} umad_info_t;


typedef struct ib_umad_msg_s {
	struct ib_user_mad_hdr	umad_msg_hdr;
	ibmf_msg_t		*umad_msg_ibmf_msg;
} ib_umad_msg_t;

/*
 * A UMAD we send is linked to a user context.
 */
struct umad_send {
	struct umad_agent_s	*send_agent;    /* agent that sent the MAD */
	size_t			send_len;
	uint8_t			send_umad[];    /* MAD from userspace */
};

struct ibmf_reg_info {
	ibmf_handle_t	ibmf_reg_handle;
	unsigned int	ibmf_reg_refcnt;
	umad_uctx_t	*ibmf_reg_uctx;
	kmutex_t	ibmf_reg_lock;
	kcondvar_t	ibmf_cv;
	unsigned int	ibmf_flags;
	enum _ibmf_client_type_t	ibmf_class;
};

/* Flags values for ibmf_flags above */
enum ibmf_flag_values {
	UMAD_IBMF_UNREGISTERING = 1 << 0
};

static inline int
is_supported_mad_method(int nr, void *addr)
{
	return (1 & (((uint32_t *)addr)[nr >> 5] >> (nr & 31)));
}

static int umad_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int umad_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int umad_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
			void **resultp);
static int umad_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
			int flags, char *name, caddr_t valuep,
			int *lengthp);
static int umad_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int umad_close(dev_t dev, int flag, int otyp, cred_t *cred);
static int umad_read(dev_t dev, struct uio *uiop, cred_t *credp);
static int umad_write(dev_t dev, struct uio *uiop, cred_t *credp);
static int umad_poll(dev_t dev, short events, int anyyet,
			short *reventsp, struct pollhead **phpp);
static int umad_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
			cred_t *credp, int *rvalp);

static void umad_async_handler(void *private, ibt_hca_hdl_t hca_hdl,
			ibt_async_code_t code,
			ibt_async_event_t *event);
static int umad_register(struct ib_user_mad_reg_req *req,
					umad_uctx_t *uctx);
static int umad_unregister(struct ib_user_mad_reg_req *agent,
					umad_uctx_t *uctx);
static void umad_unsolicited_cb(ibmf_handle_t ibmf_handle,
					ibmf_msg_t *msgp, void *args);
#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_CLIENTS_OF_SOL_UMAD_SOL_UMAD_H */
