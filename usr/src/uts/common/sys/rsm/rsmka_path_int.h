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

#ifndef	_SYS_RSM_RSMKA_PATH_INT_H
#define	_SYS_RSM_RSMKA_PATH_INT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/rsm/rsm_common.h>
#include <sys/rsm/rsm.h>
#include <sys/rsm/rsmpi.h>

/*
 * Taskq setup
 * Only one taskq thread is created and only one task is executed
 * the task is executed as an infinite loop
 */
#define	RSMKA_ONE_THREAD	1
#define	RSMKA_ONE_TASK		1

/* Path (path_t) States */
#define	RSMKA_PATH_DOWN	1
#define	RSMKA_PATH_UP	2
#define	RSMKA_PATH_ACTIVE	3
#define	RSMKA_PATH_GOING_DOWN	4

#define	RSMKA_OPCODE_TYPES	2

/*
 * Deferred Work Token Index
 */
#define	RSMKA_IPC_DOWN_INDEX	0
#define	RSMKA_IPC_UP_INDEX	1

/* Deferred Work Opcodes */
#define	RSMKA_IPC_DOWN	1
#define	RSMKA_IPC_UP	2

/* Flags */
#define	RSMKA_NO_SLEEP			1
#define	RSMKA_USE_COOKIE		2
#define	RSMKA_NOHOLD			4


/*
 * A work token is enqueued on the workqueue (singly linked list)
 * when pathup or pathdown processing is to be done by the deferred work
 * thread.  Token are enqueued at the end of the queue and processed
 * from the front of the queue.
 */
typedef struct work_token {
	struct work_token	*next;		/* pointer to next token */
	int			opcode;		/* opcode for work to do */
} work_token_t;

typedef struct workqueue {
	work_token_t	*head;		/* start of work queue		*/
	work_token_t	*tail;		/* end of work queue		*/
	kmutex_t	work_mutex;	/* protects queue add/delete    */
	kcondvar_t	work_cv;	/* synchronize deferred thread  */
} work_queue_t;

/*
 * a pointer to srv_handler_arg is registered along with the handler
 * and is passed to the rsm_srv_func - the service handler when it
 * is invoked.
 */
typedef struct srv_handler_arg {
	char		adapter_name[MAXNAMELEN];
	int		adapter_instance;
	rsm_addr_t	adapter_hwaddr;
} srv_handler_arg_t;

typedef struct msgbuf_elem {
	boolean_t		active;
	rsmipc_request_t	msg;
} msgbuf_elem_t;

/*
 * receive buffer object
 * procmsg_cnt - receivers count of messages processed since sending credits
 * msgbuf_queue - an array-based circular queue of messages received
 * msgbuf_head - index pointing to the head of msgbuf_queue
 * msgbuf_head - index pointing to the tail of msgbuf_queue
 * msgbuf_cnt - number of valid entries in msgbuf_queue
 */
typedef struct recv_info {
	int				procmsg_cnt;
	int				rem_sendq_ready;
	taskq_t				*recv_taskq;
	msgbuf_elem_t			*msgbuf_queue;
	int				msgbuf_head;
	int				msgbuf_tail;
	int				msgbuf_cnt;
} recv_info_t;

/*
 * sendq_tokens are inserted in a circular list of the ipc_info descriptor
 * when a path is added for a remote node.  When the path is active the
 * rsmpi_sendq_handle will be valid and the sendq token can be used for
 * ipc.  The sendq_tokens are used in a round robin fashion.
 *
 * msgbuf_avail - used by sender, number of avail slots in recvrs msgbuf_queue
 */
typedef struct sendq_token {
	struct sendq_token		*next;
	rsm_send_q_handle_t		rsmpi_sendq_handle;
	int				ref_cnt;
	int				msgbuf_avail;
	kcondvar_t			sendq_cv;
}sendq_token_t;




typedef struct path {
	struct path		*next_path;
	rsm_node_id_t		remote_node;
	int			remote_devinst;
	rsm_addr_t		remote_hwaddr;
	int			state;
	int			flags;
#define	RSMKA_WAIT_FOR_SQACK	0x0001	/* waiting for SQREADY_ACK	*/
#define	RSMKA_SQCREATE_PENDING	0x0002	/* sendq_create is pending	*/
	kmutex_t		mutex;
	struct adapter		*local_adapter;
	sendq_token_t		sendq_token;
	work_token_t		work_token[RSMKA_OPCODE_TYPES];
	recv_info_t		recv_buffer;
#define	procmsg_cnt	recv_buffer.procmsg_cnt
#define	rem_sendq_ready	recv_buffer.rem_sendq_ready
#define	msgbuf_queue	recv_buffer.msgbuf_queue
#define	msgbuf_head	recv_buffer.msgbuf_head
#define	msgbuf_tail	recv_buffer.msgbuf_tail
#define	msgbuf_cnt	recv_buffer.msgbuf_cnt
#define	recv_taskq	recv_buffer.recv_taskq
	int64_t			local_incn;
	int64_t			remote_incn;
#define	RSM_UNKNOWN_INCN	0
	int			ref_cnt;
	kcondvar_t 		hold_cv;
} path_t;


typedef struct adapter {
	struct adapter		*next;
	struct adapter_listhead *listhead;
	int			ref_cnt;
	kmutex_t		mutex;
	int			instance;
	dev_info_t		*dip;
	rsm_addr_t		hwaddr;
	path_t			*next_path;
	rsm_controller_handle_t rsmpi_handle;
	rsm_controller_attr_t	rsm_attr;
	rsm_ops_t		*rsmpi_ops;
	srv_handler_arg_t	*hdlr_argp;
} adapter_t;


/*
 * typedef struct {
 *	adapter_t		*next_chunk;
 *	int			base;
 *	int			next_index;
 *	int			used_count;
 *	adapter_t		*phys_adapters[MAX_CHUNK_INDEX];
 * } adapter_map_chunks_t;
 */


/*
 * There is one adapter_listhead for each adapter devname. This
 * adapter_listhead stores the number of adapters belonging to
 * it. It also stores the number of paths for all the adapters
 * belonging to it.
 */
typedef struct adapter_listhead {
	struct adapter_listhead	*next_listhead;
	char			adapter_devname[MAXNAMELEN];
	adapter_t		*next_adapter;
	int			ref_cnt;
	kmutex_t		mutex;
	int			adapter_count;
	int			path_count;
} adapter_listhead_t;


struct adapter_listhead_list {
	adapter_listhead_t	*next;
	kmutex_t		listlock;
};


/*
 * One ipc_info descriptor for each remote node
 */
typedef struct ipc_info {
	struct ipc_info			*next;
	rsm_node_id_t			remote_node;
	boolean_t			node_is_alive;
	sendq_token_t			*token_list;
	sendq_token_t			*current_token;
	kmutex_t			token_list_mutex;
	int				ref_cnt;
} ipc_info_t;


#define	SQ_TOKEN_TO_PATH(token) 	\
	((path_t *)((char *)(token) - ((char *)(&((path_t *)0)->sendq_token))))



#define	WORK_TOKEN_TO_PATH(token, index) \
	((path_t *)((char *)(token) - 	\
		((char *)(&((path_t *)0)->work_token[(index)]))))




/*
 * Descriptor Reference Count macros
 */

#define	ADAPTER_HOLD(adapter)	{	\
		mutex_enter(&((adapter)->mutex)); 	\
		(adapter)->ref_cnt++;		\
		ASSERT((adapter)->ref_cnt != 0);	\
		mutex_exit(&((adapter)->mutex));	\
}

#define	ADAPTER_RELE(adapter)	{			\
		mutex_enter(&((adapter)->mutex)); 	\
		(adapter)->ref_cnt--;			\
		ASSERT((adapter)->ref_cnt >= 0);	\
		mutex_exit(&((adapter)->mutex));	\
}

#define	ADAPTER_RELE_NOLOCK(adapter)	{		\
		ASSERT(MUTEX_HELD(&(adapter)->mutex));	\
		(adapter)->ref_cnt--;			\
		ASSERT((adapter)->ref_cnt >= 0);	\
}

#define	PATH_HOLD(path)	{			\
		mutex_enter(&(path)->mutex); 	\
		(path)->ref_cnt++;		\
		ASSERT((path)->ref_cnt != 0);	\
		mutex_exit(&(path)->mutex);	\
}

#define	PATH_HOLD_NOLOCK(path)	{			\
		ASSERT(MUTEX_HELD(&(path)->mutex));	\
		(path)->ref_cnt++;			\
		ASSERT((path)->ref_cnt != 0);		\
}

#define	PATH_RELE(path)	{				\
		mutex_enter(&(path)->mutex); 		\
		(path)->ref_cnt--;			\
		ASSERT((path)->ref_cnt >= 0);		\
		if ((path)->ref_cnt == 0)		\
			cv_signal(&(path)->hold_cv);	\
		mutex_exit(&(path)->mutex);		\
}

#define	PATH_RELE_NOLOCK(path)	{			\
		ASSERT(MUTEX_HELD(&(path)->mutex));	\
		(path)->ref_cnt--;			\
		ASSERT((path)->ref_cnt >= 0);		\
		if ((path)->ref_cnt == 0)		\
			cv_signal(&(path)->hold_cv);	\
}

#define	SENDQ_TOKEN_HOLD(path)	{				\
		(path)->sendq_token.ref_cnt++;			\
		ASSERT((path)->sendq_token.ref_cnt != 0);	\
}

#define	SENDQ_TOKEN_RELE(path)	{					\
		(path)->sendq_token.ref_cnt--;				\
		ASSERT((path)->sendq_token.ref_cnt >= 0);		\
		if ((path)->sendq_token.ref_cnt == 0)			\
			cv_signal(&(path)->sendq_token.sendq_cv);	\
}

#define	IPCINFO_HOLD(ipc_info)	{			\
		mutex_enter(&ipc_info_lock); 		\
		(ipc_info)->ref_cnt++;			\
		ASSERT((ipc_info)->ref_cnt != 0); 	\
		mutex_exit(&ipc_info_lock);		\
}

#define	IPCINFO_HOLD_NOLOCK(ipc_info)	{		\
		ASSERT(MUTEX_HELD(&ipc_info_lock));	\
		(ipc_info)->ref_cnt++;			\
		ASSERT((ipc_info)->ref_cnt != 0); 	\
}

#define	IPCINFO_RELE(ipc_info)	{			\
		mutex_enter(&ipc_info_lock); 		\
		(ipc_info)->ref_cnt--;			\
		ASSERT((ipc_info)->ref_cnt >= 0); 	\
		mutex_exit(&ipc_info_lock);		\
}

#define	IPCINFO_RELE_NOLOCK(ipc_info)	{		\
		ASSERT(MUTEX_HELD(&ipc_info_lock));	\
		(ipc_info)->ref_cnt--;			\
		ASSERT((ipc_info)->ref_cnt >= 0); 	\
}
/*
 * Topology data structures - The primary structure is struct rsm_topology_t
 * The key interconnect data required for segment operations includes the
 * cluster nodeids and the controllers (name, hardware address); with
 * the fundamental constraint that the controller specified for a segment
 * import must have a physical connection with the contorller used in the
 * export of the segment. To facilitate applications in the establishment
 * of proper and efficient export and import policies, a delineation of the
 * interconnect topology is provided by these data structures.
 *
 * A pointer to an instance of this structure type is returned by a call
 * to rsm_get_interconnect_topology(). The application is responsible for
 * calling rsm_free_interconnect_topology() to free the allocated memory.
 *
 * Note: the rsmka_connections_t structure should be always double-word
 *	aligned.
 */


#define	RSM_CONNECTION_ACTIVE	3


typedef struct {
	rsm_node_id_t		local_nodeid;
	int			local_cntlr_count;
} rsmka_topology_hdr_t;

typedef struct {
	char		cntlr_name[MAXNAMELEN];
	rsm_addr_t	local_hwaddr;
	int		remote_cntlr_count;
} rsmka_connections_hdr_t;


/*
 * An application must not attempt to use a connection unless the
 * the connection_state element of struct remote_cntlr_t is equal to
 * RSM_CONNECTION_ACTIVE
 */
typedef struct {
	rsm_node_id_t		remote_nodeid;
	char			remote_cntlrname[MAXNAMELEN];
	rsm_addr_t		remote_hwaddr;
	uint_t			connection_state;
} rsmka_remote_cntlr_t;


/*
 * The actual size of the remote_cntlr array is equal to the remote_cntlr_count
 * of the connections_hdr_t struct.
 */
typedef struct {
	rsmka_connections_hdr_t	hdr;
	rsmka_remote_cntlr_t	remote_cntlr[1];
} rsmka_connections_t;

/*
 * A pointer to an instance of this structure type is returned by a call
 * to rsm_get_interconnect_topology().  The actual size of the connections
 * array is equal to the local_cntlr_count of the topology_hdr_t struct.
 */
typedef struct {
	rsmka_topology_hdr_t	topology_hdr;
	caddr_t			connections[1];
} rsmka_topology_t;

#ifdef _SYSCALL32
typedef struct {
	rsmka_topology_hdr_t	topology_hdr;
	caddr32_t		connections[1];
} rsmka_topology32_t;
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RSM_RSMKA_PATH_INT_H */
