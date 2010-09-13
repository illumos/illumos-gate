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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_ADAPTERS_TAVOR_AGENTS_H
#define	_SYS_IB_ADAPTERS_TAVOR_AGENTS_H

/*
 * tavor_agents.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for all of the Tavor Infiniband Management Agent (SMA, PMA, BMA)
 *    routines
 *    Specifically it contains the various flags, structures used for tracking
 *    the Tavor agents, and prototypes for initialization and teardown
 *    functions.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/ib/mgt/ibmf/ibmf.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The following defines specify the default number of (SW-assisted) agents
 * per port.  It is broken down by QP number.  QP0 will have only the one
 * agent, the SMA.  QP1 should have two agents, the PMA and BMA, but for now
 * the Tavor firmware doesn't support a BMA.  So we do not register it with
 * the IBMF.
 */
#define	TAVOR_NUM_QP0_AGENTS_PER_PORT		1
#define	TAVOR_NUM_QP1_AGENTS_PER_PORT		1

/* Number of threads for the agent handling task queue */
#define	TAVOR_TASKQ_NTHREADS			1

/* Maximum number of tasks on task queue */
#define	TAVOR_TASKQ_MAX_TASKS			4

/*
 * The following defines the name for the task queue.  Note: this string
 * will later be combined with the Tavor driver instance number to create
 * a unique name for the task queue
 */
#define	TAVOR_TASKQ_NAME			"tavor_taskq"

/*
 * The following macros are used when handling directed route MADs. They tell
 * the driver whether a given MAD is a directed route MAD, can extract the
 * "hop pointer" and "hop count" fields, and can even set the "direction" bit
 * in the MAD and (if necessary) update the "hop pointer".
 * More details on how these macros are used can be found in the
 * tavor_agents.c source file.
 */
#define	TAVOR_MAD_IS_DR(madhdrp)				\
	(((sm_dr_mad_hdr_t *)(madhdrp))->MgmtClass == 0x81)
#define	TAVOR_DRMAD_GET_HOPCOUNT(madhdrp)			\
	(((sm_dr_mad_hdr_t *)(madhdrp))->HopCount)
#define	TAVOR_DRMAD_GET_HOPPOINTER(madhdrp)			\
	(((sm_dr_mad_hdr_t *)(madhdrp))->HopPointer)
#define	TAVOR_DRMAD_SET_HOPPOINTER(madhdrp, hp)			\
	(((sm_dr_mad_hdr_t *)(madhdrp))->HopPointer = (hp))
#ifdef	_LITTLE_ENDIAN
#define	TAVOR_DRMAD_SET_DIRECTION(madhdrp)			\
	(((sm_dr_mad_hdr_t *)(madhdrp))->D_Status |= 0x0080)
#else
#define	TAVOR_DRMAD_SET_DIRECTION(madhdrp)			\
	(((sm_dr_mad_hdr_t *)(madhdrp))->D_Status |= 0x8000)
#endif

/*
 * The following macro is used to determine whether a received MAD is
 * one of the special "Tavor Trap" MADs.  If it is, then some special
 * processing (described in tavor_agents.c) is necessary.
 */
#define	TAVOR_IS_SPECIAL_TRAP_MAD(msgp)				\
	((((msgp)->im_msgbufs_recv.im_bufs_mad_hdr->R_Method &	\
	MAD_METHOD_MASK) == MAD_METHOD_TRAP) &&			\
	((msgp)->im_local_addr.ia_remote_lid == 0))

/*
 * The following macro is used to determine whether a received MAD is
 * a "TrapRepress" MAD.  If it is, then no response MAD should be sent
 * (described in tavor_agents.c).
 */
#define	TAVOR_IS_TRAP_REPRESS_MAD(msgp)				\
	((((msgp)->im_msgbufs_recv.im_bufs_mad_hdr->R_Method &	\
	MAD_METHOD_MASK) == MAD_METHOD_TRAP_REPRESS))

/*
 * The following define specified the offset for the start of "Return Path"
 * in a directed route MAD.  Note: this is the offset from the start of the
 * MAD data area (in bytes).
 */
#define	TAVOR_DRMAD_RETURN_PATH_OFFSET		0x80

/*
 * The tavor_agent_list_s structure is used in the Tavor IB Management Agent
 * routines to keep track of the number (and type) of each register agent.
 * The primary purpose of tracking this information (port number, management
 * class, and IBMF handle) is to be able to later deregister all the agents
 * which are registered at attach() time.  Note: a pointer to this structure
 * is returned to the driver (by the IBMF) every time the agent callback
 * routine is called.  This is why the structure contains a backpointer to
 * the Tavor softstate.
 */
struct tavor_agent_list_s {
	tavor_state_t		*agl_state;
	uint_t			agl_port;
	ibmf_client_type_t	agl_mgmtclass;
	ibmf_handle_t		agl_ibmfhdl;
};

/*
 * The tavor_agent_handler_arg_t structure is used in the Tavor IB Management
 * Agent routines to pass request information through the task queue.  Each
 * time a request is received (by the Tavor agent request callback), one
 * of these structures is allocated and filled with the relevant information
 * for the request.  It is then dispatched to the task queue (with a pointer
 * to the structure passed as an argument).  From there it is later pulled
 * apart and the individual fields of the structure used to handle the
 * request.
 */
typedef struct tavor_agent_handler_arg_s {
	ibmf_handle_t		ahd_ibmfhdl;
	ibmf_msg_t		*ahd_ibmfmsg;
	tavor_agent_list_t	*ahd_agentlist;
} tavor_agent_handler_arg_t;

int tavor_agent_handlers_init(tavor_state_t *state);
int tavor_agent_handlers_fini(tavor_state_t *state);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_AGENTS_H */
