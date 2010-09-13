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

#ifndef _MDMN_SUBR_H
#define	_MDMN_SUBR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <syslog.h>
#include <synch.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This is the structure for the wakeup table for the initiator's side.
 * We need a transportation handle in order to wake up the process waiting
 * for the rpc call to complete
 */
typedef struct mdmn_wti {
	md_mn_msgid_t	wti_id;
	mutex_t		wti_mx;
	time_t		wti_time;	/* for timeout purpose */
	SVCXPRT		*wti_transp;
	md_mn_result_t  *wti_result;
	char		*wti_args;
} mdmn_wti_t;

extern mdmn_wti_t initiator_table[MD_MAXSETS][MD_MN_NCLASSES];


/*
 * This is the structure for the wakeup table for the master.
 * We need the ID for checking purpose, synchronizing cv's and a place to store
 * a pointer to the results so the master can take over from here.
 */
typedef struct mdmn_wtm {
	md_mn_msgid_t	wtm_id;
	mutex_t		wtm_mx;
	cond_t		wtm_cv;
	md_mn_nodeid_t	wtm_addr;
	md_mn_result_t	*wtm_result;
} mdmn_wtm_t;

extern mdmn_wtm_t mdmn_master_table[MD_MAXSETS][MD_MN_NCLASSES];


/*
 * This structure is only needed because we start a thread and we want to
 * pass more than one argument to that thread.
 * So we pack all the args into one structure and pass a pointer to it.
 */
typedef struct md_mn_msg_and_transp {
	md_mn_msg_t	*mat_msg;
	SVCXPRT		*mat_transp;
} md_mn_msg_and_transp_t;

#define	MAX_SUBMESSAGES 8

#define	MAX_OUTERR	1024

/*
 * This is the message completion entry structure that stores the result
 * for one message incore in an array and on disk
 * Each entry is identified by the msgid being part of the result structure.
 * The actual data needs to be stored in a separate pre-allocated field
 * because the result structure only contains a pointer to stdout / stderr.
 * mce_flags is set to:
 *     MDMN_MCT_IN_PROGRESS - if a message is currently being handled and
 *		no new message handler should be issued.
 *    MDMN_MCT_DONE - if the message is completely processed and
 *		the result is available
 */
typedef struct md_mn_mce {
	md_mn_result_t  mce_result;
	char		mce_data[MAX_OUTERR];
	uint_t		mce_flags;
} md_mn_mce_t;

/*
 * We need to be able to store one result per each class and for each
 * possible submessage.
 * This makes our Message Completion Table mct for one diskset.
 */
typedef struct md_mn_mct {
	md_mn_mce_t mct_mce[NNODES][MD_MN_NCLASSES][MAX_SUBMESSAGES];
} md_mn_mct_t;

extern md_mn_mct_t *mct[];
extern int mdmn_mark_completion(md_mn_msg_t *msg, md_mn_result_t *result,
    uint_t flag);
extern int mdmn_check_completion(md_mn_msg_t *msg, md_mn_result_t *result);

/* here we find the MCT files on disk */
#define	MD_MN_MSG_COMP_TABLE	"/var/run/mct"

/* the return values for mdmn_mark_completion and mdmn_check_completion */
#define	MDMN_MCT_NOT_DONE	0x0001
#define	MDMN_MCT_DONE		0x0002
#define	MDMN_MCT_ERROR		0x0004
#define	MDMN_MCT_IN_PROGRESS	0x0008

/* the different states for md_mn_set_inited[] */
#define	MDMN_SET_MUTEXES	0x0001
#define	MDMN_SET_NODES		0x0002
#define	MDMN_SET_MCT		0x0004
#define	MDMN_SET_READY		(MDMN_SET_MUTEXES | MDMN_SET_NODES | \
				MDMN_SET_MCT)

/* the different states of mdmn_busy[set][class] */
#define	MDMN_BUSY		0x0001
#define	MDMN_LOCKED		0x0002
#define	MDMN_SUSPEND_1		0x0004
#define	MDMN_SUSPEND_ALL	0x0008


extern mutex_t mdmn_busy_mutex[];
extern cond_t mdmn_busy_cv[];
extern struct md_set_desc *set_descriptor[];


/* Stuff for licensing / checking ip adresses */
typedef struct licensed_ip {
	union {
		in_addr_t	u_lip_ipv4;	/* a licensed ipv4 adress */
		in6_addr_t	u_lip_ipv6;	/* a licensed ipv6 adress */
	} lip_u;
	sa_family_t	lip_family;	/* indicator for IPv4/IPv6 */
	int		lip_cnt;	/* it's reference count */
} licensed_ip_t;

#define	lip_ipv4 lip_u.u_lip_ipv4
#define	lip_ipv6 lip_u.u_lip_ipv6

extern licensed_ip_t licensed_nodes[];

extern bool_t	check_license(struct svc_req *rqstp, md_mn_nodeid_t chknid);
extern void	add_license(md_mnnode_desc *node);
extern void	rem_license(md_mnnode_desc *node);


/* needful things */

extern bool_t	mdmn_is_class_busy(set_t setno, md_mn_msgclass_t class);
extern bool_t	mdmn_mark_class_busy(set_t setno, md_mn_msgclass_t class);
extern void	mdmn_mark_class_unbusy(set_t setno, md_mn_msgclass_t class);

extern bool_t	mdmn_is_class_locked(set_t setno, md_mn_msgclass_t class);
extern void	mdmn_mark_class_locked(set_t setno, md_mn_msgclass_t class);
extern void	mdmn_mark_class_unlocked(set_t setno, md_mn_msgclass_t class);

extern bool_t	mdmn_is_class_suspended(set_t setno, md_mn_msgclass_t class);
extern int	mdmn_mark_class_suspended(set_t setno, md_mn_msgclass_t class,
		    uint_t susptype);
extern void	mdmn_mark_class_resumed(set_t setno, md_mn_msgclass_t class,
		    uint_t susptype);

extern void	commd_debug(uint_t debug_class, const char *message, ...);
extern void	dump_result(uint_t dbc, char *prefix, md_mn_result_t *res);



/* routines for handling the wakeup table for the master (master_table) */
extern void	mdmn_set_master_table_res(set_t setno, md_mn_msgclass_t class,
		    md_mn_result_t  *res);
extern void	mdmn_set_master_table_id(set_t setno, md_mn_msgclass_t class,
		    md_mn_msgid_t *id);
extern void	mdmn_get_master_table_id(set_t setno, md_mn_msgclass_t class,
		    md_mn_msgid_t *id);
extern cond_t	*mdmn_get_master_table_cv(set_t setno, md_mn_msgclass_t class);
extern mutex_t	*mdmn_get_master_table_mx(set_t setno, md_mn_msgclass_t class);
extern md_mn_result_t	*mdmn_get_master_table_res(set_t setno,
			    md_mn_msgclass_t class);
extern void	mdmn_set_master_table_addr(set_t setno, md_mn_msgclass_t class,
		    md_mn_nodeid_t nid);
extern md_mn_nodeid_t	mdmn_get_master_table_addr(set_t setno,
			    md_mn_msgclass_t class);


/* routines for handling the wakeup table for the initiator (initiator_table) */
extern void	mdmn_register_initiator_table(set_t setno,
		    md_mn_msgclass_t class, md_mn_msg_t *msg, SVCXPRT *transp);
extern void	mdmn_unregister_initiator_table(set_t setno,
		    md_mn_msgclass_t class);
extern int	mdmn_check_initiator_table(set_t setno, md_mn_msgclass_t class);
extern void	mdmn_get_initiator_table_id(set_t setno, md_mn_msgclass_t class,
		    md_mn_msgid_t *id);
extern SVCXPRT	*mdmn_get_initiator_table_transp(set_t setno,
		    md_mn_msgclass_t class);
extern char	*mdmn_get_initiator_table_args(set_t setno,
		    md_mn_msgclass_t class);
extern cond_t	*mdmn_get_initiator_table_cv(set_t setno,
		    md_mn_msgclass_t class);
extern mutex_t	*mdmn_get_initiator_table_mx(set_t setno,
		    md_mn_msgclass_t class);
extern time_t	mdmn_get_initiator_table_time(set_t setno,
		    md_mn_msgclass_t class);

/* the change log interface */
extern int	mdmn_log_msg(md_mn_msg_t *);
extern int	mdmn_flag_msg(md_mn_msg_t *, uint_t);
extern int	mdmn_unlog_msg(md_mn_msg_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MDMN_SUBR_H */
