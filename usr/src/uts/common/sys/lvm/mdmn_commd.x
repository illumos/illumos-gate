%/*
% * CDDL HEADER START
% *
% * The contents of this file are subject to the terms of the
% * Common Development and Distribution License (the "License").
% * You may not use this file except in compliance with the License.
% *
% * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
% * or http://www.opensolaris.org/os/licensing.
% * See the License for the specific language governing permissions
% * and limitations under the License.
% *
% * When distributing Covered Code, include this CDDL HEADER in each
% * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
% * If applicable, add the following below this CDDL HEADER, with the
% * fields enclosed by brackets "[]" replaced with your own identifying
% * information: Portions Copyright [yyyy] [name of copyright owner]
% *
% * CDDL HEADER END
% */
%
%/*
% * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
% * Use is subject to license terms.
% */
%

%#include <sys/types.h>
%#include <sys/types32.h>
%#include <sys/lvm/md_basic.h>
%#include <sys/lvm/mdio.h>
%#ifndef _KERNEL
%#include <mdiox.h>
%#include <meta_basic.h>
%extern  bool_t  xdr_md_set_params_t(XDR *xdrs, md_set_params_t *objp);
%extern  bool_t  xdr_mp_unit_t(XDR *xdrs, mp_unit_t *objp);
%extern  bool_t  xdr_diskaddr_t(XDR *xdrs, diskaddr_t *objp);
%extern  bool_t  xdr_md_dev64_t(XDR *xdrs, md_dev64_t *objp);
%extern  bool_t  xdr_daddr_t(XDR *xdrs, daddr_t *objp);
%extern  bool_t  xdr_daddr32_t(XDR *xdrs, daddr32_t *objp);
%#else
%#include <sys/lvm/md_mdiox.h>
%#endif /* ! _KERNEL */

/* every message handler must have these parameters */
%#define	HANDLER_PARMS md_mn_msg_t *msg, uint_t flag, md_mn_result_t *res


/* every submessage generator must have these parameters */
%#define	SMGEN_PARMS md_mn_msg_t *msg, md_mn_msg_t **msglist

/* when ever a new message type is added, an entry for it must be made in the master msg_table (defined in mdmn_commd_server.c*/

enum md_mn_msgtype_t {
        MD_MN_MSG_NULL = 0,  /* special message type for internal use only */
	MD_MN_MSG_TEST1,
	MD_MN_MSG_TEST2,
	MD_MN_MSG_TEST3,
	MD_MN_MSG_TEST4,
	MD_MN_MSG_TEST5,
	MD_MN_MSG_TEST6,
	MD_MN_MSG_BC_CMD,		/* Send metacommand */
	MD_MN_MSG_BC_CMD_RETRY,		/* Send metacommand, retry on busy */
	MD_MN_MSG_CLU_CHECK,
	MD_MN_MSG_CLU_LOCK,
	MD_MN_MSG_CLU_UNLOCK,
	MD_MN_MSG_REQUIRE_OWNER,	/* Request to become Mirror owner */
	MD_MN_MSG_CHOOSE_OWNER,		/* Request to allocate a resync owner */
	MD_MN_MSG_CHANGE_OWNER,		/* Change owner to a specific node */
	MD_MN_MSG_SUSPEND_WRITES,	/* Suspend writes to a mirror */
	MD_MN_MSG_STATE_UPDATE_RESWR,	/* Ch state of comp & resume writes */
	MD_MN_MSG_STATE_UPDATE,		/* Susp writes/Change state of comp */
	MD_MN_MSG_ALLOCATE_HOTSPARE,	/* Allocate hotspare for mirror comp */
	MD_MN_MSG_RESYNC_STARTING,	/* Resync thread starting */
	MD_MN_MSG_RESYNC_NEXT,		/* Next resync region */
	MD_MN_MSG_RESYNC_FINISH,	/* Resync thread finished */
	MD_MN_MSG_RESYNC_PHASE_DONE,	/* End of resync phase */
	MD_MN_MSG_SET_CAP,		/* Set capability, eg ABR */
	MD_MN_MSG_VERBOSITY,		/* set various levels of debug */
	MD_MN_MSG_MDDB_PARSE,		/* Slave to reparse portion of mddb */
	MD_MN_MSG_MDDB_BLOCK,		/* Block parse/recs on master/slave */
	MD_MN_MSG_META_DB_ATTACH,	/* Master message to add new mddb */
	MD_MN_MSG_SM_MDDB_ATTACH,	/* Submessage to add new mddb */
	MD_MN_MSG_META_DB_DETACH,	/* Master message to delete mddb */
	MD_MN_MSG_SM_MDDB_DETACH,	/* Submessage to delete mddb */
	MD_MN_MSG_META_DB_NEWSIDE,	/* Node adding mddb side info */
	MD_MN_MSG_META_DB_DELSIDE,	/* Node deleting mddb side info */
	MD_MN_MSG_META_MD_ADDSIDE,	/* Node adding md side info */
	MD_MN_MSG_META_MD_DELSIDE,	/* Node deleting md side info */
	MD_MN_MSG_MDDB_OPTRECERR,	/* Node detects opt rec error */
	MD_MN_MSG_ABORT,		/* Stop sending messages to any node */
	MD_MN_MSG_STATE_UPDATE_RESWR2,	/* UPDATE_RESWR for watermark updates */
	MD_MN_MSG_STATE_UPDATE2,	/* STATE_UPDATE for watermark updates */
	MD_MN_MSG_ALLOCATE_HOTSPARE2,	/* ALLOCATE_HOTSPARE for wm updates */
	MD_MN_MSG_IOCSET,		/* Send IOCSET ioctl */
	MD_MN_MSG_SP_SETSTAT,		/* Update status of softpart */
	MD_MN_MSG_ADDKEYNAME,		/* Add key */
	MD_MN_MSG_DELKEYNAME,		/* Delete key */
	MD_MN_MSG_GET_TSTATE,		/* Get tstate from master */
	MD_MN_MSG_GET_MIRROR_STATE,	/* Get submirror state from master */
	MD_MN_MSG_SP_SETSTAT2,		/* Update softpart status on error */
	MD_MN_MSG_SETSYNC,		/* Set resync status */
	MD_MN_MSG_POKE_HOTSPARES,	/* Call poke_hotspares */
	MD_MN_MSG_ADDMDNAME,		/* Add metadevice name */
	MD_MN_MSG_RR_DIRTY,		/* Mark RR range as dirty */
	MD_MN_MSG_RR_CLEAN,		/* Mark RR range as clean */
	MD_MN_NMESSAGES /* insert elements before */
};

/*
 * A message of class X may trigger only messages of classes higher than X
 * Feel free to change the order here. As long as you leave MD_MSG_CL_NULL 
 * and NCLASSES, of course 
 */

enum md_mn_msgclass_t {
	MD_MSG_CLASS0 = 0,  /* special message class for internal use only */
	MD_MSG_CLASS1,
	MD_MSG_CLASS2,
	MD_MSG_CLASS3,
	MD_MSG_CLASS4,
	MD_MSG_CLASS5,
	MD_MSG_CLASS6,
	MD_MSG_CLASS7,
	MD_MN_NCLASSES /* insert elements before */
};

%/*
% * The following are needed for things like suspend and resume when the
% * operation is to be applied to all classes / all sets.
% */
%#define	MD_COMM_ALL_CLASSES MD_MSG_CLASS0
%#define	MD_COMM_ALL_SETS 0

/* This is for state changes of submirror components */
struct md_mn_msg_stch_t {
        minor_t		msg_stch_mnum;		/* minor number of dev */
	int		msg_stch_sm;		/* submirror involved */
	int		msg_stch_comp;		/* component */
	int		msg_stch_new_state;	/* new state for comp */
	mddb_recid_t	msg_stch_hs_id;		/* hs_id at time of call */
};


/* This is for suspending writes to a mirror */
struct md_mn_msg_suspwr_t {
        minor_t         msg_suspwr_mnum;        /* minor number of dev */
};

/* Message format for choosing a resync owner */
struct md_mn_msg_chooseid_t {
	minor_t	msg_chooseid_mnum;	/* minor num of dev */
	int	msg_chooseid_rcnt;	/* resync count for set */
	int	msg_chooseid_set_node;	/* 1 => use rcnt as nodeid for owner */
};

/* Message format for changing a resync owner */
struct md_mn_msg_chowner_t {
	minor_t	msg_chowner_mnum;	/* minor num of dev */
	int	msg_chowner_nodeid;	/* node id of new owner */
};

/* Message format for setting metadevice capability */
struct md_mn_msg_setcap_t {
	char msg_setcap_driver[MD_DRIVERNAMELEN];	/* Driver name */
	minor_t	msg_setcap_mnum;	/* minor num of dev */
	u_int	msg_setcap_set;		/* new settings */
};

/* This is for setting the verbosity level (MD_MN_MSG_VERBOSITY) */
struct md_mn_verbose_t {
	set_t			mmv_setno;
	md_mn_msgclass_t	mmv_class;
	u_int			mmv_what;
};

/* What do we want to debug ? (mmv_what) */
%/* turn off everything */
%#define	MD_MMV_NULL 		0x00000000
%/* initialization of nodes / rpc clients */
%#define	MD_MMV_INIT		0x00000001
%/* mdmn_send_svc_1 related / early stage */
%#define	MD_MMV_SEND		0x00000002
%/* mdmn_work_svc_1 stuff on master */
%#define	MD_MMV_WORK		0x00000004
%/* mdmn_master_process_msg stuff */
%#define	MD_MMV_PROC_M		0x00000008
%/* mdmn_slave_process_msg stuff */
%#define	MD_MMV_PROC_S		0x00000010
%/* wakeup_master  */
%#define	MD_MMV_WAKE_M		0x00000020
%/* wakeup_initiator */
%#define	MD_MMV_WAKE_I		0x00000040
%/* Misc stuff*/
%#define	MD_MMV_MISC		0x00000080
%/* turn on everything */
%#define	MD_MMV_ALL		0x0000ffff	
%/* write to syslog instead of output file, for critical messages */
%#define	MD_MMV_SYSLOG		0x10000000	
%/* enable timestamps */
%#define	MD_MMV_TIMESTAMP	0x20000000


/* Message format for allocating hotspares */
struct md_mn_msg_allochsp_t {
	minor_t msg_allochsp_mnum;		/* minor num of dev */
	int msg_allochsp_sm;			/* submirror index */
	int msg_allochsp_comp;			/* component index */
	mddb_recid_t msg_allochsp_hs_id;	/* hotspare id */
};

/* Message format for resync messages */
struct md_mn_msg_resync_t {
	minor_t msg_resync_mnum;		/* minor num of dev */
	int msg_resync_type;			/* resync type */
	diskaddr_t msg_resync_start;		/* start of resync region */
	diskaddr_t msg_resync_rsize;		/* size of resync region */
	diskaddr_t msg_resync_done;		/* count of resync done */
	diskaddr_t msg_resync_2_do;		/* total size of resync */
	int msg_originator;			/* message originator */
	int	msg_resync_flags;		/* resync flags */
	sm_state_t	msg_sm_state[NMIRROR];	/* submirror state */
	sm_flags_t	msg_sm_flags[NMIRROR];	/* submirror flags */
};

%#define	MD_MSGF_DEFAULT_FLAGS		0x00000000

/* Message format for blocking/unblocking MDDB parsing and record changes  */
struct md_mn_msg_mddb_block_t {
	int	msg_block_flags;
};

/* Message format for MDDB re-parsing */
struct md_mn_msg_mddb_parse_t {
	int	msg_parse_flags;	/* flags describe part to reparse */
	int	msg_lb_flags[50];
};

/* Message format for MDDB attach */
struct md_mn_msg_meta_db_attach_t {
	md_dev64_t	msg_l_dev;
	int		msg_cnt;
	int		msg_dbsize;
	char		msg_dname[16];
	md_splitname	msg_splitname;
	u_int		msg_options;
	char		msg_devid[1];	/* unused for now, for future */
					/* must be last element */
};

/* Message format for MDDB detach */
struct md_mn_msg_meta_db_detach_t {
	md_splitname	msg_splitname;
	char		msg_devid[1];	/* unused for now, for future */
					/* must be last element */
};

/* Message format for MDDB newside */
struct md_mn_msg_meta_db_newside_t {
	md_dev64_t	msg_l_dev;
	daddr_t		msg_blkno;
	side_t		msg_sideno;
	minor_t		msg_mnum;
	char		msg_dname[16];
	md_splitname	msg_splitname;
	char		msg_devid[1];	/* unused for now, for future */
					/* must be last element */
};

/* Message format for MDDB delside */
struct md_mn_msg_meta_db_delside_t {
	md_dev64_t	msg_l_dev;
	daddr_t		msg_blkno;
	side_t		msg_sideno;
	char		msg_devid[1];	/* unused for now, for future */
					/* must be last element */
};

/* Message format for MD addside */
struct md_mn_msg_meta_md_addside_t {
	side_t		msg_sideno;
	side_t		msg_otherside;
};

/* Message format for MDDB delside */
struct md_mn_msg_meta_md_delside_t {
	side_t		msg_sideno;
};

/* Message format for optimized record error */
struct md_mn_msg_mddb_optrecerr_t {
	md_replica_recerr_t	msg_recerr[2];
};

/*
 * Message format for IOCSET message
 */

struct md_mn_msg_iocset_t {
	md_set_params_t	iocset_params;
	mp_unit_t		unit;
};

/* Message format for SP_SETSTAT message */

struct md_mn_msg_sp_setstat_t {
	minor_t		sp_setstat_mnum;
	int		sp_setstat_status;
};

/* Message format for ADDKEYNAME message */

struct md_mn_msg_addkeyname_t {
	set_t		addkeyname_setno;
	char		addkeyname_name[1];	/* must be last element */
};

/*
 * Add metadevice name into replica
 */
struct md_mn_msg_addmdname_t {
	set_t		addmdname_setno;
	char		addmdname_name[1];
};

/* Message format for DELKEYNAME message */

struct md_mn_msg_delkeyname_t {
	md_dev64_t	delkeyname_dev;
	set_t		delkeyname_setno;
	mdkey_t		delkeyname_key;
};

/* Message format for GET_TSTATE message */

struct md_mn_msg_gettstate_t {
	md_dev64_t	gettstate_dev;
};

/* Message format for GET_MIRROR_STATE message */

struct md_mn_msg_mir_state_t {
	minor_t		mir_state_mnum;
};

/* Results format for GET_SM_STATE message */
struct md_mn_msg_mir_state_res_t {
	sm_state_t	sm_state[NMIRROR];
	sm_flags_t	sm_flags[NMIRROR];
	u_int		mir_tstate;
};

/* Message format for MD_MN_MSG_SETSYNC message */
struct md_mn_msg_setsync_t {
	minor_t		setsync_mnum;
	md_riflags_t	setsync_flags;
	diskaddr_t	setsync_copysize;
};

/* Message format for MD_MN_MSG_POKE_HOTSPARES message */
struct md_mn_msg_pokehsp_t {
	minor_t		pokehsp_setno;
};

/* Message format for MD_MN_MSG_RR_DIRTY message */
struct md_mn_msg_rr_dirty_t {
	minor_t		rr_mnum;
	int		rr_nodeid;
	u_int		rr_range;	/* Start(16bits) | End(16bits) */
};

/* Message format for MD_MN_MSG_RR_CLEAN message */
%#define	MDMN_MSG_RR_CLEAN_DATA_MAX_BYTES	\
%		    ((MDMN_MAX_KMSG_DATA) - \
%		    sizeof (struct md_mn_msg_rr_clean_t))
%#define	MDMN_MSG_RR_CLEAN_SIZE_DATA(x)		\
%		    (sizeof (struct md_mn_msg_rr_clean_t) + (x))
%#define	MDMN_MSG_RR_CLEAN_MSG_SIZE(x)		\
%		    (sizeof (struct md_mn_msg_rr_clean_t) \
%		    + MDMN_MSG_RR_CLEAN_DATA_BYTES(x))
%#define	MDMN_MSG_RR_CLEAN_DATA(x)		\
%		    ((unsigned char *)(x) + \
%		    sizeof (struct md_mn_msg_rr_clean_t))

/* since we cannot use ushorts, some macros to extract the parts from an int */
%#define	MDMN_MSG_RR_CLEAN_START_BIT(x)	((x)->rr_start_size >> 16)
%#define	MDMN_MSG_RR_CLEAN_DATA_BYTES(x)	((x)->rr_start_size & 0xffff)
%#define	MDMN_MSG_RR_CLEAN_START_SIZE_SET(x, start, size) \
%			((x)->rr_start_size = (start << 16) | size)

struct md_mn_msg_rr_clean_t {
	md_mn_nodeid_t	rr_nodeid;
	unsigned int	rr_mnum;
	unsigned int	rr_start_size;	/* start_bit (16b) | data_bytes (16b) */
	/* actual data goes here */
};

%#define	MD_MSGF_NO_LOG			0x00000001
%#define	MD_MSGF_NO_BCAST		0x00000002
%#define	MD_MSGF_STOP_ON_ERROR		0x00000004
%#define	MD_MSGF_REPLAY_MSG		0x00000008
%#define	MD_MSGF_OVERRIDE_SUSPEND	0x00000010
%#define	MD_MSGF_ON_MASTER		0x00000020
%#define	MD_MSGF_ON_SLAVE		0x00000040
%#define	MD_MSGF_ON_INITIATOR		0x00000080
%#define	MD_MSGF_LOCAL_ONLY		0x00000100
%#define	MD_MSGF_FAIL_ON_SUSPEND		0x00000200
%#define	MD_MSGF_NO_MCT			0x00000400
%#define	MD_MSGF_PANIC_WHEN_INCONSISTENT	0x00000800
%#define	MD_MSGF_BLK_SIGNAL		0x00001000
%#define	MD_MSGF_KSEND_NORETRY		0x00002000
%#define	MD_MSGF_DIRECTED		0x00004000
%#define	MD_MSGF_VERBOSE			0x10000000
%#define	MD_MSGF_VERBOSE_2		0x20000000

%#define	MD_MSGF_INHERIT_BITS		\
%			MD_MSGF_REPLAY_MSG | MD_MSGF_OVERRIDE_SUSPEND



%/* maximum number of nodes in cluster (not in diskset) */
%#define	NNODES MD_MNMAXSIDES
 

/* if you add elements here, make sure, to add them to MSGID_COPY(), too */
struct md_mn_msgid_t {
	uint64_t	mid_time;	/* unique timestamp */
	md_mn_nodeid_t	mid_nid;	/* node that created the message */
	md_mn_msgclass_t mid_oclass;	/* for submessages original class */
	uint8_t		mid_smid;	/* sub message number */
	uint8_t		mid_spare[15];	/* Always good to have some spares */
};

%#define MD_NULL_MSGID (md_mn_msgid_t *)NULL
%
%/* macros to handle msgid's */
%#define	MSGID_COPY(from, to) {				\
%			(to)->mid_nid = (from)->mid_nid;	\
%			(to)->mid_smid = (from)->mid_smid;	\
%			(to)->mid_oclass = (from)->mid_oclass;	\
%			(to)->mid_time = (from)->mid_time;	\
%		}
%
%#define	MSGID_CMP(a, b) 				\
%			(((a)->mid_nid == (b)->mid_nid) &&	\
%			((a)->mid_smid == (b)->mid_smid) &&	\
%			((a)->mid_time == (b)->mid_time))
%
%#define	MSGID_ELEMS(mid) (mid).mid_nid, (mid).mid_time, (mid).mid_smid

/* if you add elements here, make sure, to add them to copy_msg(), too */
struct md_mn_msg_t {
        md_mn_msgid_t	msg_msgid;	/* Message id */
	md_mn_nodeid_t	msg_sender;	/* who wants the results? */
	u_int		msg_flags;	/* See MD_MSGF_* above */
	set_t		msg_setno;	/* which set is involved */
        md_mn_msgtype_t msg_type;       /* what type of message */
	md_mn_nodeid_t	msg_recipient;	/* who to send DIRECTED message to */
	char		msg_spare[28];	/* Always good to hav'em */
	opaque		msg_event<>;	/* the actual event wrapped up */
};
%#define	msg_event_data	msg_event.msg_event_val
%#define	msg_event_size	msg_event.msg_event_len
%
%#define	MD_MN_MSG_LEN(msg)	((msg)->msg_event_size +\
%							sizeof (md_mn_msg_t))
%#define	MD_MN_MSG_MAXDATALEN	1024

/* ondisk version of the message */
struct md_mn_msg_od_t {
        md_mn_msgid_t	msg_msgid;	/* Message id */
	md_mn_nodeid_t	msg_sender;	/* who wants the results? */
	uint32_t	msg_flags;	/* See MD_MSGF_* above */
	set_t		msg_setno;	/* which set is involved */
        md_mn_msgtype_t msg_type;       /* what type of message */
	md_mn_nodeid_t	msg_recipient;	/* who to send DIRECTED message to */
	char		msg_spare[28];	/* Always good to hav'em */
	uint32_t	msg_ev_len;	
	char		msg_ev_val[MD_MN_MSG_MAXDATALEN];
};
%
%#define	msg_od_event_data	msg_ev_val
%#define	msg_od_event_size	msg_ev_len
%#define	MDMN_MAX_KMSG_DATA	256

/* needed for mdmn_ksend_message to deliver the data into userland thru doors */
struct md_mn_kmsg_t {
	md_mn_msgid_t 	kmsg_msgid;
	u_int		kmsg_flags;
	set_t		kmsg_setno;
	md_mn_msgtype_t	kmsg_type;
	md_mn_nodeid_t	kmsg_recipient;	/* who to send DIRECTED message to */
	int		kmsg_size;
	char		kmsg_data[MDMN_MAX_KMSG_DATA];
};

/* if you add elements here, make sure, to add them to copy_result(), too */
struct md_mn_result_t {
	md_mn_msgid_t	mmr_msgid;
	md_mn_msgtype_t	mmr_msgtype;
	set_t		mmr_setno;
	u_int		mmr_flags;
	md_mn_nodeid_t	mmr_sender;   /* needed to check for unsolicited msgs */
	md_mn_nodeid_t	mmr_failing_node; /* trouble maker */
	int		mmr_comm_state;
	int		mmr_exitval;
	md_error_t	mmr_ep;
	opaque		mmr_output<>; /* msg handler can store output here */
	opaque		mmr_error<>;  /* ... and error output goes here */
};

%#define	MDMN_MAX_KRES_DATA	256
/* kernel results don't provide something like stderr */
struct md_mn_kresult_t {
	md_mn_msgtype_t	kmmr_msgtype;
	u_int		kmmr_flags;
	int		kmmr_comm_state;
	md_mn_nodeid_t	kmmr_failing_node; /* trouble maker */
	int		kmmr_exitval;
	int		kmmr_res_size;
	char		kmmr_res_data[MDMN_MAX_KRES_DATA];
};

/* possible return values for the rpc services */
enum md_mn_retval_t {
	MDMNE_NULL = 0,
	MDMNE_ACK,		/* this is the good one */
	MDMNE_CLASS_BUSY,	/* try again */
	MDMNE_RPC_FAIL,		/* some RPC error occurred */
	MDMNE_THR_CREATE_FAIL,  /* cannot create working thread */
	MDMNE_NO_HANDLER,	/* this message has no handler */
	MDMNE_LOG_FAIL,		/* logging failed for some reason */
	MDMNE_CANNOT_CONNECT,	/* rpc connection not possible */
	MDMNE_NO_WAKEUP_ENTRY,	/* no entry in wakeup table for msgid */
	MDMNE_NOT_JOINED,	/* this host hasn't joined yet */
	MDMNE_HANDLER_FAILED,	/* could not run the handler for this message */
	MDMNE_EINVAL,		/* bad argument specified for special message */
	MDMNE_SUSPENDED,	/* commd doesn't accept new messgaes */
	MDMNE_CLASS_LOCKED,	/* class has been locked (for testing only) */
	MDMNE_TIMEOUT,		/* processing message took too long */
	MDMNE_SET_NOT_DRAINED,	/* still outstandang messages for this set */
	MDMNE_ABORT,		/* Contacted node is in abort state */
	MDMNE_IGNORE_NODE	/* ignore current node, send msg to next one */
};	

%
%#define	MDMN_KSEND_MSG_OK(rv, kres)		\
%	(((rv) == 0) && (((kres)->kmmr_exitval == 0) && \
%	 (((kres)->kmmr_comm_state == MDMNE_ACK) || \
%	  (!md_mn_is_commd_present() && \
%	   ((kres)->kmmr_comm_state == MDMNE_RPC_FAIL)))))
%

%
%#define	mmr_out		mmr_output.mmr_output_val
%#define	mmr_out_size	mmr_output.mmr_output_len
%#define	mmr_err		mmr_error.mmr_error_val
%#define	mmr_err_size	mmr_error.mmr_error_len
%
%
%extern void mdmn_master_process_msg(md_mn_msg_t *);
%extern void mdmn_slave_process_msg(md_mn_msg_t *);


struct md_mn_set_and_class_t {
	set_t			msc_set;
	md_mn_msgclass_t	msc_class;
	u_int			msc_flags;
};

%/* possible values for msc_flags above */
%#define	MD_MSCF_NO_FLAGS		0x0000
%#define	MD_MSCF_DONT_RESUME_CLASS1	0x0001

struct md_mn_type_and_lock_t {
	md_mn_msgtype_t	mmtl_type;
	u_int		mmtl_lock;
};

%/* possible values for mmtl_flags above */
%#define	MMTL_UNLOCK		0x0000
%#define	MMTL_LOCK		0x0001

%/* Currently not used, but thinkable extensions */
%#define	MMTL_LOCK_ON_INITIATOR	0x0002
%#define	MMTL_LOCK_ON_MASTER	0x0004
%#define	MMTL_LOCK_ON_SLAVE	0x0008
%#define	MMTL_LOCK_ONE_TIME_ONLY	0x0010


program MDMN_COMMD {
	version TWO {
		md_mn_result_t 
		mdmn_send(md_mn_msg_t) = 1;

		int
		mdmn_work(md_mn_msg_t msg) = 2;

		int
		mdmn_wakeup_initiator(md_mn_result_t) = 3;
		
		int
		mdmn_wakeup_master(md_mn_result_t) = 4;
		
		int
		mdmn_comm_lock(md_mn_set_and_class_t) = 5;
		
		int
		mdmn_comm_unlock(md_mn_set_and_class_t) = 6;
		
		int
		mdmn_comm_suspend(md_mn_set_and_class_t) = 7;
		
		int
		mdmn_comm_resume(md_mn_set_and_class_t) = 8;
		
		int
		mdmn_comm_reinit_set(set_t) = 9;
		
		int
		mdmn_comm_msglock(md_mn_type_and_lock_t) = 10;
	} = 2;
} = 100422;
