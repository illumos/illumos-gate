/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 RackTop Systems.
 */

#ifndef _NFS4X_H
#define	_NFS4X_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/cred.h>
#include <nfs/nfs4_kprot.h>

/*
 * 24 bytes of rpc header
 * 12 bytes for compound header
 * 44 bytes for SEQUENCE response
 */
#define	NFS4_MIN_HDR_SEQSZ	(24 + 12 + 44)

/*
 * NFSv4.1: slot support (reply cache)
 */

#define	RFS4_SLOT_INUSE		(1 << 0)
#define	RFS4_SLOT_CACHED	(1 << 1)

/* Slot entry structure */
typedef struct rfs4_slot {
	uint32_t	se_flags;
	sequenceid4	se_seqid;
	COMPOUND4res	se_buf;	/* Buf for slot and replays */
	kmutex_t	se_lock;
} rfs4_slot_t;

/*
 * NFSv4.1 Sessions
 */

typedef struct rfs41_csr {	/* contrived create_session result */
	sequenceid4		xi_sid;		/* seqid response to EXCHG_ID */
	nfsstat4		cs_status;
	CREATE_SESSION4resok	cs_res;		/* cached results if NFS4_OK */
} rfs41_csr_t;

/*
 * Sessions Callback Infrastructure
 *
 * Locking:
 *
 * . cn_lock protects all fields in sess_channel_t, but since
 *   fore/back and dir don't change often, we serialize only
 *   the occasional update.
 *
 * cn_lock:	cn_lock
 * bsd_rwlock:	cn_lock -> bsd_rwlock
 */

#define		MAX_CH_CACHE	10
typedef struct {				/* Back Chan Specific Data */
	rfs4_slot_t		 *bsd_slots;	/* opaque token for slot tab */
	nfsstat4		  bsd_stat;
	krwlock_t		  bsd_rwlock;	/* protect slot tab info */
	uint64_t		  bsd_idx;	/* Index of next spare CLNT */
	uint64_t		  bsd_cur;	/* Most recent added CLNT */
	int			  bsd_ch_free;
	CLIENT			 *bsd_clnt[MAX_CH_CACHE];
} sess_bcsd_t;

typedef struct {
	channel_dir_from_server4 cn_dir;		/* Chan Direction */
	channel_attrs4		 cn_attrs;		/* chan Attrs */
	channel_attrs4		 cn_back_attrs;		/* back channel Attrs */
	sess_bcsd_t		*cn_csd;		/* Chan Specific Data */
	krwlock_t		 cn_lock;
} sess_channel_t;

/*
 * Maximum number of concurrent COMPOUND requests per session
 */
#define	MAXSLOTS	256
#define	MAXSLOTS_BACK	4

typedef struct {
	state_protect_how4	 sp_type;
} rfs41_sprot_t;

/*
 * NFSv4.1 Sessions (cont'd)
 *
 *   rfs4_session_t             rfs4_client_t
 *   +-------------+           +--------------------+
 *   | sn_sessid   |           | clientid           |
 *   | sn_clnt *  -|---------->|    :               |
 *   | sn_fore     |           +--------------------+
 *   | sn_back     |
 *   | sn_slots * -|---------> +--------------------------------+
 *   +-------------+           |        (slot_ent_t)            |
 *                             |  +----------------------------+|
 *                             |  | status, slot, seqid, resp *||------><Res>
 *                             |  +----------------------------+|
 *                             |  | status, slot, seqid, resp *||
 *                             |  +----------------------------+|
 *                             |  | status, slot, seqid, resp *||
 *                             |  +----------------------------+|
 *			       | .				|
 *			       | :				|
 *                             +--------------------------------+
 *                             stok_t
 */
struct rfs4_client;
struct rfs4_dbe;

typedef struct {
	nfsstat4		 cs_error;
	struct rfs4_client	*cs_client;
	struct svc_req		*cs_req;
	uint32_t		 cs_id;
	CREATE_SESSION4args	 cs_aotw;
} session41_create_t;

/*
 * sn_seq4 - sequence result bit accounting info (session scope)
 *	CB_PATH_DOWN_SESSION, CB_GSS_CONTEXT_EXPIRING,
 *	CB_GSS_CONTEXT_EXPIRED, BACKCHANNEL_FAULT
 */
typedef struct rfs4_session {
	struct rfs4_dbe		*sn_dbe;
	sessionid4		 sn_sessid;	/* session id */
	struct rfs4_client	*sn_clnt;	/* back ptr to client state */
	sess_channel_t		*sn_fore;	/* fore chan for this session */
	sess_channel_t		*sn_back;	/* back chan for this session */
	rfs4_slot_t		*sn_slots;	/* slot replay cache */
	time_t			 sn_laccess;	/* struct was last accessed */
	int			 sn_csflags;	/* create_session only flags */
	uint32_t		 sn_flags;	/* SEQ4 status bits */
	list_node_t		 sn_node;	/* link node to rfs4_client */
	struct	{
		uint32_t	pngcnt;		/* conn pings outstanding */
		uint32_t	progno;		/* cb_program number */
		uint32_t	failed:1;	/* TRUE if no cb path avail */
		uint32_t	pnginprog:1;
	} sn_bc;
	uint32_t		 sn_rcached;	/* cached replies, for stat */
} rfs4_session_t;

#define	SN_CB_CHAN_EST(x)	((x)->sn_back != NULL)
#define	SN_CB_CHAN_OK(x)	((x)->sn_bc.failed == 0)

/* error code for internal use */
#define	nfserr_replay_cache NFS4ERR_REPLAY_CACHE

/* Session end */

/*
 * Set of RPC credentials used for a particular operation.
 * Used for operations like SETCLIENTID_CONFIRM where the
 * credentials needs to match those used at SETCLIENTID.
 * For EXCHANGE_ID (NFSv4.1+)
 */

typedef struct {
	cred_t	*cp_cr;
	int	 cp_aflavor;
	int	 cp_secmod;
	caddr_t	 cp_princ;
} cred_set_t;

/* NFSv4.1 Functions */
extern int rfs4x_dispatch(struct svc_req *, SVCXPRT *, char *);

void rfs4_free_cred_set(cred_set_t *);
void rfs4x_session_rele(rfs4_session_t *);
rfs4_session_t *rfs4x_createsession(session41_create_t *);
nfsstat4 rfs4x_destroysession(rfs4_session_t *, unsigned useref);
void rfs4x_client_session_remove(struct rfs4_client *);
rfs4_session_t *rfs4x_findsession_by_id(sessionid4);
void rfs4x_session_hold(rfs4_session_t *);
void rfs4x_session_rele(rfs4_session_t *);

/* Some init/fini helpers */
struct rfs4_srv;
struct compound_state;
void rfs4x_state_init_locked(struct nfs4_srv *);
void rfs4x_state_fini(struct nfs4_srv *);
int rfs4x_sequence_prep(COMPOUND4args *, COMPOUND4res *,
    struct compound_state *, SVCXPRT *);
void rfs4x_sequence_done(COMPOUND4res *, struct compound_state *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _NFS4X_H */
