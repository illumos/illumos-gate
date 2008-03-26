/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smb_conn.h,v 1.32.42.1 2005/05/27 02:35:29 lindak Exp $
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMB_CONN_H
#define	_SMB_CONN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/t_lock.h>
#include <sys/queue.h> /* for SLIST below */
#include <sys/uio.h>
#include <netsmb/smb_dev.h>

#ifndef _KERNEL
#error "Not _KERNEL?"
#endif

/*
 * Credentials of user/process for processing in the connection procedures
 */
typedef struct smb_cred {
	pid_t	vc_pid;
	cred_t *vc_ucred;
} smb_cred_t;

/*
 * Common object flags
 */
#define	SMBO_GONE		0x1000000

/*
 * Bits in vc_flags (a.k.a. vc_co.co_flags)
 * Many of these were duplicates of SMBVOPT_ flags
 * and we now keep those too instead of merging
 * them into vc_flags.
 */

#define	SMBV_LONGNAMES		0x0004	/* conn configured to use long names */
#define	SMBV_ENCRYPT		0x0008	/* server demands encrypted password */
#define	SMBV_WIN95		0x0010	/* used to apply bugfixes for this OS */
#define	SMBV_NT4		0x0020	/* used when NT4 issues invalid resp */
#define	SMBV_RECONNECTING	0x0040	/* conn in process of reconnection */
/*				0x0200	   unused - was SMBV_FAILED */
#define	SMBV_UNICODE		0x0400	/* conn configured to use Unicode */
#define	SMBV_EXT_SEC		0x0800	/* conn to use extended security */

/*
 * Note: the common "obj" level uses this GONE flag by
 * the name SMBO_GONE.  Keep this alias as a reminder.
 */
#define	SMBV_GONE SMBO_GONE

/*
 * bits in smb_share ss_flags (a.k.a. ss_co.co_flags)
 */
#define	SMBS_RECONNECTING	0x0002
#define	SMBS_CONNECTED		0x0004
#define	SMBS_TCON_WAIT		0x0008
#define	SMBS_1980		0x0010
/*
 * ^ This partition can't handle dates before 1980. It's probably a FAT
 * partition but could be some other ancient FS type
 */
#define	SMBS_RESUMEKEYS		0x0010	/* must use resume keys */
/*
 * Note: the common "obj" level uses this GONE flag by
 * the name SMBO_GONE.  Keep this alias as a reminder.
 */
#define	SMBS_GONE SMBO_GONE

/*
 * Negotiated protocol parameters
 */
struct smb_sopt {
	int		sv_proto;
	int16_t		sv_tz;		/* offset in min relative to UTC */
	uint32_t	sv_maxtx;	/* maximum transmit buf size */
	uchar_t		sv_sm;		/* security mode */
	uint16_t	sv_maxmux;	/* max number of outstanding rq's */
	uint16_t 	sv_maxvcs;	/* max number of VCs */
	uint16_t	sv_rawmode;
	uint32_t	sv_maxraw;	/* maximum raw-buffer size */
	uint32_t	sv_skey;	/* session key */
	uint32_t	sv_caps;	/* capabilites SMB_CAP_ */
};
typedef struct smb_sopt smb_sopt_t;

/*
 * network IO daemon states
 * really connection states.
 */
enum smbiod_state {
	SMBIOD_ST_NOTCONN,	/* no connect request was made */
	SMBIOD_ST_RECONNECT,	/* a [re]connect attempt is in progress */
	SMBIOD_ST_TRANACTIVE,	/* transport level is up */
	SMBIOD_ST_NEGOACTIVE,	/* completed negotiation */
	SMBIOD_ST_SSNSETUP,	/* started (a) session setup */
	SMBIOD_ST_VCACTIVE,	/* session established */
	SMBIOD_ST_DEAD		/* connection broken, transport is down */
};


/*
 * Info structures
 */
#define	SMB_INFO_NONE		0
#define	SMB_INFO_VC		2
#define	SMB_INFO_SHARE		3

struct smb_vc_info {
	int		itype;
	int		usecount;
	uid_t		uid;		/* user id of connection */
	gid_t		gid;		/* group of connection */
	mode_t		mode;		/* access mode */
	int		flags;
	enum smbiod_state iodstate;
	struct smb_sopt	sopt;
	char		srvname[SMB_MAXSRVNAMELEN+1];
	char		vcname[128];
};
typedef struct smb_vc_info smb_vc_info_t;

struct smb_share_info {
	int		itype;
	int		usecount;
	ushort_t		tid;		/* TID */
	int		type;		/* share type */
	uid_t		uid;		/* user id of connection */
	gid_t		gid;		/* group of connection */
	mode_t		mode;		/* access mode */
	int		flags;
	char		sname[128];
};
typedef struct smb_share_info smb_share_info_t;

struct smb_rq;
/* This declares struct smb_rqhead */
TAILQ_HEAD(smb_rqhead, smb_rq);

#define	SMB_NBTIMO	15
#define	SMB_DEFRQTIMO	30	/* 30 for oplock revoke/writeback */
#define	SMBWRTTIMO	60
#define	SMBSSNSETUPTIMO	60
#define	SMBNOREPLYWAIT (0)

#define	SMB_DIALECT(vcp)	((vcp)->vc_sopt.sv_proto)

/*
 * Connection object
 */

#define	SMB_CO_LOCK(cp)		mutex_enter(&(cp)->co_lock)
#define	SMB_CO_UNLOCK(cp)	mutex_exit(&(cp)->co_lock)

/*
 * Common part of smb_vc, smb_share
 * Locking: co_lock protects most
 * fields in this struct, except
 * as noted below:
 */
struct smb_connobj {
	kmutex_t		co_lock;
	int			co_level;	/* SMBL_ */
	int			co_flags;
	int			co_usecount;

	/* Note: must lock co_parent before child. */
	struct smb_connobj	*co_parent;

	/* this.co_lock protects the co_children list */
	SLIST_HEAD(, smb_connobj) co_children;

	/*
	 * Linkage in parent's list of children.
	 * Must hold parent.co_lock to traverse.
	 */
	SLIST_ENTRY(smb_connobj) co_next;

	/* These two are set only at creation. */
	void (*co_gone)(struct smb_connobj *);
	void (*co_free)(struct smb_connobj *);
};
typedef struct smb_connobj smb_connobj_t;

/*
 * Virtual Circuit (session) to a server.
 * This is the most (over)complicated part of SMB protocol.
 * For the user security level (usl), each session with different remote
 * user name has its own VC.
 * It is unclear however, should share security level (ssl) allow additional
 * VCs, because user name is not used and can be the same. On other hand,
 * multiple VCs allows us to create separate sessions to server on a per
 * user basis.
 */

typedef struct smb_vc {
	struct smb_connobj vc_co;
	enum smbiod_state vc_state;
	kcondvar_t vc_statechg;
	ksema_t	vc_sendlock;

	zoneid_t	vc_zoneid;
	char		*vc_srvname;
	struct sockaddr *vc_paddr;	/* server addr */
	struct sockaddr *vc_laddr;	/* local addr, if any */
	char		*vc_domain;	/* domain that defines username */
	char		*vc_username;
	char		*vc_pass;	/* password for usl case */
	uchar_t		vc_lmhash[SMB_PWH_MAX];
	uchar_t		vc_nthash[SMB_PWH_MAX];

	uint_t		vc_timo;	/* default request timeout */
	int		vc_maxvcs;	/* maximum number of VC per conn */

	void		*vc_tolower;	/* local charset */
	void		*vc_toupper;	/* local charset */
	void		*vc_toserver;	/* local charset to server one */
	void		*vc_tolocal;	/* server charset to local one */
	int		vc_number;	/* number of this VC from client side */
	int		vc_genid;	/* "generation ID" of this VC */
	uid_t		vc_uid;		/* user id of connection */
	gid_t		vc_grp;		/* group of connection */
	mode_t		vc_mode;	/* access mode */
	uint16_t	vc_smbuid;	/* auth. session ID from server */

	uint8_t		vc_hflags;	/* or'ed with flags in the smb header */
	uint16_t	vc_hflags2;	/* or'ed with flags in the smb header */
	void		*vc_tdata;	/* transport control block */
	struct smb_tran_desc *vc_tdesc;
	int		vc_chlen;	/* actual challenge length */
	uchar_t 	vc_challenge[SMB_MAXCHALLENGELEN];
	uint16_t		vc_mid;		/* multiplex id */
	int		vc_vopt;	/* local options SMBVOPT_ */
	struct smb_sopt	vc_sopt;	/* server options */
	struct smb_cred	vc_scred;	/* used in reconnect procedure */
	int		vc_txmax;	/* max tx/rx packet size */
	int		vc_rxmax;	/* max readx data size */
	int		vc_wxmax;	/* max writex data size */

	/* Authentication tokens */
	size_t		vc_intoklen;
	caddr_t		vc_intok;
	size_t		vc_outtoklen;
	caddr_t		vc_outtok;
	size_t		vc_negtoklen;
	caddr_t		vc_negtok;

	/*
	 * These members used to be in struct smbiod,
	 * which has been eliminated.
	 */
	krwlock_t	iod_rqlock;	/* iod_rqlist */
	struct smb_rqhead	iod_rqlist;	/* list of outstanding reqs */
	struct _kthread 	*iod_thr;	/* the IOD (reader) thread */
	kcondvar_t		iod_exit; 	/* IOD thread termination */
	int			iod_flags;	/* see SMBIOD_* below */
	int			iod_newrq;	/* send needed (iod_rqlock) */
	int			iod_muxfull;	/* maxmux limit reached */
	uint_t		iod_rqwaiting;	/* count of waiting requests */
} smb_vc_t;

#define	vc_lock		vc_co.co_lock
#define	vc_flags	vc_co.co_flags
#define	vc_maxmux	vc_sopt.sv_maxmux

#define	SMB_VC_LOCK(vcp)	mutex_enter(&(vcp)->vc_lock)
#define	SMB_VC_UNLOCK(vcp)	mutex_exit(&(vcp)->vc_lock)

#define	SMB_UNICODE_STRINGS(vcp)	((vcp)->vc_hflags2 & SMB_FLAGS2_UNICODE)

/* Bits in iod_flags */
#define	SMBIOD_RUNNING		0x0001
#define	SMBIOD_SHUTDOWN		0x0002

/*
 * smb_share structure describes connection to the given SMB share (tree).
 * Connection to share is always built on top of the VC.
 */

typedef struct smb_share {
	struct smb_connobj ss_co;
	kcondvar_t	ss_conn_done;	/* wait for reconnect */
	int		ss_conn_waiters;
	char		*ss_name;
	char		*ss_pass;	/* share password, can be null */
	char		*ss_fsname;
	void		*ss_mount;	/* used for smb up/down */
	uint16_t	ss_tid;		/* TID */
	int		ss_type;	/* share type */
	mode_t		ss_mode;	/* access mode */
	int		ss_vcgenid;	/* check VC generation ID */
	uint32_t	ss_maxfilenamelen;
	int		ss_sopt;	/* local options SMBSOPT_ */
} smb_share_t;

#define	ss_lock		ss_co.co_lock
#define	ss_flags	ss_co.co_flags

#define	SMB_SS_LOCK(ssp)	mutex_enter(&(ssp)->ss_lock)
#define	SMB_SS_UNLOCK(ssp)	mutex_exit(&(ssp)->ss_lock)

#define	CPTOVC(cp)	((struct smb_vc *)(cp))
#define	VCTOCP(vcp)	(&(vcp)->vc_co)

#define	CPTOSS(cp)	((struct smb_share *)(cp))
#define	SSTOVC(ssp)	CPTOVC(((ssp)->ss_co.co_parent))
#define	SSTOCP(ssp)	(&(ssp)->ss_co)

/*
 * This is used internally to pass all the info about
 * some VC that an ioctl caller is looking for.
 */
struct smb_vcspec {
	char		*srvname;
	struct sockaddr *sap;
	struct sockaddr *lap;
	int		optflags;
	char		*domain;
	char		*username;
	char		*pass;
	uid_t		owner;
	gid_t		group;
	mode_t		mode;
	mode_t		rights;
	char		*localcs;
	char		*servercs;
	size_t		toklen;
	caddr_t		tok;
};
typedef struct smb_vcspec smb_vcspec_t;

/*
 * This is used internally to pass all the info about
 * some share that an ioctl caller is looking for.
 */
struct smb_sharespec {
	char		*name;
	char		*pass;
	mode_t		mode;
	mode_t		rights;
	uid_t		owner;
	gid_t		group;
	int		stype;
	int		optflags;
};
typedef struct smb_sharespec smb_sharespec_t;


/*
 * Call-back operations vector, so the netsmb module
 * can notify smbfs about events affecting mounts.
 * Installed in netsmb after smbfs loads.
 */
/* #define NEED_SMBFS_CALLBACKS 1 */
#ifdef NEED_SMBFS_CALLBACKS
typedef struct smb_fscb {
	void (*fscb_dead)(smb_share_t *);
	void (*fscb_down)(smb_share_t *);
	void (*fscb_up)(smb_share_t *);
} smb_fscb_t;
/* Install the above vector, or pass NULL to clear it. */
int smb_fscb_set(smb_fscb_t *);
#endif /* NEED_SMBFS_CALLBACKS */

/*
 * IOD functions
 */
int  smb_iod_create(struct smb_vc *vcp);
int  smb_iod_destroy(struct smb_vc *vcp);
int  smb_iod_connect(struct smb_vc *vcp);
int  smb_iod_disconnect(struct smb_vc *vcp);
int  smb_iod_addrq(struct smb_rq *rqp);
int  smb_iod_multirq(struct smb_rq *rqp);
int  smb_iod_waitrq(struct smb_rq *rqp);
int  smb_iod_removerq(struct smb_rq *rqp);
void smb_iod_shutdown_share(struct smb_share *ssp);
void smb_iod_notify_down(struct smb_vc *vcp);
void smb_iod_notify_up(struct smb_vc *vcp);

/*
 * Session level functions
 */
int  smb_sm_init(void);
int  smb_sm_idle(void);
void smb_sm_done(void);

int  smb_sm_findvc(struct smb_vcspec *vcspec,
	struct smb_cred *scred,	struct smb_vc **vcpp);
int  smb_sm_negotiate(struct smb_vcspec *vcspec,
	struct smb_cred *scred,	struct smb_vc **vcpp);
int  smb_sm_ssnsetup(struct smb_vcspec *vcspec,
	struct smb_cred *scred,	struct smb_vc *vcp);
int  smb_sm_tcon(struct smb_sharespec *shspec, struct smb_cred *scred,
	struct smb_vc *vcp, struct smb_share **sspp);

/*
 * VC level functions
 */
int smb_vc_setup(struct smb_vcspec *vcspec, struct smb_cred *scred,
	struct smb_vc *vcp, int is_ss);
int  smb_vc_create(struct smb_vcspec *vcspec,
	struct smb_cred *scred, struct smb_vc **vcpp);
int  smb_vc_negotiate(struct smb_vc *vcp, struct smb_cred *scred);
int  smb_vc_ssnsetup(struct smb_vc *vcp, struct smb_cred *scred);
void smb_vc_hold(struct smb_vc *vcp);
void smb_vc_rele(struct smb_vc *vcp);
void smb_vc_kill(struct smb_vc *vcp);
int  smb_vc_lookupshare(struct smb_vc *vcp, struct smb_sharespec *shspec,
	struct smb_cred *scred, struct smb_share **sspp);
const char *smb_vc_getpass(struct smb_vc *vcp);
uint16_t smb_vc_nextmid(struct smb_vc *vcp);
void *smb_vc_getipaddr(struct smb_vc *vcp, int *ipvers);

/*
 * share level functions
 */
int  smb_share_create(struct smb_vc *vcp, struct smb_sharespec *shspec,
	struct smb_cred *scred, struct smb_share **sspp);

void smb_share_hold(struct smb_share *ssp);
void smb_share_rele(struct smb_share *ssp);
void smb_share_kill(struct smb_share *ssp);

void smb_share_invalidate(struct smb_share *ssp);
int  smb_share_tcon(struct smb_share *ssp);
int  smb_share_valid(struct smb_share *ssp);
const char *smb_share_getpass(struct smb_share *ssp);
int  smb_share_count(void);

/*
 * SMB protocol level functions
 */
int  smb_smb_negotiate(struct smb_vc *vcp, struct smb_cred *scred);
int  smb_smb_ssnsetup(struct smb_vc *vcp, struct smb_cred *scred);
int  smb_smb_ssnclose(struct smb_vc *vcp, struct smb_cred *scred);
int  smb_smb_treeconnect(struct smb_share *ssp, struct smb_cred *scred);
int  smb_smb_treedisconnect(struct smb_share *ssp, struct smb_cred *scred);
int  smb_smb_echo(struct smb_vc *vcp, struct smb_cred *scred, int timo);
#ifdef APPLE
int  smb_smb_checkdir(struct smb_share *ssp, void *dnp,
	char *name, int nmlen, struct smb_cred *scred);
#endif
int smb_rwuio(struct smb_share *ssp, uint16_t fid, uio_rw_t rw,
	uio_t *uiop, struct smb_cred *scred, int timo);

#endif /* _SMB_CONN_H */
