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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMB_CONN_H
#define	_SMB_CONN_H

#include <sys/dditypes.h>
#include <sys/t_lock.h>
#include <sys/queue.h> /* for SLIST below */
#include <sys/uio.h>
#include <netsmb/smb_dev.h>

/*
 * Credentials of user/process for processing in the connection procedures
 */
typedef struct smb_cred {
	struct cred *scr_cred;
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

#define	SMBV_WIN95		0x0010	/* used to apply bugfixes for this OS */
#define	SMBV_NT4		0x0020	/* used when NT4 issues invalid resp */
#define	SMBV_UNICODE		0x0040	/* conn configured to use Unicode */

/*
 * Note: the common "obj" level uses this GONE flag by
 * the name SMBO_GONE.  Keep this alias as a reminder.
 */
#define	SMBV_GONE		SMBO_GONE

/*
 * bits in smb_share ss_flags (a.k.a. ss_co.co_flags)
 */
#define	SMBS_RECONNECTING	0x0002
#define	SMBS_CONNECTED		0x0004
#define	SMBS_TCON_WAIT		0x0008
#define	SMBS_FST_FAT		0x0010	/* share FS Type is FAT */
/*
 * Note: the common "obj" level uses this GONE flag by
 * the name SMBO_GONE.  Keep this alias as a reminder.
 */
#define	SMBS_GONE		SMBO_GONE

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
 * "Level" in the connection object hierarchy
 */
#define	SMBL_SM		0
#define	SMBL_VC		1
#define	SMBL_SHARE	2

/*
 * Virtual Circuit to a server (really connection + session).
 * Yes, calling this a "Virtual Circuit" is confusining,
 * because it has nothing to do with the SMB notion of a
 * "Virtual Circuit".
 */
typedef struct smb_vc {
	struct smb_connobj	vc_co;	/* keep first! See CPTOVC */
	enum smbiod_state	vc_state;
	kcondvar_t		vc_statechg;

	zoneid_t		vc_zoneid;
	uid_t			vc_owner;	/* Unix owner */
	int			vc_genid;	/* "generation" ID */

	int			vc_mackeylen;	/* length of MAC key */
	uint8_t			*vc_mackey;	/* MAC key */

	ksema_t			vc_sendlock;
	struct smb_tran_desc	*vc_tdesc;	/* transport ops. vector */
	void			*vc_tdata;	/* transport control block */

	kcondvar_t		iod_idle; 	/* IOD thread idle CV */
	krwlock_t		iod_rqlock;	/* iod_rqlist */
	struct smb_rqhead	iod_rqlist;	/* list of outstanding reqs */
	struct _kthread 	*iod_thr;	/* the IOD (reader) thread */
	int			iod_flags;	/* see SMBIOD_* below */
	int			iod_newrq;	/* send needed (iod_rqlock) */
	int			iod_muxfull;	/* maxmux limit reached */

	/* This is copied in/out when IOD enters/returns */
	smbioc_ssn_work_t	vc_work;

	/* session identity, etc. */
	smbioc_ossn_t		vc_ssn;
} smb_vc_t;

#define	vc_lock		vc_co.co_lock
#define	vc_flags	vc_co.co_flags

/* defines for members in vc_ssn */
#define	vc_owner	vc_ssn.ssn_owner
#define	vc_srvname	vc_ssn.ssn_srvname
#define	vc_srvaddr	vc_ssn.ssn_id.id_srvaddr
#define	vc_domain	vc_ssn.ssn_id.id_domain
#define	vc_username	vc_ssn.ssn_id.id_user
#define	vc_vopt 	vc_ssn.ssn_vopt

/* defines for members in vc_work */
#define	vc_sopt		vc_work.wk_sopt
#define	vc_maxmux	vc_work.wk_sopt.sv_maxmux
#define	vc_tran_fd	vc_work.wk_iods.is_tran_fd
#define	vc_hflags	vc_work.wk_iods.is_hflags
#define	vc_hflags2	vc_work.wk_iods.is_hflags2
#define	vc_smbuid	vc_work.wk_iods.is_smbuid
#define	vc_next_mid	vc_work.wk_iods.is_next_mid
#define	vc_txmax	vc_work.wk_iods.is_txmax
#define	vc_rwmax	vc_work.wk_iods.is_rwmax
#define	vc_rxmax	vc_work.wk_iods.is_rxmax
#define	vc_wxmax	vc_work.wk_iods.is_wxmax
#define	vc_ssn_key	vc_work.wk_iods.is_ssn_key
#define	vc_next_seq	vc_work.wk_iods.is_next_seq
#define	vc_u_mackey	vc_work.wk_iods.is_u_mackey
#define	vc_u_maclen	vc_work.wk_iods.is_u_maclen

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
	struct smb_connobj ss_co;	/* keep first! See CPTOSS */
	kcondvar_t	ss_conn_done;	/* wait for reconnect */
	int		ss_conn_waiters;
	int		ss_vcgenid;	/* check VC generation ID */
	uint16_t	ss_tid;		/* TID */
	uint16_t	ss_options;	/* option support bits */
	smbioc_oshare_t ss_ioc;
} smb_share_t;

#define	ss_lock		ss_co.co_lock
#define	ss_flags	ss_co.co_flags

#define	ss_use		ss_ioc.sh_use
#define	ss_type		ss_ioc.sh_type
#define	ss_name		ss_ioc.sh_name
#define	ss_pass		ss_ioc.sh_pass

#define	SMB_SS_LOCK(ssp)	mutex_enter(&(ssp)->ss_lock)
#define	SMB_SS_UNLOCK(ssp)	mutex_exit(&(ssp)->ss_lock)

#define	CPTOVC(cp)	((struct smb_vc *)((void *)(cp)))
#define	VCTOCP(vcp)	(&(vcp)->vc_co)

#define	CPTOSS(cp)	((struct smb_share *)((void *)(cp)))
#define	SSTOVC(ssp)	CPTOVC(((ssp)->ss_co.co_parent))
#define	SSTOCP(ssp)	(&(ssp)->ss_co)

/*
 * Call-back operations vector, so the netsmb module
 * can notify smbfs about events affecting mounts.
 * Installed in netsmb after smbfs loads.
 */
typedef struct smb_fscb {
	/* Called when the VC has disconnected. */
	void (*fscb_disconn)(smb_share_t *);
	/* Called when the VC has reconnected. */
	void (*fscb_connect)(smb_share_t *);
	/* Called when the server becomes unresponsive. */
	void (*fscb_down)(smb_share_t *);
	/* Called when the server is responding again. */
	void (*fscb_up)(smb_share_t *);
} smb_fscb_t;
/* Install the above vector, or pass NULL to clear it. */
void smb_fscb_set(smb_fscb_t *);

/*
 * The driver per open instance object.
 * Mostly used in: smb_dev.c, smb_usr.c
 */
typedef struct smb_dev {
	kmutex_t	sd_lock;
	struct smb_vc	*sd_vc;		/* Reference to VC */
	struct smb_share *sd_share;	/* Reference to share if any */
	int		sd_level;	/* SMBL_VC, ... */
	int		sd_vcgenid;	/* Generation of share or VC */
	int		sd_poll;	/* Future use */
	int		sd_flags;	/* State of connection */
#define	NSMBFL_OPEN		0x0001
#define	NSMBFL_IOD		0x0002
#define	NSMBFL_IOCTL		0x0004
	int		sd_smbfid;	/* library read/write */
	zoneid_t	zoneid;		/* Zone id */
} smb_dev_t;

extern const uint32_t nsmb_version;

/*
 * smb_dev.c
 */
int  smb_dev2share(int fd, struct smb_share **sspp);


/*
 * smb_usr.c
 */
int smb_usr_get_flags2(smb_dev_t *sdp, intptr_t arg, int flags);
int smb_usr_get_ssnkey(smb_dev_t *sdp, intptr_t arg, int flags);
int smb_usr_dup_dev(smb_dev_t *sdp, intptr_t arg, int flags);

int smb_usr_simplerq(smb_dev_t *sdp, intptr_t arg, int flags, cred_t *cr);
int smb_usr_t2request(smb_dev_t *sdp, intptr_t arg, int flags, cred_t *cr);

int smb_usr_closefh(smb_dev_t *, cred_t *);
int smb_usr_rw(smb_dev_t *sdp, int cmd, intptr_t arg, int flags, cred_t *cr);
int smb_usr_ntcreate(smb_dev_t *, intptr_t, int, cred_t *);
int smb_usr_printjob(smb_dev_t *, intptr_t, int, cred_t *);

int smb_usr_get_ssn(smb_dev_t *, int, intptr_t, int, cred_t *);
int smb_usr_drop_ssn(smb_dev_t *sdp, int cmd);

int smb_usr_get_tree(smb_dev_t *, int, intptr_t, int, cred_t *);
int smb_usr_drop_tree(smb_dev_t *sdp, int cmd);

int smb_usr_iod_work(smb_dev_t *sdp, intptr_t arg, int flags, cred_t *cr);
int smb_usr_iod_ioctl(smb_dev_t *sdp, int cmd, intptr_t arg, int flags);


/*
 * IOD functions
 */
int  smb_iod_create(smb_vc_t *vcp);
int  smb_iod_destroy(smb_vc_t *vcp);
int  smb_iod_connect(smb_vc_t *vcp);
void smb_iod_disconnect(smb_vc_t *vcp);
int  smb_iod_addrq(struct smb_rq *rqp);
int  smb_iod_multirq(struct smb_rq *rqp);
int  smb_iod_waitrq(struct smb_rq *rqp);
void smb_iod_removerq(struct smb_rq *rqp);
void smb_iod_shutdown_share(smb_share_t *ssp);

void smb_iod_sendall(smb_vc_t *);
int smb_iod_recvall(smb_vc_t *);

int smb_iod_vc_work(smb_vc_t *, cred_t *);
int smb_iod_vc_idle(smb_vc_t *);
int smb_iod_vc_rcfail(smb_vc_t *);
int smb_iod_reconnect(smb_vc_t *);

/*
 * Session level functions
 */
int  smb_sm_init(void);
int  smb_sm_idle(void);
void smb_sm_done(void);

/*
 * VC level functions
 */
void smb_vc_hold(smb_vc_t *vcp);
void smb_vc_rele(smb_vc_t *vcp);
void smb_vc_kill(smb_vc_t *vcp);

int smb_vc_findcreate(smbioc_ossn_t *, smb_cred_t *, smb_vc_t **);
int smb_vc_create(smbioc_ossn_t *ossn, smb_cred_t *scred, smb_vc_t **vcpp);

const char *smb_vc_getpass(smb_vc_t *vcp);
uint16_t smb_vc_nextmid(smb_vc_t *vcp);
void *smb_vc_getipaddr(smb_vc_t *vcp, int *ipvers);

typedef void (*walk_share_func_t)(smb_share_t *);
void smb_vc_walkshares(struct smb_vc *,	walk_share_func_t);

/*
 * share level functions
 */

int smb_share_findcreate(smbioc_tcon_t *, smb_vc_t *,
	smb_share_t **, smb_cred_t *);

void smb_share_hold(smb_share_t *ssp);
void smb_share_rele(smb_share_t *ssp);
void smb_share_kill(smb_share_t *ssp);

void smb_share_invalidate(smb_share_t *ssp);
int  smb_share_tcon(smb_share_t *, smb_cred_t *);

#endif /* _SMB_CONN_H */
