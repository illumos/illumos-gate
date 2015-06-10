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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */
/*
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

#ifndef _SYS_SOCKETVAR_H
#define	_SYS_SOCKETVAR_H

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/t_lock.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/zone.h>
#include <sys/sdt.h>
#include <sys/modctl.h>
#include <sys/atomic.h>
#include <sys/socket.h>
#include <sys/ksocket.h>
#include <sys/kstat.h>

#ifdef _KERNEL
#include <sys/vfs_opreg.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Internal representation of the address used to represent addresses
 * in the loopback transport for AF_UNIX. While the sockaddr_un is used
 * as the sockfs layer address for AF_UNIX the pathnames contained in
 * these addresses are not unique (due to relative pathnames) thus can not
 * be used in the transport.
 *
 * The transport level address consists of a magic number (used to separate the
 * name space for specific and implicit binds). For a specific bind
 * this is followed by a "vnode *" which ensures that all specific binds
 * have a unique transport level address. For implicit binds the latter
 * part of the address is a byte string (of the same length as a pointer)
 * that is assigned by the loopback transport.
 *
 * The uniqueness assumes that the loopback transport has a separate namespace
 * for sockets in order to avoid name conflicts with e.g. TLI use of the
 * same transport.
 */
struct so_ux_addr {
	void	*soua_vp;	/* vnode pointer or assigned by tl */
	uint_t	soua_magic;	/* See below */
};

#define	SOU_MAGIC_EXPLICIT	0x75787670	/* "uxvp" */
#define	SOU_MAGIC_IMPLICIT	0x616e6f6e	/* "anon" */

struct sockaddr_ux {
	sa_family_t		sou_family;	/* AF_UNIX */
	struct so_ux_addr	sou_addr;
};

#if defined(_KERNEL) || defined(_KMEMUSER)

#include <sys/socket_proto.h>

typedef struct sonodeops sonodeops_t;
typedef struct sonode sonode_t;

struct sodirect_s;

/*
 * The sonode represents a socket. A sonode never exist in the file system
 * name space and can not be opened using open() - only the socket, socketpair
 * and accept calls create sonodes.
 *
 * The locking of sockfs uses the so_lock mutex plus the SOLOCKED and
 * SOREADLOCKED flags in so_flag. The mutex protects all the state in the
 * sonode. It is expected that the underlying transport protocol serializes
 * socket operations, so sockfs will not normally not single-thread
 * operations. However, certain sockets, including TPI based ones, can only
 * handle one control operation at a time. The SOLOCKED flag is used to
 * single-thread operations from sockfs users to prevent e.g. multiple bind()
 * calls to operate on the same sonode concurrently. The SOREADLOCKED flag is
 * used to ensure that only one thread sleeps in kstrgetmsg for a given
 * sonode. This is needed to ensure atomic operation for things like
 * MSG_WAITALL.
 *
 * The so_fallback_rwlock is used to ensure that for sockets that can
 * fall back to TPI, the fallback is not initiated until all pending
 * operations have completed.
 *
 * Note that so_lock is sometimes held across calls that might go to sleep
 * (kmem_alloc and soallocproto*). This implies that no other lock in
 * the system should be held when calling into sockfs; from the system call
 * side or from strrput (in case of TPI based sockets). If locks are held
 * while calling into sockfs the system might hang when running low on memory.
 */
struct sonode {
	struct	vnode	*so_vnode;	/* vnode associated with this sonode */

	sonodeops_t 	*so_ops;	/* operations vector for this sonode */
	void		*so_priv;	/* sonode private data */

	krwlock_t	so_fallback_rwlock;
	kmutex_t	so_lock;	/* protects sonode fields */

	kcondvar_t	so_state_cv;	/* synchronize state changes */
	kcondvar_t	so_single_cv;	/* wait due to SOLOCKED */
	kcondvar_t	so_read_cv;	/* wait due to SOREADLOCKED */

	/* These fields are protected by so_lock */

	uint_t		so_state;	/* internal state flags SS_*, below */
	uint_t		so_mode;	/* characteristics on socket. SM_* */
	ushort_t 	so_flag;	/* flags, see below */
	int		so_count;	/* count of opened references */

	sock_connid_t	so_proto_connid; /* protocol generation number */

	ushort_t 	so_error;	/* error affecting connection */

	struct sockparams *so_sockparams;	/* vnode or socket module */
	/* Needed to recreate the same socket for accept */
	short	so_family;
	short	so_type;
	short	so_protocol;
	short	so_version;		/* From so_socket call */

	/* Accept queue */
	kmutex_t	so_acceptq_lock;	/* protects accept queue */
	list_t		so_acceptq_list;	/* pending conns */
	list_t		so_acceptq_defer;	/* deferred conns */
	list_node_t	so_acceptq_node;	/* acceptq list node */
	unsigned int	so_acceptq_len;		/* # of conns (both lists) */
	unsigned int	so_backlog;		/* Listen backlog */
	kcondvar_t	so_acceptq_cv;		/* wait for new conn. */
	struct sonode	*so_listener;		/* parent socket */

	/* Options */
	short	so_options;		/* From socket call, see socket.h */
	struct linger	so_linger;	/* SO_LINGER value */
#define	so_sndbuf	so_proto_props.sopp_txhiwat	/* SO_SNDBUF value */
#define	so_sndlowat	so_proto_props.sopp_txlowat	/* tx low water mark */
#define	so_rcvbuf	so_proto_props.sopp_rxhiwat	/* SO_RCVBUF value */
#define	so_rcvlowat	so_proto_props.sopp_rxlowat	/* rx low water mark */
#define	so_max_addr_len	so_proto_props.sopp_maxaddrlen
#define	so_minpsz	so_proto_props.sopp_minpsz
#define	so_maxpsz	so_proto_props.sopp_maxpsz

	int	so_xpg_rcvbuf;		/* SO_RCVBUF value for XPG4 socket */
	clock_t	so_sndtimeo;		/* send timeout */
	clock_t	so_rcvtimeo;		/* recv timeout */

	mblk_t	*so_oobmsg;		/* outofline oob data */
	ssize_t	so_oobmark;		/* offset of the oob data */

	pid_t	so_pgrp;		/* pgrp for signals */

	cred_t		*so_peercred;	/* connected socket peer cred */
	pid_t		so_cpid;	/* connected socket peer cached pid */
	zoneid_t	so_zoneid;	/* opener's zoneid */

	struct pollhead	so_poll_list;	/* common pollhead */
	short		so_pollev;	/* events that should be generated */

	/* Receive */
	unsigned int	so_rcv_queued;	/* # bytes on both rcv lists */
	mblk_t		*so_rcv_q_head;	/* processing/copyout rcv queue */
	mblk_t		*so_rcv_q_last_head;
	mblk_t		*so_rcv_head;	/* protocol prequeue */
	mblk_t		*so_rcv_last_head;	/* last mblk in b_next chain */
	kcondvar_t	so_rcv_cv;	/* wait for data */
	uint_t		so_rcv_wanted;	/* # of bytes wanted by app */
	timeout_id_t	so_rcv_timer_tid;

#define	so_rcv_thresh	so_proto_props.sopp_rcvthresh
#define	so_rcv_timer_interval so_proto_props.sopp_rcvtimer

	kcondvar_t	so_snd_cv;	/* wait for snd buffers */
	uint32_t
		so_snd_qfull: 1,	/* Transmit full */
		so_rcv_wakeup: 1,
		so_snd_wakeup: 1,
		so_not_str: 1,	/* B_TRUE if not streams based socket */
		so_pad_to_bit_31: 28;

	/* Communication channel with protocol */
	sock_lower_handle_t	so_proto_handle;
	sock_downcalls_t 	*so_downcalls;

	struct sock_proto_props	so_proto_props; /* protocol settings */
	boolean_t		so_flowctrld;	/* Flow controlled */
	uint_t			so_copyflag;	/* Copy related flag */
	kcondvar_t		so_copy_cv;	/* Copy cond variable */

	/* kernel sockets */
	ksocket_callbacks_t 	so_ksock_callbacks;
	void			*so_ksock_cb_arg;	/* callback argument */
	kcondvar_t		so_closing_cv;

	/* != NULL for sodirect enabled socket */
	struct sodirect_s	*so_direct;

	/* socket filters */
	uint_t			so_filter_active;	/* # of active fil */
	uint_t			so_filter_tx;		/* pending tx ops */
	struct sof_instance	*so_filter_top;		/* top of stack */
	struct sof_instance	*so_filter_bottom;	/* bottom of stack */
	clock_t			so_filter_defertime;	/* time when deferred */
};

#define	SO_HAVE_DATA(so)						\
	/*								\
	 * For the (tid == 0) case we must check so_rcv_{q_,}head	\
	 * rather than (so_rcv_queued > 0), since the latter does not	\
	 * take into account mblks with only control/name information.	\
	 */								\
	((so)->so_rcv_timer_tid == 0 && ((so)->so_rcv_head != NULL ||	\
	(so)->so_rcv_q_head != NULL)) ||				\
	((so)->so_state & SS_CANTRCVMORE)

/*
 * Events handled by the protocol (in case sd_poll is set)
 */
#define	SO_PROTO_POLLEV		(POLLIN|POLLRDNORM|POLLRDBAND)


#endif /* _KERNEL || _KMEMUSER */

/* flags */
#define	SOMOD		0x0001		/* update socket modification time */
#define	SOACC		0x0002		/* update socket access time */

#define	SOLOCKED	0x0010		/* use to serialize open/closes */
#define	SOREADLOCKED	0x0020		/* serialize kstrgetmsg calls */
#define	SOCLONE		0x0040		/* child of clone driver */
#define	SOASYNC_UNBIND	0x0080		/* wait for ACK of async unbind */

#define	SOCK_IS_NONSTR(so)	((so)->so_not_str)

/*
 * Socket state bits.
 */
#define	SS_ISCONNECTED		0x00000001 /* socket connected to a peer */
#define	SS_ISCONNECTING		0x00000002 /* in process, connecting to peer */
#define	SS_ISDISCONNECTING	0x00000004 /* in process of disconnecting */
#define	SS_CANTSENDMORE		0x00000008 /* can't send more data to peer */

#define	SS_CANTRCVMORE		0x00000010 /* can't receive more data */
#define	SS_ISBOUND		0x00000020 /* socket is bound */
#define	SS_NDELAY		0x00000040 /* FNDELAY non-blocking */
#define	SS_NONBLOCK		0x00000080 /* O_NONBLOCK non-blocking */

#define	SS_ASYNC		0x00000100 /* async i/o notify */
#define	SS_ACCEPTCONN		0x00000200 /* listen done */
/*	unused			0x00000400 */	/* was SS_HASCONNIND */
#define	SS_SAVEDEOR		0x00000800 /* Saved MSG_EOR rcv side state */

#define	SS_RCVATMARK		0x00001000 /* at mark on input */
#define	SS_OOBPEND		0x00002000 /* OOB pending or present - poll */
#define	SS_HAVEOOBDATA		0x00004000 /* OOB data present */
#define	SS_HADOOBDATA		0x00008000 /* OOB data consumed */
#define	SS_CLOSING		0x00010000 /* in process of closing */

#define	SS_FIL_DEFER		0x00020000 /* filter deferred notification */
#define	SS_FILOP_OK		0x00040000 /* socket can attach filters */
#define	SS_FIL_RCV_FLOWCTRL	0x00080000 /* filter asserted rcv flow ctrl */
#define	SS_FIL_SND_FLOWCTRL	0x00100000 /* filter asserted snd flow ctrl */
#define	SS_FIL_STOP		0x00200000 /* no more filter actions */

#define	SS_SODIRECT		0x00400000 /* transport supports sodirect */

#define	SS_SENTLASTREADSIG	0x01000000 /* last rx signal has been sent */
#define	SS_SENTLASTWRITESIG	0x02000000 /* last tx signal has been sent */

#define	SS_FALLBACK_DRAIN	0x20000000 /* data was/is being drained */
#define	SS_FALLBACK_PENDING	0x40000000 /* fallback is pending */
#define	SS_FALLBACK_COMP	0x80000000 /* fallback has completed */


/* Set of states when the socket can't be rebound */
#define	SS_CANTREBIND	(SS_ISCONNECTED|SS_ISCONNECTING|SS_ISDISCONNECTING|\
			    SS_CANTSENDMORE|SS_CANTRCVMORE|SS_ACCEPTCONN)

/*
 * Sockets that can fall back to TPI must ensure that fall back is not
 * initiated while a thread is using a socket.
 */
#define	SO_BLOCK_FALLBACK(so, fn)				\
	ASSERT(MUTEX_NOT_HELD(&(so)->so_lock));			\
	rw_enter(&(so)->so_fallback_rwlock, RW_READER);		\
	if ((so)->so_state & (SS_FALLBACK_COMP|SS_FILOP_OK)) {	\
		if ((so)->so_state & SS_FALLBACK_COMP) {	\
			rw_exit(&(so)->so_fallback_rwlock);	\
			return (fn);				\
		} else {					\
			mutex_enter(&(so)->so_lock);		\
			(so)->so_state &= ~SS_FILOP_OK;		\
			mutex_exit(&(so)->so_lock);		\
		}						\
	}

#define	SO_UNBLOCK_FALLBACK(so)	{			\
	rw_exit(&(so)->so_fallback_rwlock);		\
}

#define	SO_SND_FLOWCTRLD(so)	\
	((so)->so_snd_qfull || (so)->so_state & SS_FIL_SND_FLOWCTRL)

/* Poll events */
#define	SO_POLLEV_IN		0x1	/* POLLIN wakeup needed */
#define	SO_POLLEV_ALWAYS	0x2	/* wakeups */

/*
 * Characteristics of sockets. Not changed after the socket is created.
 */
#define	SM_PRIV			0x001	/* privileged for broadcast, raw... */
#define	SM_ATOMIC		0x002	/* atomic data transmission */
#define	SM_ADDR			0x004	/* addresses given with messages */
#define	SM_CONNREQUIRED		0x008	/* connection required by protocol */

#define	SM_FDPASSING		0x010	/* passes file descriptors */
#define	SM_EXDATA		0x020	/* Can handle T_EXDATA_REQ */
#define	SM_OPTDATA		0x040	/* Can handle T_OPTDATA_REQ */
#define	SM_BYTESTREAM		0x080	/* Byte stream - can use M_DATA */

#define	SM_ACCEPTOR_ID		0x100	/* so_acceptor_id is valid */

#define	SM_KERNEL		0x200	/* kernel socket */

/* The modes below are only for non-streams sockets */
#define	SM_ACCEPTSUPP		0x400	/* can handle accept() */
#define	SM_SENDFILESUPP		0x800	/* Private: proto supp sendfile  */

/*
 * Socket versions. Used by the socket library when calling _so_socket().
 */
#define	SOV_STREAM	0	/* Not a socket - just a stream */
#define	SOV_DEFAULT	1	/* Select based on so_default_version */
#define	SOV_SOCKSTREAM	2	/* Socket plus streams operations */
#define	SOV_SOCKBSD	3	/* Socket with no streams operations */
#define	SOV_XPG4_2	4	/* Xnet socket */

#if defined(_KERNEL) || defined(_KMEMUSER)

/*
 * sonode create and destroy functions.
 */
typedef struct sonode *(*so_create_func_t)(struct sockparams *,
    int, int, int, int, int, int *, cred_t *);
typedef void (*so_destroy_func_t)(struct sonode *);

/* STREAM device information */
typedef struct sdev_info {
	char	*sd_devpath;
	int	sd_devpathlen; /* Is 0 if sp_devpath is a static string */
	vnode_t	*sd_vnode;
} sdev_info_t;

#define	SOCKMOD_VERSION_1	1
#define	SOCKMOD_VERSION		2

/* name of the TPI pseudo socket module */
#define	SOTPI_SMOD_NAME		"socktpi"

typedef struct __smod_priv_s {
	so_create_func_t	smodp_sock_create_func;
	so_destroy_func_t	smodp_sock_destroy_func;
	so_proto_fallback_func_t smodp_proto_fallback_func;
	const char		*smodp_fallback_devpath_v4;
	const char		*smodp_fallback_devpath_v6;
} __smod_priv_t;

/*
 * Socket module register information
 */
typedef struct smod_reg_s {
	int		smod_version;
	char		*smod_name;
	size_t		smod_uc_version;
	size_t		smod_dc_version;
	so_proto_create_func_t	smod_proto_create_func;

	/* __smod_priv_data must be NULL */
	__smod_priv_t	*__smod_priv;
} smod_reg_t;

/*
 * Socket module information
 */
typedef struct smod_info {
	int		smod_version;
	char		*smod_name;
	uint_t		smod_refcnt;		/* # of entries */
	size_t		smod_uc_version; 	/* upcall version */
	size_t		smod_dc_version;	/* down call version */
	so_proto_create_func_t	smod_proto_create_func;
	so_proto_fallback_func_t smod_proto_fallback_func;
	const char		*smod_fallback_devpath_v4;
	const char		*smod_fallback_devpath_v6;
	so_create_func_t	smod_sock_create_func;
	so_destroy_func_t	smod_sock_destroy_func;
	list_node_t	smod_node;
} smod_info_t;

typedef struct sockparams_stats {
	kstat_named_t	sps_nfallback;	/* # of fallbacks to TPI */
	kstat_named_t	sps_nactive;	/* # of active sockets */
	kstat_named_t	sps_ncreate;	/* total # of created sockets */
} sockparams_stats_t;

/*
 * sockparams
 *
 * Used for mapping family/type/protocol to a socket module or STREAMS device
 */
struct sockparams {
	/*
	 * The family, type, protocol, sdev_info and smod_name are
	 * set when the entry is created, and they will never change
	 * thereafter.
	 */
	int		sp_family;
	int		sp_type;
	int		sp_protocol;

	sdev_info_t	sp_sdev_info;	/* STREAM device */
	char		*sp_smod_name;	/* socket module name */

	kmutex_t	sp_lock;	/* lock for refcnt and smod_info */
	uint64_t	sp_refcnt;	/* entry reference count */
	smod_info_t	*sp_smod_info;	/* socket module */

	sockparams_stats_t sp_stats;
	kstat_t		*sp_kstat;

	/*
	 * The entries below are only modified while holding
	 * sockconf_lock as a writer.
	 */
	int		sp_flags;	/* see below */
	list_node_t	sp_node;

	list_t		sp_auto_filters; /* list of automatic filters */
	list_t		sp_prog_filters; /* list of programmatic filters */
};

struct sof_entry;

typedef struct sp_filter {
	struct sof_entry *spf_filter;
	list_node_t	spf_node;
} sp_filter_t;


/*
 * sockparams flags
 */
#define	SOCKPARAMS_EPHEMERAL	0x1	/* temp. entry, not on global list */

extern void sockparams_init(void);
extern struct sockparams *sockparams_hold_ephemeral_bydev(int, int, int,
    const char *, int, int *);
extern struct sockparams *sockparams_hold_ephemeral_bymod(int, int, int,
    const char *, int, int *);
extern void sockparams_ephemeral_drop_last_ref(struct sockparams *);

extern struct sockparams *sockparams_create(int, int, int, char *, char *, int,
    int, int, int *);
extern void 	sockparams_destroy(struct sockparams *);
extern int 	sockparams_add(struct sockparams *);
extern int	sockparams_delete(int, int, int);
extern int	sockparams_new_filter(struct sof_entry *);
extern void	sockparams_filter_cleanup(struct sof_entry *);
extern int	sockparams_copyout_socktable(uintptr_t);

extern void smod_init(void);
extern void smod_add(smod_info_t *);
extern int smod_register(const smod_reg_t *);
extern int smod_unregister(const char *);
extern smod_info_t *smod_lookup_byname(const char *);

#define	SOCKPARAMS_HAS_DEVICE(sp)					\
	((sp)->sp_sdev_info.sd_devpath != NULL)

/* Increase the smod_info_t reference count */
#define	SMOD_INC_REF(smodp) {						\
	ASSERT((smodp) != NULL);					\
	DTRACE_PROBE1(smodinfo__inc__ref, struct smod_info *, (smodp));	\
	atomic_inc_uint(&(smodp)->smod_refcnt);				\
}

/*
 * Decreace the socket module entry reference count.
 * When no one mapping to the entry, we try to unload the module from the
 * kernel. If the module can't unload, just leave the module entry with
 * a zero refcnt.
 */
#define	SMOD_DEC_REF(smodp, modname) {					\
	ASSERT((smodp) != NULL);					\
	ASSERT((smodp)->smod_refcnt != 0);				\
	atomic_dec_uint(&(smodp)->smod_refcnt);				\
	/*								\
	 * No need to atomically check the return value because the	\
	 * socket module framework will verify that no one is using	\
	 * the module before unloading. Worst thing that can happen	\
	 * here is multiple calls to mod_remove_by_name(), which is OK.	\
	 */								\
	if ((smodp)->smod_refcnt == 0)					\
		(void) mod_remove_by_name(modname);			\
}

/* Increase the reference count */
#define	SOCKPARAMS_INC_REF(sp) {					\
	ASSERT((sp) != NULL);						\
	DTRACE_PROBE1(sockparams__inc__ref, struct sockparams *, (sp));	\
	mutex_enter(&(sp)->sp_lock);					\
	(sp)->sp_refcnt++;						\
	ASSERT((sp)->sp_refcnt != 0);					\
	mutex_exit(&(sp)->sp_lock);					\
}

/*
 * Decrease the reference count.
 *
 * If the sockparams is ephemeral, then the thread dropping the last ref
 * count will destroy the entry.
 */
#define	SOCKPARAMS_DEC_REF(sp) {					\
	ASSERT((sp) != NULL);						\
	DTRACE_PROBE1(sockparams__dec__ref, struct sockparams *, (sp));	\
	mutex_enter(&(sp)->sp_lock);					\
	ASSERT((sp)->sp_refcnt > 0);					\
	if ((sp)->sp_refcnt == 1) {					\
		if ((sp)->sp_flags & SOCKPARAMS_EPHEMERAL) {		\
			mutex_exit(&(sp)->sp_lock);			\
			sockparams_ephemeral_drop_last_ref((sp));	\
		} else {						\
			(sp)->sp_refcnt--;				\
			if ((sp)->sp_smod_info != NULL) {		\
				SMOD_DEC_REF((sp)->sp_smod_info,	\
				    (sp)->sp_smod_name);		\
			}						\
			(sp)->sp_smod_info = NULL;			\
			mutex_exit(&(sp)->sp_lock);			\
		}							\
	} else {							\
		(sp)->sp_refcnt--;					\
		mutex_exit(&(sp)->sp_lock);				\
	}								\
}

/*
 * Used to traverse the list of AF_UNIX sockets to construct the kstat
 * for netstat(1m).
 */
struct socklist {
	kmutex_t	sl_lock;
	struct sonode	*sl_list;
};

extern struct socklist socklist;
/*
 * ss_full_waits is the number of times the reader thread
 * waits when the queue is full and ss_empty_waits is the number
 * of times the consumer thread waits when the queue is empty.
 * No locks for these as they are just indicators of whether
 * disk or network or both is slow or fast.
 */
struct sendfile_stats {
	uint32_t ss_file_cached;
	uint32_t ss_file_not_cached;
	uint32_t ss_full_waits;
	uint32_t ss_empty_waits;
	uint32_t ss_file_segmap;
};

/*
 * A single sendfile request is represented by snf_req.
 */
typedef struct snf_req {
	struct snf_req	*sr_next;
	mblk_t		*sr_mp_head;
	mblk_t		*sr_mp_tail;
	kmutex_t	sr_lock;
	kcondvar_t	sr_cv;
	uint_t		sr_qlen;
	int		sr_hiwat;
	int		sr_lowat;
	int		sr_operation;
	struct vnode	*sr_vp;
	file_t 		*sr_fp;
	ssize_t		sr_maxpsz;
	u_offset_t	sr_file_off;
	u_offset_t	sr_file_size;
#define	SR_READ_DONE	0x80000000
	int		sr_read_error;
	int		sr_write_error;
} snf_req_t;

/* A queue of sendfile requests */
struct sendfile_queue {
	snf_req_t	*snfq_req_head;
	snf_req_t	*snfq_req_tail;
	kmutex_t	snfq_lock;
	kcondvar_t	snfq_cv;
	int		snfq_svc_threads;	/* # of service threads */
	int		snfq_idle_cnt;		/* # of idling threads */
	int		snfq_max_threads;
	int		snfq_req_cnt;		/* Number of requests */
};

#define	READ_OP			1
#define	SNFQ_TIMEOUT		(60 * 5 * hz)	/* 5 minutes */

/* Socket network operations switch */
struct sonodeops {
	int 	(*sop_init)(struct sonode *, struct sonode *, cred_t *,
		    int);
	int	(*sop_accept)(struct sonode *, int, cred_t *, struct sonode **);
	int	(*sop_bind)(struct sonode *, struct sockaddr *, socklen_t,
		    int, cred_t *);
	int	(*sop_listen)(struct sonode *, int, cred_t *);
	int	(*sop_connect)(struct sonode *, struct sockaddr *,
		    socklen_t, int, int, cred_t *);
	int	(*sop_recvmsg)(struct sonode *, struct msghdr *,
		    struct uio *, cred_t *);
	int	(*sop_sendmsg)(struct sonode *, struct msghdr *,
		    struct uio *, cred_t *);
	int	(*sop_sendmblk)(struct sonode *, struct msghdr *, int,
		    cred_t *, mblk_t **);
	int	(*sop_getpeername)(struct sonode *, struct sockaddr *,
		    socklen_t *, boolean_t, cred_t *);
	int	(*sop_getsockname)(struct sonode *, struct sockaddr *,
		    socklen_t *, cred_t *);
	int	(*sop_shutdown)(struct sonode *, int, cred_t *);
	int	(*sop_getsockopt)(struct sonode *, int, int, void *,
		    socklen_t *, int, cred_t *);
	int 	(*sop_setsockopt)(struct sonode *, int, int, const void *,
		    socklen_t, cred_t *);
	int 	(*sop_ioctl)(struct sonode *, int, intptr_t, int,
		    cred_t *, int32_t *);
	int 	(*sop_poll)(struct sonode *, short, int, short *,
		    struct pollhead **);
	int 	(*sop_close)(struct sonode *, int, cred_t *);
};

#define	SOP_INIT(so, flag, cr, flags)	\
	((so)->so_ops->sop_init((so), (flag), (cr), (flags)))
#define	SOP_ACCEPT(so, fflag, cr, nsop)	\
	((so)->so_ops->sop_accept((so), (fflag), (cr), (nsop)))
#define	SOP_BIND(so, name, namelen, flags, cr)	\
	((so)->so_ops->sop_bind((so), (name), (namelen), (flags), (cr)))
#define	SOP_LISTEN(so, backlog, cr)	\
	((so)->so_ops->sop_listen((so), (backlog), (cr)))
#define	SOP_CONNECT(so, name, namelen, fflag, flags, cr)	\
	((so)->so_ops->sop_connect((so), (name), (namelen), (fflag), (flags), \
	(cr)))
#define	SOP_RECVMSG(so, msg, uiop, cr)	\
	((so)->so_ops->sop_recvmsg((so), (msg), (uiop), (cr)))
#define	SOP_SENDMSG(so, msg, uiop, cr)	\
	((so)->so_ops->sop_sendmsg((so), (msg), (uiop), (cr)))
#define	SOP_SENDMBLK(so, msg, size, cr, mpp)	\
	((so)->so_ops->sop_sendmblk((so), (msg), (size), (cr), (mpp)))
#define	SOP_GETPEERNAME(so, addr, addrlen, accept, cr)	\
	((so)->so_ops->sop_getpeername((so), (addr), (addrlen), (accept), (cr)))
#define	SOP_GETSOCKNAME(so, addr, addrlen, cr)	\
	((so)->so_ops->sop_getsockname((so), (addr), (addrlen), (cr)))
#define	SOP_SHUTDOWN(so, how, cr)	\
	((so)->so_ops->sop_shutdown((so), (how), (cr)))
#define	SOP_GETSOCKOPT(so, level, optionname, optval, optlenp, flags, cr) \
	((so)->so_ops->sop_getsockopt((so), (level), (optionname),	\
	    (optval), (optlenp), (flags), (cr)))
#define	SOP_SETSOCKOPT(so, level, optionname, optval, optlen, cr)	\
	((so)->so_ops->sop_setsockopt((so), (level), (optionname),	\
	    (optval), (optlen), (cr)))
#define	SOP_IOCTL(so, cmd, arg, mode, cr, rvalp)	\
	((so)->so_ops->sop_ioctl((so), (cmd), (arg), (mode), (cr), (rvalp)))
#define	SOP_POLL(so, events, anyyet, reventsp, phpp) \
	((so)->so_ops->sop_poll((so), (events), (anyyet), (reventsp), (phpp)))
#define	SOP_CLOSE(so, flag, cr)	\
	((so)->so_ops->sop_close((so), (flag), (cr)))

#endif /* defined(_KERNEL) || defined(_KMEMUSER) */

#ifdef _KERNEL

#define	ISALIGNED_cmsghdr(addr) \
		(((uintptr_t)(addr) & (_CMSG_HDR_ALIGNMENT - 1)) == 0)

#define	ROUNDUP_cmsglen(len) \
	(((len) + _CMSG_HDR_ALIGNMENT - 1) & ~(_CMSG_HDR_ALIGNMENT - 1))

#define	IS_NON_STREAM_SOCK(vp) \
	((vp)->v_type == VSOCK && (vp)->v_stream == NULL)
/*
 * Macros that operate on struct cmsghdr.
 * Used in parsing msg_control.
 * The CMSG_VALID macro does not assume that the last option buffer is padded.
 */
#define	CMSG_NEXT(cmsg)						\
	(struct cmsghdr *)((uintptr_t)(cmsg) +			\
	    ROUNDUP_cmsglen((cmsg)->cmsg_len))
#define	CMSG_CONTENT(cmsg)	(&((cmsg)[1]))
#define	CMSG_CONTENTLEN(cmsg)	((cmsg)->cmsg_len - sizeof (struct cmsghdr))
#define	CMSG_VALID(cmsg, start, end)					\
	(ISALIGNED_cmsghdr(cmsg) &&					\
	((uintptr_t)(cmsg) >= (uintptr_t)(start)) &&			\
	((uintptr_t)(cmsg) < (uintptr_t)(end)) &&			\
	((ssize_t)(cmsg)->cmsg_len >= sizeof (struct cmsghdr)) &&	\
	((uintptr_t)(cmsg) + (cmsg)->cmsg_len <= (uintptr_t)(end)))

/*
 * Maximum size of any argument that is copied in (addresses, options,
 * access rights). MUST be at least MAXPATHLEN + 3.
 * BSD and SunOS 4.X limited this to MLEN or MCLBYTES.
 */
#define	SO_MAXARGSIZE	8192

/*
 * Convert between vnode and sonode
 */
#define	VTOSO(vp)	((struct sonode *)((vp)->v_data))
#define	SOTOV(sp)	((sp)->so_vnode)

/*
 * Internal flags for sobind()
 */
#define	_SOBIND_REBIND		0x01	/* Bind to existing local address */
#define	_SOBIND_UNSPEC		0x02	/* Bind to unspecified address */
#define	_SOBIND_LOCK_HELD	0x04	/* so_excl_lock held by caller */
#define	_SOBIND_NOXLATE		0x08	/* No addr translation for AF_UNIX */
#define	_SOBIND_XPG4_2		0x10	/* xpg4.2 semantics */
#define	_SOBIND_SOCKBSD		0x20	/* BSD semantics */
#define	_SOBIND_LISTEN		0x40	/* Make into SS_ACCEPTCONN */
#define	_SOBIND_SOCKETPAIR	0x80	/* Internal flag for so_socketpair() */
					/* to enable listen with backlog = 1 */

/*
 * Internal flags for sounbind()
 */
#define	_SOUNBIND_REBIND	0x01	/* Don't clear fields - will rebind */

/*
 * Internal flags for soconnect()
 */
#define	_SOCONNECT_NOXLATE	0x01	/* No addr translation for AF_UNIX */
#define	_SOCONNECT_DID_BIND	0x02	/* Unbind when connect fails */
#define	_SOCONNECT_XPG4_2	0x04	/* xpg4.2 semantics */

/*
 * Internal flags for sodisconnect()
 */
#define	_SODISCONNECT_LOCK_HELD	0x01	/* so_excl_lock held by caller */

/*
 * Internal flags for sotpi_getsockopt().
 */
#define	_SOGETSOCKOPT_XPG4_2	0x01	/* xpg4.2 semantics */

/*
 * Internal flags for soallocproto*()
 */
#define	_ALLOC_NOSLEEP		0	/* Don't sleep for memory */
#define	_ALLOC_INTR		1	/* Sleep until interrupt */
#define	_ALLOC_SLEEP		2	/* Sleep forever */

/*
 * Internal structure for handling AF_UNIX file descriptor passing
 */
struct fdbuf {
	int		fd_size;	/* In bytes, for kmem_free */
	int		fd_numfd;	/* Number of elements below */
	char		*fd_ebuf;	/* Extra buffer to free  */
	int		fd_ebuflen;
	frtn_t		fd_frtn;
	struct file	*fd_fds[1];	/* One or more */
};
#define	FDBUF_HDRSIZE	(sizeof (struct fdbuf) - sizeof (struct file *))

/*
 * Variable that can be patched to set what version of socket socket()
 * will create.
 */
extern int so_default_version;

#ifdef DEBUG
/* Turn on extra testing capabilities */
#define	SOCK_TEST
#endif /* DEBUG */

#ifdef DEBUG
char	*pr_state(uint_t, uint_t);
char	*pr_addr(int, struct sockaddr *, t_uscalar_t);
int	so_verify_oobstate(struct sonode *);
#endif /* DEBUG */

/*
 * DEBUG macros
 */
#if defined(DEBUG)
#define	SOCK_DEBUG

extern int sockdebug;
extern int sockprinterr;

#define	eprint(args)	printf args
#define	eprintso(so, args) \
{ if (sockprinterr && ((so)->so_options & SO_DEBUG)) printf args; }
#define	eprintline(error)					\
{								\
	if (error != EINTR && (sockprinterr || sockdebug > 0))	\
		printf("socket error %d: line %d file %s\n",	\
			(error), __LINE__, __FILE__);		\
}

#define	eprintsoline(so, error)					\
{ if (sockprinterr && ((so)->so_options & SO_DEBUG))		\
	printf("socket(%p) error %d: line %d file %s\n",	\
		(void *)(so), (error), __LINE__, __FILE__);	\
}
#define	dprint(level, args)	{ if (sockdebug > (level)) printf args; }
#define	dprintso(so, level, args) \
{ if (sockdebug > (level) && ((so)->so_options & SO_DEBUG)) printf args; }

#else /* define(DEBUG) */

#define	eprint(args)		{}
#define	eprintso(so, args)	{}
#define	eprintline(error)	{}
#define	eprintsoline(so, error)	{}
#define	dprint(level, args)	{}
#define	dprintso(so, level, args) {}

#endif /* defined(DEBUG) */

extern struct vfsops			sock_vfsops;
extern struct vnodeops			*socket_vnodeops;
extern const struct fs_operation_def	socket_vnodeops_template[];

extern dev_t				sockdev;

extern krwlock_t			sockconf_lock;

/*
 * sockfs functions
 */
extern int	sock_getmsg(vnode_t *, struct strbuf *, struct strbuf *,
			uchar_t *, int *, int, rval_t *);
extern int	sock_putmsg(vnode_t *, struct strbuf *, struct strbuf *,
			uchar_t, int, int);
extern int	sogetvp(char *, vnode_t **, int);
extern int	sockinit(int, char *);
extern int	solookup(int, int, int, struct sockparams **);
extern void	so_lock_single(struct sonode *);
extern void	so_unlock_single(struct sonode *, int);
extern int	so_lock_read(struct sonode *, int);
extern int	so_lock_read_intr(struct sonode *, int);
extern void	so_unlock_read(struct sonode *);
extern void	*sogetoff(mblk_t *, t_uscalar_t, t_uscalar_t, uint_t);
extern void	so_getopt_srcaddr(void *, t_uscalar_t,
			void **, t_uscalar_t *);
extern int	so_getopt_unix_close(void *, t_uscalar_t);
extern void	fdbuf_free(struct fdbuf *);
extern mblk_t	*fdbuf_allocmsg(int, struct fdbuf *);
extern int	fdbuf_create(void *, int, struct fdbuf **);
extern void	so_closefds(void *, t_uscalar_t, int, int);
extern int	so_getfdopt(void *, t_uscalar_t, int, void **, int *);
t_uscalar_t	so_optlen(void *, t_uscalar_t, int);
extern void	so_cmsg2opt(void *, t_uscalar_t, int, mblk_t *);
extern t_uscalar_t
		so_cmsglen(mblk_t *, void *, t_uscalar_t, int);
extern int	so_opt2cmsg(mblk_t *, void *, t_uscalar_t, int,
			void *, t_uscalar_t);
extern void	soisconnecting(struct sonode *);
extern void	soisconnected(struct sonode *);
extern void	soisdisconnected(struct sonode *, int);
extern void	socantsendmore(struct sonode *);
extern void	socantrcvmore(struct sonode *);
extern void	soseterror(struct sonode *, int);
extern int	sogeterr(struct sonode *, boolean_t);
extern int	sowaitconnected(struct sonode *, int, int);

extern ssize_t	soreadfile(file_t *, uchar_t *, u_offset_t, int *, size_t);
extern void	*sock_kstat_init(zoneid_t);
extern void	sock_kstat_fini(zoneid_t, void *);
extern struct sonode *getsonode(int, int *, file_t **);
/*
 * Function wrappers (mostly around the sonode switch) for
 * backward compatibility.
 */
extern int	soaccept(struct sonode *, int, struct sonode **);
extern int	sobind(struct sonode *, struct sockaddr *, socklen_t,
		    int, int);
extern int	solisten(struct sonode *, int);
extern int	soconnect(struct sonode *, struct sockaddr *, socklen_t,
		    int, int);
extern int	sorecvmsg(struct sonode *, struct nmsghdr *, struct uio *);
extern int	sosendmsg(struct sonode *, struct nmsghdr *, struct uio *);
extern int	soshutdown(struct sonode *, int);
extern int	sogetsockopt(struct sonode *, int, int, void *, socklen_t *,
		    int);
extern int	sosetsockopt(struct sonode *, int, int, const void *,
		    t_uscalar_t);

extern struct sonode	*socreate(struct sockparams *, int, int, int, int,
			    int *);

extern int	so_copyin(const void *, void *, size_t, int);
extern int	so_copyout(const void *, void *, size_t, int);

#endif

/*
 * Internal structure for obtaining sonode information from the socklist.
 * These types match those corresponding in the sonode structure.
 * This is not a published interface, and may change at any time.
 */
struct sockinfo {
	uint_t		si_size;		/* real length of this struct */
	short		si_family;
	short		si_type;
	ushort_t	si_flag;
	uint_t		si_state;
	uint_t		si_ux_laddr_sou_magic;
	uint_t		si_ux_faddr_sou_magic;
	t_scalar_t	si_serv_type;
	t_uscalar_t	si_laddr_soa_len;
	t_uscalar_t	si_faddr_soa_len;
	uint16_t	si_laddr_family;
	uint16_t	si_faddr_family;
	char		si_laddr_sun_path[MAXPATHLEN + 1]; /* NULL terminated */
	char		si_faddr_sun_path[MAXPATHLEN + 1];
	boolean_t	si_faddr_noxlate;
	zoneid_t	si_szoneid;
};

/*
 * Subcodes for sockconf() system call
 */
#define	SOCKCONFIG_ADD_SOCK		0
#define	SOCKCONFIG_REMOVE_SOCK		1
#define	SOCKCONFIG_ADD_FILTER		2
#define	SOCKCONFIG_REMOVE_FILTER	3
#define	SOCKCONFIG_GET_SOCKTABLE	4

/*
 * Data structures for configuring socket filters.
 */

/*
 * Placement hint for automatic filters
 */
typedef enum {
	SOF_HINT_NONE,
	SOF_HINT_TOP,
	SOF_HINT_BOTTOM,
	SOF_HINT_BEFORE,
	SOF_HINT_AFTER
} sof_hint_t;

/*
 * Socket tuple. Used by sockconfig_filter_props to list socket
 * types of interest.
 */
typedef struct sof_socktuple {
	int	sofst_family;
	int	sofst_type;
	int	sofst_protocol;
} sof_socktuple_t;

/*
 * Socket filter properties used by sockconfig() system call.
 */
struct sockconfig_filter_props {
	char		*sfp_modname;
	boolean_t	sfp_autoattach;
	sof_hint_t	sfp_hint;
	char		*sfp_hintarg;
	uint_t		sfp_socktuple_cnt;
	sof_socktuple_t	*sfp_socktuple;
};

/*
 * Data structures for the in-kernel socket configuration table.
 */
typedef struct sockconfig_socktable_entry {
	int		se_family;
	int		se_type;
	int		se_protocol;
	int		se_refcnt;
	int		se_flags;
	char		se_modname[MODMAXNAMELEN];
	char		se_strdev[MAXPATHLEN];
} sockconfig_socktable_entry_t;

typedef struct sockconfig_socktable {
	uint_t		num_of_entries;
	sockconfig_socktable_entry_t *st_entries;
} sockconfig_socktable_t;

#ifdef	_SYSCALL32

typedef struct sof_socktuple32 {
	int32_t	sofst_family;
	int32_t	sofst_type;
	int32_t	sofst_protocol;
} sof_socktuple32_t;

struct sockconfig_filter_props32 {
	caddr32_t	sfp_modname;
	boolean_t	sfp_autoattach;
	sof_hint_t	sfp_hint;
	caddr32_t	sfp_hintarg;
	uint32_t	sfp_socktuple_cnt;
	caddr32_t	sfp_socktuple;
};

typedef struct sockconfig_socktable32 {
	uint_t		num_of_entries;
	caddr32_t	st_entries;
} sockconfig_socktable32_t;

#endif	/* _SYSCALL32 */

#define	SOCKMOD_PATH	"socketmod"	/* dir where sockmods are stored */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SOCKETVAR_H */
