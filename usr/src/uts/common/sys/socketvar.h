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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include <sys/sodirect.h>
#include <inet/kssl/ksslapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Internal representation used for addresses.
 */
struct soaddr {
	struct sockaddr	*soa_sa;	/* Actual address */
	t_uscalar_t	soa_len;	/* Length in bytes for kmem_free */
	t_uscalar_t	soa_maxlen;	/* Allocated length */
};
/* Maximum size address for transports that have ADDR_size == 1 */
#define	SOA_DEFSIZE	128

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

typedef struct sonodeops sonodeops_t;
typedef struct sonode sonode_t;

/*
 * The sonode represents a socket. A sonode never exist in the file system
 * name space and can not be opened using open() - only the socket, socketpair
 * and accept calls create sonodes.
 *
 * When an AF_UNIX socket is bound to a pathname the sockfs
 * creates a VSOCK vnode in the underlying file system. However, the vnodeops
 * etc in this VNODE remain those of the underlying file system.
 * Sockfs uses the v_stream pointer in the underlying file system VSOCK node
 * to find the sonode bound to the pathname. The bound pathname vnode
 * is accessed through so_ux_vp.
 *
 * A socket always corresponds to a VCHR stream representing the transport
 * provider (e.g. /dev/tcp). This information is retrieved from the kernel
 * socket configuration table and entered into so_accessvp. sockfs uses
 * this to perform VOP_ACCESS checks before allowing an open of the transport
 * provider.
 *
 * The locking of sockfs uses the so_lock mutex plus the SOLOCKED
 * and SOREADLOCKED flags in so_flag. The mutex protects all the state
 * in the sonode. The SOLOCKED flag is used to single-thread operations from
 * sockfs users to prevent e.g. multiple bind() calls to operate on the
 * same sonode concurrently. The SOREADLOCKED flag is used to ensure that
 * only one thread sleeps in kstrgetmsg for a given sonode. This is needed
 * to ensure atomic operation for things like MSG_WAITALL.
 *
 * Note that so_lock is sometimes held across calls that might go to sleep
 * (kmem_alloc and soallocproto*). This implies that no other lock in
 * the system should be held when calling into sockfs; from the system call
 * side or from strrput. If locks are held while calling into sockfs
 * the system might hang when running low on memory.
 */
struct sonode {
	struct	vnode	*so_vnode;	/* vnode associated with this sonode */

	sonodeops_t	*so_ops;	/* operations vector for this sonode */

	/*
	 * These fields are initialized once.
	 */
	dev_t		so_dev;		/* device the sonode represents */
	struct	vnode	*so_accessvp;	/* vnode for the /dev entry */

	/* The locks themselves */
	kmutex_t	so_lock;	/* protects sonode fields */
	kmutex_t	so_plumb_lock;	/* serializes plumbs, and the related */
					/* fields so_version and so_pushcnt */
	kcondvar_t	so_state_cv;	/* synchronize state changes */
	kcondvar_t	so_ack_cv;	/* wait for TPI acks */
	kcondvar_t	so_connind_cv;	/* wait for T_CONN_IND */
	kcondvar_t	so_want_cv;	/* wait due to SOLOCKED */

	/* These fields are protected by so_lock */
	uint_t	so_state;		/* internal state flags SS_*, below */
	uint_t	so_mode;		/* characteristics on socket. SM_* */

	mblk_t	*so_ack_mp;		/* TPI ack received from below */
	mblk_t	*so_conn_ind_head;	/* b_next list of T_CONN_IND */
	mblk_t	*so_conn_ind_tail;
	mblk_t	*so_unbind_mp;		/* Preallocated T_UNBIND_REQ message */

	ushort_t so_flag;		/* flags, see below */
	dev_t	so_fsid;		/* file system identifier */
	time_t  so_atime;		/* time of last access */
	time_t  so_mtime;		/* time of last modification */
	time_t  so_ctime;		/* time of last attributes change */
	int	so_count;		/* count of opened references */

	/* Needed to recreate the same socket for accept */
	short	so_family;
	short	so_type;
	short	so_protocol;
	short	so_version;		/* From so_socket call */
	short	so_pushcnt;		/* Number of modules above "sockmod" */

	/* Options */
	short	so_options;		/* From socket call, see socket.h */
	struct linger	so_linger;	/* SO_LINGER value */
	int	so_sndbuf;		/* SO_SNDBUF value */
	int	so_rcvbuf;		/* SO_RCVBUF value */
	int	so_sndlowat;		/* send low water mark */
	int	so_rcvlowat;		/* receive low water mark */
#ifdef notyet
	int	so_sndtimeo;		/* Not yet implemented */
	int	so_rcvtimeo;		/* Not yet implemented */
#endif /* notyet */
	ushort_t so_error;		/* error affecting connection */
	ushort_t so_delayed_error;	/* From T_uderror_ind */
	int	so_backlog;		/* Listen backlog */

	/*
	 * The counts (so_oobcnt and so_oobsigcnt) track the number of
	 * urgent indicates that are (logically) queued on the stream head
	 * read queue. The urgent data is queued on the stream head
	 * as follows.
	 *
	 * In the normal case the SIGURG is not generated until
	 * the T_EXDATA_IND arrives at the stream head. However, transports
	 * that have an early indication that urgent data is pending
	 * (e.g. TCP receiving a "new" urgent pointer value) can send up
	 * an M_PCPROTO/SIGURG message to generate the signal early.
	 *
	 * The mark is indicated by either:
	 *  - a T_EXDATA_IND (with no M_DATA b_cont) with MSGMARK set.
	 *    When this message is consumed by sorecvmsg the socket layer
	 *    sets SS_RCVATMARK until data has been consumed past the mark.
	 *  - a message with MSGMARKNEXT set (indicating that the
	 *    first byte of the next message constitutes the mark). When
	 *    the last byte of the MSGMARKNEXT message is consumed in
	 *    the stream head the stream head sets STRATMARK. This flag
	 *    is cleared when at least one byte is read. (Note that
	 *    the MSGMARKNEXT messages can be of zero length when there
	 *    is no previous data to which the marknext can be attached.)
	 *
	 * While the T_EXDATA_IND method is the common case which is used
	 * with all TPI transports, the MSGMARKNEXT method is needed to
	 * indicate the mark when e.g. the TCP urgent byte has not been
	 * received yet but the TCP urgent pointer has made TCP generate
	 * the M_PCSIG/SIGURG.
	 *
	 * The signal (the M_PCSIG carrying the SIGURG) and the mark
	 * indication can not be delivered as a single message, since
	 * the signal should be delivered as high priority and any mark
	 * indication must flow with the data. This implies that immediately
	 * when the SIGURG has been delivered if the stream head queue is
	 * empty it is impossible to determine if this will be the position
	 * of the mark. This race condition is resolved by using MSGNOTMARKNEXT
	 * messages and the STRNOTATMARK flag in the stream head. The
	 * SIOCATMARK code calls the stream head to wait for either a
	 * non-empty queue or one of the STR*ATMARK flags being set.
	 * This implies that any transport that is sending M_PCSIG(SIGURG)
	 * should send the appropriate MSGNOTMARKNEXT message (which can be
	 * zero length) after sending an M_PCSIG to prevent SIOCATMARK
	 * from sleeping unnecessarily.
	 */
	mblk_t	*so_oobmsg;		/* outofline oob data */
	uint_t	so_oobsigcnt;		/* Number of SIGURG generated */
	uint_t	so_oobcnt;		/* Number of T_EXDATA_IND queued */
	pid_t	so_pgrp;		/* pgrp for signals */

	/* From T_info_ack */
	t_uscalar_t	so_tsdu_size;
	t_uscalar_t	so_etsdu_size;
	t_scalar_t	so_addr_size;
	t_uscalar_t	so_opt_size;
	t_uscalar_t	so_tidu_size;
	t_scalar_t	so_serv_type;

	/* From T_capability_ack */
	t_uscalar_t	so_acceptor_id;

	/* Internal provider information */
	struct tpi_provinfo	*so_provinfo;

	/*
	 * The local and remote addresses have multiple purposes
	 * but one of the key reasons for their existence and careful
	 * tracking in sockfs is to support getsockname and getpeername
	 * when the transport does not handle the TI_GET*NAME ioctls
	 * and caching when it does (signaled by valid bits in so_state).
	 * When all transports support the new TPI (with T_ADDR_REQ)
	 * we can revisit this code.
	 * The other usage of so_faddr is to keep the "connected to"
	 * address for datagram sockets.
	 * Finally, for AF_UNIX both local and remote addresses are used
	 * to record the sockaddr_un since we use a separate namespace
	 * in the loopback transport.
	 */
	struct soaddr so_laddr;		/* Local address */
	struct soaddr so_faddr;		/* Peer address */
#define	so_laddr_sa	so_laddr.soa_sa
#define	so_faddr_sa	so_faddr.soa_sa
#define	so_laddr_len	so_laddr.soa_len
#define	so_faddr_len	so_faddr.soa_len
#define	so_laddr_maxlen	so_laddr.soa_maxlen
#define	so_faddr_maxlen	so_faddr.soa_maxlen
	mblk_t		*so_eaddr_mp;	/* for so_delayed_error */

	/*
	 * For AF_UNIX sockets:
	 * so_ux_laddr/faddr records the internal addresses used with the
	 * transport.
	 * so_ux_vp and v_stream->sd_vnode form the cross-
	 * linkage between the underlying fs vnode corresponding to
	 * the bound sockaddr_un and the socket node.
	 */
	struct so_ux_addr so_ux_laddr;	/* laddr bound with the transport */
	struct so_ux_addr so_ux_faddr;	/* temporary peer address */
	struct vnode	*so_ux_bound_vp; /* bound AF_UNIX file system vnode */
	struct sonode	*so_next;	/* next sonode on socklist	*/
	struct sonode	*so_prev;	/* previous sonode on socklist	*/
	mblk_t	*so_discon_ind_mp;	/* T_DISCON_IND received from below */

					/* put here for delayed processing  */
	void		*so_priv;	/* sonode private data */
	cred_t		*so_peercred;	/* connected socket peer cred */
	pid_t		so_cpid;	/* connected socket peer cached pid */
	zoneid_t	so_zoneid;	/* opener's zoneid */

	kmem_cache_t	*so_cache;	/* object cache of this "sonode". */
	void		*so_obj;	/* object to free */

	/*
	 * For NL7C sockets:
	 *
	 * so_nl7c_flags	the NL7C state of URL processing.
	 *
	 * so_nl7c_rcv_mp	mblk_t chain of already received data to be
	 *			passed up to the app after NL7C gives up on
	 *			a socket.
	 *
	 * so_nl7c_rcv_rval	returned rval for last mblk_t from above.
	 *
	 * so_nl7c_uri		the URI currently being processed.
	 *
	 * so_nl7c_rtime	URI request gethrestime_sec().
	 *
	 * so_nl7c_addr		pointer returned by nl7c_addr_lookup().
	 */
	uint64_t	so_nl7c_flags;
	mblk_t		*so_nl7c_rcv_mp;
	int64_t		so_nl7c_rcv_rval;
	void		*so_nl7c_uri;
	time_t		so_nl7c_rtime;
	void		*so_nl7c_addr;

	/* For sockets acting as an in-kernel SSL proxy */
	kssl_endpt_type_t	so_kssl_type;	/* is proxy/is proxied/none */
	kssl_ent_t		so_kssl_ent;	/* SSL config entry */
	kssl_ctx_t		so_kssl_ctx;	/* SSL session context */

	/* != NULL for sodirect_t enabled socket */
	sodirect_t	*so_direct;
};

/* flags */
#define	SOMOD		0x0001		/* update socket modification time */
#define	SOACC		0x0002		/* update socket access time */

#define	SOLOCKED	0x0010		/* use to serialize open/closes */
#define	SOREADLOCKED	0x0020		/* serialize kstrgetmsg calls */
#define	SOWANT		0x0040		/* some process waiting on lock */
#define	SOCLONE		0x0080		/* child of clone driver */
#define	SOASYNC_UNBIND	0x0100		/* wait for ACK of async unbind */

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
#define	SS_HASCONNIND		0x00000400 /* T_CONN_IND for poll */
#define	SS_SAVEDEOR		0x00000800 /* Saved MSG_EOR rcv side state */

#define	SS_RCVATMARK		0x00001000 /* at mark on input */
#define	SS_OOBPEND		0x00002000 /* OOB pending or present - poll */
#define	SS_HAVEOOBDATA		0x00004000 /* OOB data present */
#define	SS_HADOOBDATA		0x00008000 /* OOB data consumed */

#define	SS_FADDR_NOXLATE	0x00020000 /* No xlation of faddr for AF_UNIX */

#define	SS_HASDATA		0x00040000 /* NCAfs: data available */
#define	SS_DONEREAD		0x00080000 /* NCAfs: all data read */
#define	SS_MOREDATA		0x00100000 /* NCAfs: NCA has more data */

#define	SS_DIRECT		0x00200000 /* transport is directly below */
#define	SS_SODIRECT		0x00400000 /* transport supports sodirect */

#define	SS_LADDR_VALID		0x01000000	/* so_laddr valid for user */
#define	SS_FADDR_VALID		0x02000000	/* so_faddr valid for user */

/* Set of states when the socket can't be rebound */
#define	SS_CANTREBIND	(SS_ISCONNECTED|SS_ISCONNECTING|SS_ISDISCONNECTING|\
			    SS_CANTSENDMORE|SS_CANTRCVMORE|SS_ACCEPTCONN)

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
 * Used for mapping family/type/protocol to vnode.
 * Defined here so that crash can use it.
 */
struct sockparams {
	int	sp_domain;
	int	sp_type;
	int	sp_protocol;
	char	*sp_devpath;
	int	sp_devpathlen;	/* Is 0 if sp_devpath is a static string */
	vnode_t	*sp_vnode;
	struct sockparams *sp_next;
};

extern struct sockparams *sphead;

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
	int	(*sop_accept)(struct sonode *, int, struct sonode **);
	int	(*sop_bind)(struct sonode *, struct sockaddr *, socklen_t,
		    int);
	int	(*sop_listen)(struct sonode *, int);
	int	(*sop_connect)(struct sonode *, const struct sockaddr *,
		    socklen_t, int, int);
	int	(*sop_recvmsg)(struct sonode *, struct msghdr *,
		    struct uio *);
	int	(*sop_sendmsg)(struct sonode *, struct msghdr *,
		    struct uio *);
	int	(*sop_getpeername)(struct sonode *);
	int	(*sop_getsockname)(struct sonode *);
	int	(*sop_shutdown)(struct sonode *, int);
	int	(*sop_getsockopt)(struct sonode *, int, int, void *,
		    socklen_t *, int);
	int 	(*sop_setsockopt)(struct sonode *, int, int, const void *,
		    socklen_t);
};

#define	SOP_ACCEPT(so, fflag, nsop)	\
	((so)->so_ops->sop_accept((so), (fflag), (nsop)))
#define	SOP_BIND(so, name, namelen, flags)	\
	((so)->so_ops->sop_bind((so), (name), (namelen), (flags)))
#define	SOP_LISTEN(so, backlog)	\
	((so)->so_ops->sop_listen((so), (backlog)))
#define	SOP_CONNECT(so, name, namelen, fflag, flags)	\
	((so)->so_ops->sop_connect((so), (name), (namelen), (fflag), (flags)))
#define	SOP_RECVMSG(so, msg, uiop)	\
	((so)->so_ops->sop_recvmsg((so), (msg), (uiop)))
#define	SOP_SENDMSG(so, msg, uiop)	\
	((so)->so_ops->sop_sendmsg((so), (msg), (uiop)))
#define	SOP_GETPEERNAME(so)	\
	((so)->so_ops->sop_getpeername((so)))
#define	SOP_GETSOCKNAME(so)	\
	((so)->so_ops->sop_getsockname((so)))
#define	SOP_SHUTDOWN(so, how)	\
	((so)->so_ops->sop_shutdown((so), (how)))
#define	SOP_GETSOCKOPT(so, level, optionname, optval, optlenp, flags)	\
	((so)->so_ops->sop_getsockopt((so), (level), (optionname),	\
	    (optval), (optlenp), (flags)))
#define	SOP_SETSOCKOPT(so, level, optionname, optval, optlen)		\
	((so)->so_ops->sop_setsockopt((so), (level), (optionname),	\
	    (optval), (optlen)))

#endif /* defined(_KERNEL) || defined(_KMEMUSER) */

#ifdef _KERNEL

#define	ISALIGNED_cmsghdr(addr) \
		(((uintptr_t)(addr) & (_CMSG_HDR_ALIGNMENT - 1)) == 0)

#define	ROUNDUP_cmsglen(len) \
	(((len) + _CMSG_HDR_ALIGNMENT - 1) & ~(_CMSG_HDR_ALIGNMENT - 1))

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
extern struct vnodeops			*socktpi_vnodeops;
extern const struct fs_operation_def	socktpi_vnodeops_template[];

extern sonodeops_t			sotpi_sonodeops;

extern dev_t				sockdev;

/*
 * sockfs functions
 */
extern int	sock_getmsg(vnode_t *, struct strbuf *, struct strbuf *,
			uchar_t *, int *, int, rval_t *);
extern int	sock_putmsg(vnode_t *, struct strbuf *, struct strbuf *,
			uchar_t, int, int);
struct sonode	*sotpi_create(vnode_t *, int, int, int, int, struct sonode *,
			int *);
extern int	socktpi_open(struct vnode **, int, struct cred *,
			caller_context_t *);
extern int	so_sock2stream(struct sonode *);
extern void	so_stream2sock(struct sonode *);
extern int	sockinit(int, char *);
extern struct vnode
		*makesockvp(struct vnode *, int, int, int);
extern void	sockfree(struct sonode *);
extern void	so_update_attrs(struct sonode *, int);
extern int	soconfig(int, int, int,	char *, int);
extern struct vnode
		*solookup(int, int, int, char *, int *);
extern void	so_lock_single(struct sonode *);
extern void	so_unlock_single(struct sonode *, int);
extern int	so_lock_read(struct sonode *, int);
extern int	so_lock_read_intr(struct sonode *, int);
extern void	so_unlock_read(struct sonode *);
extern void	*sogetoff(mblk_t *, t_uscalar_t, t_uscalar_t, uint_t);
extern void	so_getopt_srcaddr(void *, t_uscalar_t,
			void **, t_uscalar_t *);
extern int	so_getopt_unix_close(void *, t_uscalar_t);
extern int	so_addr_verify(struct sonode *, const struct sockaddr *,
			socklen_t);
extern int	so_ux_addr_xlate(struct sonode *, struct sockaddr *,
			socklen_t, int, void **, socklen_t *);
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
extern int	sogeterr(struct sonode *);
extern int	sogetrderr(vnode_t *, int, int *);
extern int	sogetwrerr(vnode_t *, int, int *);
extern void	so_unix_close(struct sonode *);
extern mblk_t	*soallocproto(size_t, int);
extern mblk_t	*soallocproto1(const void *, ssize_t, ssize_t, int);
extern void	soappendmsg(mblk_t *, const void *, ssize_t);
extern mblk_t	*soallocproto2(const void *, ssize_t, const void *, ssize_t,
			ssize_t, int);
extern mblk_t	*soallocproto3(const void *, ssize_t, const void *, ssize_t,
			const void *, ssize_t, ssize_t, int);
extern int	sowaitprim(struct sonode *, t_scalar_t, t_scalar_t,
			t_uscalar_t, mblk_t **, clock_t);
extern int	sowaitokack(struct sonode *, t_scalar_t);
extern int	sowaitack(struct sonode *, mblk_t **, clock_t);
extern void	soqueueack(struct sonode *, mblk_t *);
extern int	sowaitconnind(struct sonode *, int, mblk_t **);
extern void	soqueueconnind(struct sonode *, mblk_t *);
extern int	soflushconnind(struct sonode *, t_scalar_t);
extern void	so_drain_discon_ind(struct sonode *);
extern void	so_flush_discon_ind(struct sonode *);
extern int	sowaitconnected(struct sonode *, int, int);

extern int	sostream_direct(struct sonode *, struct uio *,
		    mblk_t *, cred_t *);
extern int	sosend_dgram(struct sonode *, struct sockaddr *,
		    socklen_t, struct uio *, int);
extern int	sosend_svc(struct sonode *, struct uio *, t_scalar_t, int, int);
extern void	so_installhooks(struct sonode *);
extern int	so_strinit(struct sonode *, struct sonode *);
extern int	sotpi_recvmsg(struct sonode *, struct nmsghdr *,
		    struct uio *);
extern int	sotpi_getpeername(struct sonode *);
extern int	sotpi_getsockopt(struct sonode *, int, int, void *,
		    socklen_t *, int);
extern int	sotpi_setsockopt(struct sonode *, int, int, const void *,
		    socklen_t);
extern int	socktpi_ioctl(struct vnode *, int, intptr_t, int,
		    struct cred *, int *, caller_context_t *);
extern int	sodisconnect(struct sonode *, t_scalar_t, int);
extern ssize_t	soreadfile(file_t *, uchar_t *, u_offset_t, int *, size_t);
extern int	so_set_asyncsigs(vnode_t *, pid_t, int, int, cred_t *);
extern int	so_set_events(struct sonode *, vnode_t *, cred_t *);
extern int	so_flip_async(struct sonode *, vnode_t *, int, cred_t *);
extern int	so_set_siggrp(struct sonode *, vnode_t *, pid_t, int, cred_t *);
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
extern int	soconnect(struct sonode *, const struct sockaddr *, socklen_t,
		    int, int);
extern int	sorecvmsg(struct sonode *, struct nmsghdr *, struct uio *);
extern int	sosendmsg(struct sonode *, struct nmsghdr *, struct uio *);
extern int	sogetpeername(struct sonode *);
extern int	sogetsockname(struct sonode *);
extern int	soshutdown(struct sonode *, int);
extern int	sogetsockopt(struct sonode *, int, int, void *, socklen_t *,
		    int);
extern int	sosetsockopt(struct sonode *, int, int, const void *,
		    t_uscalar_t);

extern struct sonode	*socreate(vnode_t *, int, int, int, int,
			    struct sonode *, int *);

extern int	so_copyin(const void *, void *, size_t, int);
extern int	so_copyout(const void *, void *, size_t, int);

extern int	socktpi_access(struct vnode *, int, int, struct cred *,
		    caller_context_t *);
extern int	socktpi_fid(struct vnode *, struct fid *, caller_context_t *);
extern int	socktpi_fsync(struct vnode *, int, struct cred *,
		    caller_context_t *);
extern int	socktpi_getattr(struct vnode *, struct vattr *, int,
		    struct cred *, caller_context_t *);
extern int	socktpi_seek(struct vnode *, offset_t, offset_t *,
		    caller_context_t *);
extern int	socktpi_setattr(struct vnode *, struct vattr *, int,
		    struct cred *, caller_context_t *);
extern int	socktpi_setfl(vnode_t *, int, int, cred_t *,
		    caller_context_t *);

/* SCTP sockfs */
extern struct sonode	*sosctp_create(vnode_t *, int, int, int, int,
			    struct sonode *, int *);
extern int sosctp_init(void);

/* SDP sockfs */
extern struct sonode    *sosdp_create(vnode_t *, int, int, int, int,
			    struct sonode *, int *);
extern int sosdp_init(void);

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
	zoneid_t	si_szoneid;
};


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SOCKETVAR_H */
