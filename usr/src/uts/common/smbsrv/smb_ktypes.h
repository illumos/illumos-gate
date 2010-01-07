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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Structures and type definitions for the SMB module.
 */

#ifndef _SMBSRV_SMB_KTYPES_H
#define	_SMBSRV_SMB_KTYPES_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/note.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/synch.h>
#include <sys/taskq.h>
#include <sys/socket.h>
#include <sys/acl.h>
#include <sys/sdt.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/cred.h>
#include <netinet/in.h>
#include <sys/ksocket.h>
#include <sys/fem.h>
#include <sys/door.h>
#include <sys/extdirent.h>
#include <smbsrv/smb.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/mbuf.h>
#include <smbsrv/smb_sid.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/netbios.h>
#include <smbsrv/smb_vops.h>

struct smb_disp_entry;
struct smb_request;
struct smb_server;

int smb_noop(void *, size_t, int);

#define	SMB_AUDIT_STACK_DEPTH	16
#define	SMB_AUDIT_BUF_MAX_REC	16
#define	SMB_AUDIT_NODE		0x00000001

/*
 * Maximum number of records returned in SMBsearch, SMBfind
 * and SMBfindunique response. Value set to 10 for compatibility
 * with Windows.
 */
#define	SMB_MAX_SEARCH		10

#define	SMB_SEARCH_ATTRIBUTES    \
	(FILE_ATTRIBUTE_HIDDEN | \
	FILE_ATTRIBUTE_SYSTEM |  \
	FILE_ATTRIBUTE_DIRECTORY)

#define	SMB_SEARCH_HIDDEN(sattr) ((sattr) & FILE_ATTRIBUTE_HIDDEN)
#define	SMB_SEARCH_SYSTEM(sattr) ((sattr) & FILE_ATTRIBUTE_SYSTEM)
#define	SMB_SEARCH_DIRECTORY(sattr) ((sattr) & FILE_ATTRIBUTE_DIRECTORY)
#define	SMB_SEARCH_ALL(sattr) ((sattr) & SMB_SEARCH_ATTRIBUTES)

typedef struct {
	uint32_t		anr_refcnt;
	int			anr_depth;
	pc_t			anr_stack[SMB_AUDIT_STACK_DEPTH];
} smb_audit_record_node_t;

typedef struct {
	int			anb_index;
	int			anb_max_index;
	smb_audit_record_node_t	anb_records[SMB_AUDIT_BUF_MAX_REC];
} smb_audit_buf_node_t;

#define	SMB_WORKER_PRIORITY	99
/*
 * Thread State Machine
 * --------------------
 *
 *			    T5			   T0
 * smb_thread_destroy()	<-------+		+------- smb_thread_init()
 *                              |		|
 *				|		v
 *			+-----------------------------+
 *			|   SMB_THREAD_STATE_EXITED   |<---+
 *			+-----------------------------+	   |
 *				      | T1		   |
 *				      v			   |
 *			+-----------------------------+	   |
 *			|  SMB_THREAD_STATE_STARTING  |	   |
 *			+-----------------------------+	   |
 *				     | T2		   | T4
 *				     v			   |
 *			+-----------------------------+	   |
 *			|  SMB_THREAD_STATE_RUNNING   |	   |
 *			+-----------------------------+	   |
 *				     | T3		   |
 *				     v			   |
 *			+-----------------------------+	   |
 *			|  SMB_THREAD_STATE_EXITING   |----+
 *			+-----------------------------+
 *
 * Transition T0
 *
 *    This transition is executed in smb_thread_init().
 *
 * Transition T1
 *
 *    This transition is executed in smb_thread_start().
 *
 * Transition T2
 *
 *    This transition is executed by the thread itself when it starts running.
 *
 * Transition T3
 *
 *    This transition is executed by the thread itself in
 *    smb_thread_entry_point() just before calling thread_exit().
 *
 *
 * Transition T4
 *
 *    This transition is executed in smb_thread_stop().
 *
 * Transition T5
 *
 *    This transition is executed in smb_thread_destroy().
 *
 * Comments
 * --------
 *
 *    The field smb_thread_aw_t contains a function pointer that knows how to
 *    awake the thread. It is a temporary solution to work around the fact that
 *    kernel threads (not part of a userspace process) cannot be signaled.
 */
typedef enum smb_thread_state {
	SMB_THREAD_STATE_STARTING = 0,
	SMB_THREAD_STATE_RUNNING,
	SMB_THREAD_STATE_EXITING,
	SMB_THREAD_STATE_EXITED
} smb_thread_state_t;

struct _smb_thread;

typedef void (*smb_thread_ep_t)(struct _smb_thread *, void *ep_arg);
typedef void (*smb_thread_aw_t)(struct _smb_thread *, void *aw_arg);

#define	SMB_THREAD_MAGIC	0x534D4254	/* SMBT */

typedef struct _smb_thread {
	uint32_t		sth_magic;
	char			sth_name[16];
	smb_thread_state_t	sth_state;
	kthread_t		*sth_th;
	kt_did_t		sth_did;
	smb_thread_ep_t		sth_ep;
	void			*sth_ep_arg;
	smb_thread_aw_t		sth_aw;
	void			*sth_aw_arg;
	boolean_t		sth_kill;
	kmutex_t		sth_mtx;
	kcondvar_t		sth_cv;
} smb_thread_t;

/*
 * Pool of IDs
 * -----------
 *
 *    A pool of IDs is a pool of 16 bit numbers. It is implemented as a bitmap.
 *    A bit set to '1' indicates that that particular value has been allocated.
 *    The allocation process is done shifting a bit through the whole bitmap.
 *    The current position of that index bit is kept in the smb_idpool_t
 *    structure and represented by a byte index (0 to buffer size minus 1) and
 *    a bit index (0 to 7).
 *
 *    The pools start with a size of 8 bytes or 64 IDs. Each time the pool runs
 *    out of IDs its current size is doubled until it reaches its maximum size
 *    (8192 bytes or 65536 IDs). The IDs 0 and 65535 are never given out which
 *    means that a pool can have a maximum number of 65534 IDs available.
 */
#define	SMB_IDPOOL_MAGIC	0x4944504C	/* IDPL */
#define	SMB_IDPOOL_MIN_SIZE	64	/* Number of IDs to begin with */
#define	SMB_IDPOOL_MAX_SIZE	64 * 1024

typedef struct smb_idpool {
	uint32_t	id_magic;
	kmutex_t	id_mutex;
	uint8_t		*id_pool;
	uint32_t	id_size;
	uint8_t		id_bit;
	uint8_t		id_bit_idx;
	uint32_t	id_idx;
	uint32_t	id_idx_msk;
	uint32_t	id_free_counter;
	uint32_t	id_max_free_counter;
} smb_idpool_t;

/*
 * Maximum size of a Transport Data Unit when CAP_LARGE_READX and
 * CAP_LARGE_WRITEX are not set.  CAP_LARGE_READX/CAP_LARGE_WRITEX
 * allow the payload to exceed the negotiated buffer size.
 *     4 --> NBT/TCP Transport Header.
 *    32 --> SMB Header
 *     1 --> Word Count byte
 *   510 --> Maximum Number of bytes of the Word Table (2 * 255)
 *     2 --> Byte count of the data
 * 65535 --> Maximum size of the data
 * -----
 * 66084
 */
#define	SMB_REQ_MAX_SIZE	66560		/* 65KB */
#define	SMB_XPRT_MAX_SIZE	(SMB_REQ_MAX_SIZE + NETBIOS_HDR_SZ)

#define	SMB_TXREQ_MAGIC		0X54524251	/* 'TREQ' */
typedef struct {
	uint32_t	tr_magic;
	list_node_t	tr_lnd;
	int		tr_len;
	uint8_t		tr_buf[SMB_XPRT_MAX_SIZE];
} smb_txreq_t;

#define	SMB_TXLST_MAGIC		0X544C5354	/* 'TLST' */
typedef struct {
	uint32_t	tl_magic;
	kmutex_t	tl_mutex;
	boolean_t	tl_active;
	list_t		tl_list;
} smb_txlst_t;

/*
 * Maximum buffer size for NT is 37KB.  If all clients are Windows 2000, this
 * can be changed to 64KB.  37KB must be used with a mix of NT/Windows 2000
 * clients because NT loses directory entries when values greater than 37KB are
 * used.
 *
 * Note: NBT_MAXBUF will be subtracted from the specified max buffer size to
 * account for the NBT header.
 */
#define	NBT_MAXBUF		8
#define	SMB_NT_MAXBUF		(37 * 1024)

#define	OUTBUFSIZE		(65 * 1024)
#define	SMBHEADERSIZE		32
#define	SMBND_HASH_MASK		(0xFF)
#define	MAX_IOVEC		512
#define	MAX_READREF		(8 * 1024)

#define	SMB_WORKER_MIN		4
#define	SMB_WORKER_DEFAULT	64
#define	SMB_WORKER_MAX		1024

/*
 * Fix align a pointer or offset appropriately so that fields will not
 * cross word boundaries.
 */
#define	PTRALIGN(x) \
	(((uintptr_t)(x) + (uintptr_t)(_POINTER_ALIGNMENT) - 1l) & \
	    ~((uintptr_t)(_POINTER_ALIGNMENT) - 1l))

/*
 * native os types are defined in win32/smbinfo.h
 */

/*
 * All 4 different time / date formats that will bee seen in SMB
 */
typedef struct {
	uint16_t	Day	: 5;
	uint16_t	Month	: 4;
	uint16_t	Year	: 7;
} SMB_DATE;

typedef struct {
	uint16_t	TwoSeconds : 5;
	uint16_t	Minutes	   : 6;
	uint16_t	Hours	   : 5;
} SMB_TIME;


typedef uint32_t 	UTIME;		/* seconds since Jan 1 1970 */

typedef struct smb_llist {
	krwlock_t	ll_lock;
	list_t		ll_list;
	uint32_t	ll_count;
	uint64_t	ll_wrop;
} smb_llist_t;

typedef struct smb_slist {
	kmutex_t	sl_mutex;
	kcondvar_t	sl_cv;
	list_t		sl_list;
	uint32_t	sl_count;
	boolean_t	sl_waiting;
} smb_slist_t;

typedef struct smb_session_list {
	krwlock_t	se_lock;
	uint64_t	se_wrop;
	struct {
		list_t		lst;
		uint32_t	count;
	} se_rdy;
	struct {
		list_t		lst;
		uint32_t	count;
	} se_act;
} smb_session_list_t;

typedef struct {
	kcondvar_t	rwx_cv;
	kmutex_t	rwx_mutex;
	krwlock_t	rwx_lock;
	boolean_t	rwx_waiting;
} smb_rwx_t;

/* NOTIFY CHANGE */

typedef struct smb_notify_change_req {
	list_node_t		nc_lnd;
	struct smb_node		*nc_node;
	uint32_t		nc_reply_type;
	uint32_t		nc_flags;
} smb_notify_change_req_t;

/*
 * SMB operates over a NetBIOS-over-TCP transport (NBT) or directly
 * over TCP, which is also known as direct hosted NetBIOS-less SMB
 * or SMB-over-TCP.
 *
 * NBT messages have a 4-byte header that defines the message type
 * (8-bits), a 7-bit flags field and a 17-bit length.
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      TYPE     |     FLAGS   |E|            LENGTH             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 8-bit type      Defined in RFC 1002
 * 7-bit flags     Bits 0-6 reserved (must be 0)
 *                 Bit 7: Length extension bit (E)
 * 17-bit length   Includes bit 7 of the flags byte
 *
 *
 * SMB-over-TCP is defined to use a modified version of the NBT header
 * containing an 8-bit message type and 24-bit message length.
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      TYPE     |                  LENGTH                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 8-bit type      Must be 0
 * 24-bit length
 *
 * The following structure is used to represent a generic, in-memory
 * SMB transport header; it is not intended to map directly to either
 * of the over-the-wire formats.
 */
typedef struct {
	uint8_t		xh_type;
	uint32_t	xh_length;
} smb_xprt_t;

int MBC_LENGTH(struct mbuf_chain *);
int MBC_MAXBYTES(struct mbuf_chain *);
void MBC_SETUP(struct mbuf_chain *, uint32_t);
void MBC_INIT(struct mbuf_chain *, uint32_t);
void MBC_FLUSH(struct mbuf_chain *);
void MBC_ATTACH_MBUF(struct mbuf_chain *, struct mbuf *);
void MBC_APPEND_MBUF(struct mbuf_chain *, struct mbuf *);
void MBC_ATTACH_BUF(struct mbuf_chain *MBC, unsigned char *BUF, int LEN);
int MBC_SHADOW_CHAIN(struct mbuf_chain *SUBMBC, struct mbuf_chain *MBC,
    int OFF, int LEN);

#define	MBC_ROOM_FOR(b, n) (((b)->chain_offset + (n)) <= (b)->max_bytes)

/*
 * ol_sess_id:
 *
 *	ID of the session holding the oplock (if an oplock was granted).
 *
 * ol_xthread:
 *
 *	Worker thread treating the command that was granted the oplock. Until
 *	that thread is done with that command and has submitted the response
 *	to the network stack, all the other threads will be suspended in
 *	smb_oplock_enter(). They will be awaken when the worker thread
 *	referenced in 'ol_xthread' calls smb_oplock_broadcast().
 *
 *	The purpose of this mechanism is to prevent another thread from
 *	triggering a oplock break before the response conveying the grant
 *	has been sent.
 *
 * ol_ofile
 *
 *	Open file that was granted the oplock.
 *
 * ol_waiters_count
 *
 *	Number of threads waiting for a call to smb_oplock_broadcast().
 *
 * ol_level
 *
 *	Level of the oplock granted.
 */
typedef struct smb_oplock {
	uint64_t		ol_sess_id;
	kcondvar_t		ol_cv;
	kthread_t		*ol_xthread;
	struct smb_ofile	*ol_ofile;
	uint8_t			ol_level;
} smb_oplock_t;

#define	DOS_ATTR_VALID	0x80000000

#define	SMB_VFS_MAGIC	0x534D4256	/* 'SMBV' */

typedef struct smb_vfs {
	uint32_t		sv_magic;
	list_node_t		sv_lnd;
	uint32_t		sv_refcnt;
	vfs_t			*sv_vfsp;
	vnode_t			*sv_rootvp;
} smb_vfs_t;

typedef struct smb_unexport {
	list_node_t	ux_lnd;
	char		ux_sharename[MAXNAMELEN];
} smb_unexport_t;

/*
 * Solaris file systems handle timestamps differently from NTFS.
 * In order to provide a more similar view of an open file's
 * timestamps, we cache the timestamps in the node and manipulate
 * them in a manner more consistent with windows.
 * t_cached is B_TRUE when timestamps are cached.
 * Timestamps remain cached while there are open ofiles for the node.
 * This includes open ofiles for named streams.  t_open_ofiles is a
 * count of open ofiles on the node, including named streams' ofiles,
 * n_open_ofiles cannot be used as it doesn't include ofiles opened
 * for the node's named streams.
 */
typedef struct smb_times {
	uint32_t		t_open_ofiles;
	boolean_t		t_cached;
	timestruc_t		t_atime;
	timestruc_t		t_mtime;
	timestruc_t		t_ctime;
	timestruc_t		t_crtime;
} smb_times_t;

#define	SMB_NODE_MAGIC		0x4E4F4445	/* 'NODE' */
#define	SMB_NODE_VALID(p)	ASSERT((p)->n_magic == SMB_NODE_MAGIC)

typedef enum {
	SMB_NODE_STATE_AVAILABLE = 0,
	SMB_NODE_STATE_OPLOCK_GRANTED,
	SMB_NODE_STATE_OPLOCK_BREAKING,
	SMB_NODE_STATE_DESTROYING
} smb_node_state_t;

typedef struct smb_node {
	uint32_t		n_magic;
	krwlock_t		n_lock;
	kmutex_t		n_mutex;
	list_node_t		n_lnd;
	smb_node_state_t	n_state;
	uint32_t		n_refcnt;
	uint32_t		n_hashkey;
	smb_llist_t		*n_hash_bucket;
	uint32_t		n_orig_uid;
	uint32_t		n_open_count;
	smb_llist_t		n_ofile_list;
	smb_llist_t		n_lock_list;
	struct smb_ofile	*readonly_creator;
	volatile int		flags;	/* FILE_NOTIFY_CHANGE_* */
	volatile int		waiting_event; /* # of clients requesting FCN */
	smb_times_t		n_timestamps; /* cached timestamps */
	u_offset_t		n_allocsz; /* cached file allocation size */
	smb_oplock_t		n_oplock;
	struct smb_node		*n_dnode; /* directory node */
	struct smb_node		*n_unode; /* unnamed stream node */
	/* Credentials for delayed delete */
	cred_t			*delete_on_close_cred;
	uint32_t		n_delete_on_close_flags;
	char			od_name[MAXNAMELEN];
	vnode_t			*vp;
	smb_audit_buf_node_t	*n_audit_buf;
} smb_node_t;

#define	NODE_FLAGS_WATCH_TREE		0x10000000
#define	NODE_FLAGS_NOTIFY_CHANGE	\
	(NODE_FLAGS_WATCH_TREE | FILE_NOTIFY_VALID_MASK)
#define	NODE_FLAGS_CHANGED		0x08000000
#define	NODE_FLAGS_WRITE_THROUGH	0x00100000
#define	NODE_XATTR_DIR			0x01000000
#define	NODE_FLAGS_DELETE_ON_CLOSE	0x40000000
#define	NODE_FLAGS_EXECUTABLE		0x80000000

#define	SMB_NODE_VFS(node)	((node)->vp->v_vfsp)
#define	SMB_NODE_FSID(node)	((node)->vp->v_vfsp->vfs_fsid)

/*
 * Based on section 2.6.1.2 (Connection Management) of the June 13,
 * 1996 CIFS spec, a server may terminate the transport connection
 * due to inactivity. The client software is expected to be able to
 * automatically reconnect to the server if this happens. Like much
 * of the useful background information, this section appears to
 * have been dropped from later revisions of the document.
 *
 * Each session has an activity timestamp that's updated whenever a
 * request is dispatched. If the session is idle, i.e. receives no
 * requests, for SMB_SESSION_INACTIVITY_TIMEOUT minutes it will be
 * closed.
 *
 * Each session has an I/O semaphore to serialize communication with
 * the client. For example, after receiving a raw-read request, the
 * server is not allowed to send an oplock break to the client until
 * after it has sent the raw-read data.
 */
#define	SMB_SESSION_INACTIVITY_TIMEOUT		(15 * 60)

#define	SMB_SESSION_OFILE_MAX			(16 * 1024)

/*
 * When a connection is set up we need to remember both the client
 * (peer) IP address and the local IP address used to establish the
 * connection. When a client connects with a vc number of zero, we
 * are supposed to abort any existing connections with that client
 * (see notes in smb_negotiate.c and smb_session_setup_andx.c). For
 * servers with multiple network interfaces or IP aliases, however,
 * each interface has to be managed independently since the client
 * is not aware of the server configuration. We have to allow the
 * client to establish a connection on each interface with a vc
 * number of zero without aborting the other connections.
 *
 * ipaddr:       the client (peer) IP address for the session.
 * local_ipaddr: the local IP address used to connect to the server.
 */

#define	SMB_MAC_KEYSZ	512

struct smb_sign {
	unsigned int seqnum;
	unsigned int mackey_len;
	unsigned int flags;
	unsigned char mackey[SMB_MAC_KEYSZ];
};

#define	SMB_SIGNING_ENABLED	1
#define	SMB_SIGNING_CHECK	2

/*
 * Session State Machine
 * ---------------------
 *
 * +-----------------------------+	     +------------------------------+
 * | SMB_SESSION_STATE_CONNECTED |           | SMB_SESSION_STATE_TERMINATED |
 * +-----------------------------+           +------------------------------+
 *		T0|					     ^
 *		  +--------------------+		     |T13
 *		  v		       |T14                  |
 * +-------------------------------+   |    +--------------------------------+
 * | SMB_SESSION_STATE_ESTABLISHED |---+--->| SMB_SESSION_STATE_DISCONNECTED |
 * +-------------------------------+        +--------------------------------+
 *		T1|				^	   ^ ^ ^
 *		  +----------+			|T9        | | |
 *                           v			|          | | |
 *                  +------------------------------+       | | |
 *                  | SMB_SESSION_STATE_NEGOTIATED |       | | |
 *                  +------------------------------+       | | |
 *	                 ^|   ^|   | ^                     | | |
 *      +----------------+|   ||   | |                     | | |
 *      |+----------------+   || T7| |T8                   | | |
 *      ||                    ||   | |                     | | |
 *      ||   +----------------+|   | |                     | | |
 *      ||   |+----------------+   | |                     | | |
 *	||   ||			   v |                     | | |
 *      ||   ||   +-----------------------------------+ T10| | |
 *      ||   ||   | SMB_SESSION_STATE_OPLOCK_BREAKING |----+ | |
 *      ||   ||   +-----------------------------------+      | |
 *	||   ||T5                                            | |
 *      ||   |+-->+-----------------------------------+	  T11| |
 *      ||   |T6  | SMB_SESSION_STATE_READ_RAW_ACTIVE |------+ |
 *      ||   +----+-----------------------------------+        |
 *	||T3                                                   |
 *      |+------->+------------------------------------+    T12|
 *      |T4       | SMB_SESSION_STATE_WRITE_RAW_ACTIVE |-------+
 *      +---------+------------------------------------+
 *
 * Transition T0
 *
 *
 *
 * Transition T1
 *
 *
 *
 * Transition T2
 *
 *
 *
 * Transition T3
 *
 *
 *
 * Transition T4
 *
 *
 *
 * Transition T5
 *
 *
 *
 * Transition T6
 *
 *
 *
 * Transition T7
 *
 *
 *
 * Transition T8
 *
 *
 *
 * Transition T9
 *
 *
 *
 * Transition T10
 *
 *
 *
 * Transition T11
 *
 *
 *
 * Transition T12
 *
 *
 *
 * Transition T13
 *
 *
 *
 * Transition T14
 *
 *
 *
 */
#define	SMB_SESSION_MAGIC	0x53455353	/* 'SESS' */
#define	SMB_SESSION_VALID(p)	ASSERT((p)->s_magic == SMB_SESSION_MAGIC)

typedef enum {
	SMB_SESSION_STATE_INITIALIZED = 0,
	SMB_SESSION_STATE_DISCONNECTED,
	SMB_SESSION_STATE_CONNECTED,
	SMB_SESSION_STATE_ESTABLISHED,
	SMB_SESSION_STATE_NEGOTIATED,
	SMB_SESSION_STATE_OPLOCK_BREAKING,
	SMB_SESSION_STATE_WRITE_RAW_ACTIVE,
	SMB_SESSION_STATE_READ_RAW_ACTIVE,
	SMB_SESSION_STATE_TERMINATED,
	SMB_SESSION_STATE_SENTINEL
} smb_session_state_t;

typedef struct smb_session {
	uint32_t		s_magic;
	smb_rwx_t		s_lock;
	list_node_t		s_lnd;
	uint64_t		s_kid;
	smb_session_state_t	s_state;
	uint32_t		s_flags;
	int			s_write_raw_status;
	kthread_t		*s_thread;
	kt_did_t		s_ktdid;
	smb_kmod_cfg_t		s_cfg;
	kmem_cache_t		*s_cache;
	kmem_cache_t		*s_cache_request;
	struct smb_server	*s_server;
	int32_t			s_gmtoff;
	uint32_t		keep_alive;
	uint64_t		opentime;
	uint16_t		vcnumber;
	uint16_t		s_local_port;
	smb_inaddr_t		ipaddr;
	smb_inaddr_t		local_ipaddr;
	char 			workstation[SMB_PI_MAX_HOST];
	int			dialect;
	int			native_os;
	uint32_t		capabilities;
	struct smb_sign		signing;

	ksocket_t		sock;

	smb_slist_t		s_req_list;
	smb_llist_t		s_xa_list;
	smb_llist_t		s_user_list;
	smb_idpool_t		s_uid_pool;
	smb_txlst_t		s_txlst;

	volatile uint32_t	s_tree_cnt;
	volatile uint32_t	s_file_cnt;
	volatile uint32_t	s_dir_cnt;

	uint16_t		secmode;
	uint32_t		sesskey;
	uint32_t		challenge_len;
	unsigned char		challenge_key[8];
	unsigned char		MAC_key[44];
	int64_t			activity_timestamp;
	/*
	 * Maximum negotiated buffer size between SMB client and server
	 * in SMB_SESSION_SETUP_ANDX
	 */
	uint16_t		smb_msg_size;
	uchar_t			*outpipe_data;
	int			outpipe_datalen;
	int			outpipe_cookie;
	list_t			s_oplock_brkreqs;
} smb_session_t;

#define	SMB_USER_MAGIC 0x55534552	/* 'USER' */

#define	SMB_USER_FLAG_GUEST			SMB_ATF_GUEST
#define	SMB_USER_FLAG_IPC			SMB_ATF_ANON
#define	SMB_USER_FLAG_ADMIN			SMB_ATF_ADMIN
#define	SMB_USER_FLAG_POWER_USER		SMB_ATF_POWERUSER
#define	SMB_USER_FLAG_BACKUP_OPERATOR		SMB_ATF_BACKUPOP

#define	SMB_USER_PRIV_TAKE_OWNERSHIP	0x00000001
#define	SMB_USER_PRIV_BACKUP		0x00000002
#define	SMB_USER_PRIV_RESTORE		0x00000004
#define	SMB_USER_PRIV_SECURITY		0x00000008


typedef enum {
	SMB_USER_STATE_LOGGED_IN = 0,
	SMB_USER_STATE_LOGGING_OFF,
	SMB_USER_STATE_LOGGED_OFF,
	SMB_USER_STATE_SENTINEL
} smb_user_state_t;

typedef struct smb_user {
	uint32_t		u_magic;
	list_node_t		u_lnd;
	kmutex_t		u_mutex;
	smb_user_state_t	u_state;

	struct smb_server	*u_server;
	smb_session_t		*u_session;
	uint16_t		u_name_len;
	char			*u_name;
	uint16_t		u_domain_len;
	char			*u_domain;
	time_t			u_logon_time;
	cred_t			*u_cred;
	cred_t			*u_privcred;

	smb_llist_t		u_tree_list;
	smb_idpool_t		u_tid_pool;

	uint32_t		u_refcnt;
	uint32_t		u_flags;
	uint32_t		u_privileges;
	uint16_t		u_uid;
	uint32_t		u_audit_sid;
} smb_user_t;

#define	SMB_TREE_MAGIC			0x54524545	/* 'TREE' */

#define	SMB_TYPENAMELEN			_ST_FSTYPSZ
#define	SMB_VOLNAMELEN			32

#define	SMB_TREE_READONLY		0x00000001
#define	SMB_TREE_SUPPORTS_ACLS		0x00000002
#define	SMB_TREE_STREAMS		0x00000004
#define	SMB_TREE_CASEINSENSITIVE	0x00000008
#define	SMB_TREE_NO_CASESENSITIVE	0x00000010
#define	SMB_TREE_NO_EXPORT		0x00000020
#define	SMB_TREE_NO_OPLOCKS		0x00000040
#define	SMB_TREE_NO_ATIME		0x00000080
#define	SMB_TREE_XVATTR			0x00000100
#define	SMB_TREE_DIRENTFLAGS		0x00000200
#define	SMB_TREE_ACLONCREATE		0x00000400
#define	SMB_TREE_ACEMASKONACCESS	0x00000800
#define	SMB_TREE_NFS_MOUNTED		0x00001000
#define	SMB_TREE_UNICODE_ON_DISK	0x00002000
#define	SMB_TREE_CATIA			0x00004000
#define	SMB_TREE_ABE			0x00008000

typedef enum {
	SMB_TREE_STATE_CONNECTED = 0,
	SMB_TREE_STATE_DISCONNECTING,
	SMB_TREE_STATE_DISCONNECTED,
	SMB_TREE_STATE_SENTINEL
} smb_tree_state_t;

typedef struct smb_tree {
	uint32_t		t_magic;
	kmutex_t		t_mutex;
	list_node_t		t_lnd;
	smb_tree_state_t	t_state;

	struct smb_server	*t_server;
	smb_session_t		*t_session;
	smb_user_t		*t_user;
	smb_node_t		*t_snode;

	smb_llist_t		t_ofile_list;
	smb_idpool_t		t_fid_pool;

	smb_llist_t		t_odir_list;
	smb_idpool_t		t_odid_pool;

	uint32_t		t_refcnt;
	uint32_t		t_flags;
	int32_t			t_res_type;
	uint16_t		t_tid;
	uint16_t		t_umask;
	char			t_sharename[MAXNAMELEN];
	char			t_resource[MAXPATHLEN];
	char			t_typename[SMB_TYPENAMELEN];
	char			t_volume[SMB_VOLNAMELEN];
	acl_type_t		t_acltype;
	uint32_t		t_access;
	uint32_t		t_shr_flags;
	time_t			t_connect_time;
	volatile uint32_t	t_open_files;
} smb_tree_t;

#define	SMB_TREE_VFS(tree)	((tree)->t_snode->vp->v_vfsp)
#define	SMB_TREE_FSID(tree)	((tree)->t_snode->vp->v_vfsp->vfs_fsid)

#define	SMB_TREE_IS_READONLY(sr)					\
	((sr) != NULL && (sr)->tid_tree != NULL &&			\
	!((sr)->tid_tree->t_access & ACE_ALL_WRITE_PERMS))

#define	SMB_TREE_IS_CASEINSENSITIVE(sr)                                 \
	(((sr) && (sr)->tid_tree) ?                                     \
	smb_tree_has_feature((sr)->tid_tree, SMB_TREE_CASEINSENSITIVE) : 0)

#define	SMB_TREE_HAS_ACCESS(sr, acemask)				\
	((sr) == NULL ? ACE_ALL_PERMS : (				\
	(((sr) && (sr)->tid_tree) ?					\
	(((sr)->tid_tree->t_access) & (acemask)) : 0)))

#define	SMB_TREE_SUPPORTS_CATIA(sr)            				\
	(((sr) && (sr)->tid_tree) ?                                     \
	smb_tree_has_feature((sr)->tid_tree, SMB_TREE_CATIA) : 0)

#define	SMB_TREE_SUPPORTS_ABE(sr)            				\
	(((sr) && (sr)->tid_tree) ?                                     \
	smb_tree_has_feature((sr)->tid_tree, SMB_TREE_ABE) : 0)

/*
 * SMB_TREE_CONTAINS_NODE is used to check that a node is in the same
 * file system as the tree.
 */
#define	SMB_TREE_CONTAINS_NODE(sr, node)                                \
	(((sr) && (sr)->tid_tree) ?                                     \
	(SMB_TREE_VFS((sr)->tid_tree) == SMB_NODE_VFS(node)) : 1)

/*
 * SMB_OFILE_IS_READONLY reflects whether an ofile is readonly or not.
 * The macro takes into account
 *      - the tree readonly state
 *      - the node readonly state
 *      - whether the specified ofile is the readonly creator
 * The readonly creator has write permission until the ofile is closed.
 */

#define	SMB_OFILE_IS_READONLY(of)                               \
	(((of)->f_flags & SMB_OFLAGS_READONLY) ||               \
	smb_node_file_is_readonly((of)->f_node) ||                   \
	(((of)->f_node->readonly_creator) &&                    \
	((of)->f_node->readonly_creator != (of))))

/*
 * SMB_PATHFILE_IS_READONLY indicates whether or not a file is
 * readonly when the caller has a path rather than an ofile.  Unlike
 * SMB_OFILE_IS_READONLY, the caller cannot be the readonly creator,
 * since that requires an ofile.
 */

#define	SMB_PATHFILE_IS_READONLY(sr, node)                       \
	(SMB_TREE_IS_READONLY((sr)) ||                           \
	smb_node_file_is_readonly((node)) ||                          \
	((node)->readonly_creator))

#define	PIPE_STATE_AUTH_VERIFY	0x00000001

/*
 * Data structure for SMB_FTYPE_MESG_PIPE ofiles, which is used
 * at the interface between SMB and NDR RPC.
 */
typedef struct smb_opipe {
	kmutex_t p_mutex;
	kcondvar_t p_cv;
	char *p_name;
	uint32_t p_busy;
	smb_opipe_hdr_t p_hdr;
	smb_netuserinfo_t p_user;
	uint8_t *p_doorbuf;
	uint8_t *p_data;
} smb_opipe_t;

/*
 * The of_ftype	of an open file should contain the SMB_FTYPE value
 * returned when the file/pipe was opened. The following
 * assumptions are currently made:
 *
 * File Type	    Node       PipeInfo
 * ---------	    --------   --------
 * SMB_FTYPE_DISK       Valid      Null
 * SMB_FTYPE_BYTE_PIPE  Undefined  Undefined
 * SMB_FTYPE_MESG_PIPE  Null       Valid
 * SMB_FTYPE_PRINTER    Undefined  Undefined
 * SMB_FTYPE_UNKNOWN    Undefined  Undefined
 */

/*
 * Some flags for ofile structure
 *
 *	SMB_OFLAGS_SET_DELETE_ON_CLOSE
 *   Set this flag when the corresponding open operation whose
 *   DELETE_ON_CLOSE bit of the CreateOptions is set. If any
 *   open file instance has this bit set, the NODE_FLAGS_DELETE_ON_CLOSE
 *   will be set for the file node upon close.
 *
 *	SMB_OFLAGS_TIMESTAMPS_PENDING
 *   This flag gets set when a write operation is performed on the
 *   ofile. The timestamps will be updated, and the flags cleared,
 *   when the ofile gets closed or a setattr is performed on the ofile.
 */

#define	SMB_OFLAGS_READONLY		0x0001
#define	SMB_OFLAGS_EXECONLY		0x0002
#define	SMB_OFLAGS_SET_DELETE_ON_CLOSE	0x0004
#define	SMB_OFLAGS_LLF_POS_VALID	0x0008
#define	SMB_OFLAGS_TIMESTAMPS_PENDING	0x0010

#define	SMB_OFILE_MAGIC 	0x4F464C45	/* 'OFLE' */
#define	SMB_OFILE_VALID(p)	ASSERT((p)->f_magic == SMB_OFILE_MAGIC)

typedef enum {
	SMB_OFILE_STATE_OPEN = 0,
	SMB_OFILE_STATE_CLOSING,
	SMB_OFILE_STATE_CLOSED,
	SMB_OFILE_STATE_SENTINEL
} smb_ofile_state_t;

typedef struct smb_ofile {
	uint32_t		f_magic;
	kmutex_t		f_mutex;
	list_node_t		f_lnd;
	list_node_t		f_nnd;
	smb_ofile_state_t	f_state;

	struct smb_server	*f_server;
	smb_session_t		*f_session;
	smb_user_t		*f_user;
	smb_tree_t		*f_tree;
	smb_node_t		*f_node;
	smb_opipe_t		*f_pipe;

	uint32_t		f_uniqid;
	uint32_t		f_refcnt;
	uint64_t		f_seek_pos;
	uint32_t		f_flags;
	uint32_t		f_granted_access;
	uint32_t		f_share_access;
	uint32_t		f_create_options;
	uint16_t		f_fid;
	uint16_t		f_opened_by_pid;
	uint16_t		f_ftype;
	uint64_t		f_llf_pos;
	int			f_mode;
	cred_t			*f_cr;
	pid_t			f_pid;
	boolean_t		f_oplock_granted;
	boolean_t		f_oplock_exit;
	uint32_t		f_explicit_times;

} smb_ofile_t;

#define	SMB_ODIR_MAGIC 		0x4F444952	/* 'ODIR' */
#define	SMB_ODIR_BUFSIZE	(8 * 1024)

#define	SMB_ODIR_FLAG_WILDCARDS		0x0001
#define	SMB_ODIR_FLAG_IGNORE_CASE	0x0002
#define	SMB_ODIR_FLAG_XATTR		0x0004
#define	SMB_ODIR_FLAG_EDIRENT		0x0008
#define	SMB_ODIR_FLAG_CATIA		0x0010
#define	SMB_ODIR_FLAG_ABE		0x0020

typedef enum {
	SMB_ODIR_STATE_OPEN = 0,
	SMB_ODIR_STATE_IN_USE,
	SMB_ODIR_STATE_CLOSING,
	SMB_ODIR_STATE_CLOSED,
	SMB_ODIR_STATE_SENTINEL
} smb_odir_state_t;

typedef enum {
	SMB_ODIR_RESUME_IDX,
	SMB_ODIR_RESUME_COOKIE,
	SMB_ODIR_RESUME_FNAME
} smb_odir_resume_type_t;

typedef struct smb_odir_resume {
	smb_odir_resume_type_t	or_type;
	int			or_idx;
	uint32_t		or_cookie;
	char			*or_fname;
} smb_odir_resume_t;

/*
 * Flags used when opening an odir
 */
#define	SMB_ODIR_OPENF_BACKUP_INTENT	0x01

typedef struct smb_odir {
	uint32_t		d_magic;
	kmutex_t		d_mutex;
	list_node_t		d_lnd;
	smb_odir_state_t	d_state;
	smb_session_t		*d_session;
	smb_tree_t		*d_tree;
	smb_node_t		*d_dnode;
	cred_t			*d_cred;
	uint16_t		d_odid;
	uint16_t		d_opened_by_pid;
	uint16_t		d_sattr;
	uint32_t		d_refcnt;
	uint32_t		d_flags;
	boolean_t		d_eof;
	int			d_bufsize;
	uint64_t		d_offset;
	union {
		char		*u_bufptr;
		edirent_t	*u_edp;
		dirent64_t	*u_dp;
	} d_u;
	uint32_t		d_cookies[SMB_MAX_SEARCH];
	char			d_pattern[MAXNAMELEN];
	char			d_buf[SMB_ODIR_BUFSIZE];
} smb_odir_t;
#define	d_bufptr	d_u.u_bufptr
#define	d_edp		d_u.u_edp
#define	d_dp		d_u.u_dp

typedef struct smb_odirent {
	char		od_name[MAXNAMELEN];	/* on disk name */
	ino64_t		od_ino;
	uint32_t	od_eflags;
} smb_odirent_t;

typedef struct smb_fileinfo {
	char		fi_name[MAXNAMELEN];
	char		fi_name83[SMB_SHORTNAMELEN];
	char		fi_shortname[SMB_SHORTNAMELEN];
	uint32_t	fi_cookie;
	uint32_t	fi_dosattr;	/* DOS attributes */
	uint64_t	fi_nodeid;	/* file system node id */
	uint64_t	fi_size;	/* file size in bytes */
	uint64_t	fi_alloc_size;	/* allocation size in bytes */
	timestruc_t	fi_atime;	/* last access */
	timestruc_t	fi_mtime;	/* last modification */
	timestruc_t	fi_ctime;	/* last status change */
	timestruc_t	fi_crtime;	/* file creation */
} smb_fileinfo_t;

typedef struct smb_streaminfo {
	uint64_t	si_size;
	uint64_t	si_alloc_size;
	char		si_name[MAXPATHLEN];
} smb_streaminfo_t;

#define	SMB_LOCK_MAGIC 	0x4C4F434B	/* 'LOCK' */

typedef struct smb_lock {
	uint32_t		l_magic;
	kmutex_t		l_mutex;
	list_node_t		l_lnd;
	kcondvar_t		l_cv;

	list_node_t		l_conflict_lnd;
	smb_slist_t		l_conflict_list;

	smb_session_t		*l_session;
	smb_ofile_t		*l_file;
	struct smb_request	*l_sr;

	uint32_t		l_flags;
	uint64_t		l_session_kid;
	struct smb_lock		*l_blocked_by; /* Debug info only */

	uint16_t		l_pid;
	uint16_t		l_uid;
	uint32_t		l_type;
	uint64_t		l_start;
	uint64_t		l_length;
	clock_t			l_end_time;
} smb_lock_t;

#define	SMB_LOCK_FLAG_INDEFINITE	0x0004
#define	SMB_LOCK_INDEFINITE_WAIT(lock) \
	((lock)->l_flags & SMB_LOCK_FLAG_INDEFINITE)

#define	SMB_LOCK_TYPE_READWRITE		101
#define	SMB_LOCK_TYPE_READONLY		102

typedef struct vardata_block {
	uint8_t			vdb_tag;
	uint32_t		vdb_len;
	struct uio 		vdb_uio;
	struct iovec		vdb_iovec[MAX_IOVEC];
} smb_vdb_t;

#define	SMB_WRMODE_WRITE_THRU	0x0001
#define	SMB_WRMODE_IS_STABLE(M)	((M) & SMB_WRMODE_WRITE_THRU)

#define	SMB_RW_MAGIC		0x52445257	/* 'RDRW' */

typedef struct smb_rw_param {
	uint32_t rw_magic;
	smb_vdb_t rw_vdb;
	uint64_t rw_offset;
	uint32_t rw_last_write;
	uint16_t rw_mode;
	uint32_t rw_count;		/* bytes in this request */
	uint16_t rw_mincnt;
	uint32_t rw_total;		/* total bytes (write-raw) */
	uint16_t rw_dsoff;		/* SMB data offset */
	uint8_t rw_andx;		/* SMB secondary andx command */
} smb_rw_param_t;

typedef struct smb_pathname {
	char	*pn_path;
	char	*pn_pname;
	char	*pn_fname;
	char	*pn_sname;
	char	*pn_stype;
} smb_pathname_t;

/*
 * fs_query_info
 */
typedef struct smb_fqi {
	smb_pathname_t	fq_path;
	uint16_t	fq_sattr;
	smb_node_t	*fq_dnode;
	smb_node_t	*fq_fnode;
	smb_attr_t	fq_fattr;
	char		fq_last_comp[MAXNAMELEN];
} smb_fqi_t;

#define	OPLOCK_MIN_TIMEOUT	(5 * 1000)
#define	OPLOCK_STD_TIMEOUT	(15 * 1000)
#define	OPLOCK_RETRIES		2

typedef struct {
	uint32_t severity;
	uint32_t status;
	uint16_t errcls;
	uint16_t errcode;
} smb_error_t;

typedef struct open_param {
	smb_fqi_t	fqi;
	uint16_t	omode;
	uint16_t	ofun;
	uint32_t	nt_flags;
	uint32_t	timeo;
	uint32_t	dattr;
	timestruc_t	crtime;
	timestruc_t	mtime;
	uint64_t	dsize;
	uint32_t	desired_access;
	uint32_t	share_access;
	uint32_t	create_options;
	uint32_t	create_disposition;
	boolean_t	created_readonly;
	uint32_t	ftype;
	uint32_t	devstate;
	uint32_t	action_taken;
	uint64_t	fileid;
	uint32_t	rootdirfid;
	smb_ofile_t	*dir;
	/* This is only set by NTTransactCreate */
	struct smb_sd	*sd;
	uint8_t		op_oplock_level;
} open_param_t;

#define	SMB_OPLOCK_NONE		0
#define	SMB_OPLOCK_EXCLUSIVE	1
#define	SMB_OPLOCK_BATCH	2
#define	SMB_OPLOCK_LEVEL_II	3

/*
 * SMB Request State Machine
 * -------------------------
 *
 *                  T4               +------+		T0
 *      +--------------------------->| FREE |---------------------------+
 *      |                            +------+                           |
 * +-----------+                                                        |
 * | COMPLETED |                                                        |
 * +-----------+
 *      ^                                                               |
 *      | T15                      +----------+                         v
 * +------------+        T6        |          |                 +--------------+
 * | CLEANED_UP |<-----------------| CANCELED |                 | INITIALIZING |
 * +------------+                  |          |                 +--------------+
 *      |    ^                     +----------+                         |
 *      |    |                        ^  ^ ^ ^                          |
 *      |    |          +-------------+  | | |                          |
 *      |    |    T3    |                | | |               T13        | T1
 *      |    +-------------------------+ | | +----------------------+   |
 *      +----------------------------+ | | |                        |   |
 *         T16          |            | | | +-----------+            |   |
 *                      |           \/ | | T5          |            |   v
 * +-----------------+  |   T12     +--------+         |     T2    +-----------+
 * | EVENT_OCCURRED  |------------->| ACTIVE |<--------------------| SUBMITTED |
 * +-----------------+  |           +--------+         |           +-----------+
 *        ^             |              | ^ |           |
 *        |             |           T8 | | |  T7       |
 *        | T10      T9 |   +----------+ | +-------+   |  T11
 *        |             |   |            +-------+ |   |
 *        |             |   |               T14  | |   |
 *        |             |   v                    | v   |
 *      +----------------------+                +--------------+
 *	|     WAITING_EVENT    |                | WAITING_LOCK |
 *      +----------------------+                +--------------+
 *
 *
 *
 *
 *
 * Transition T0
 *
 * This transition occurs when the request is allocated and is still under the
 * control of the session thread.
 *
 * Transition T1
 *
 * This transition occurs when the session thread dispatches a task to treat the
 * request.
 *
 * Transition T2
 *
 *
 *
 * Transition T3
 *
 * A request completes and smbsr_cleanup is called to release resources
 * associated with the request (but not the smb_request_t itself).  This
 * includes references on smb_ofile_t, smb_node_t, and other structures.
 * CLEANED_UP state exists to detect if we attempt to cleanup a request
 * multiple times and to allow us to detect that we are accessing a
 * request that has already been cleaned up.
 *
 * Transition T4
 *
 *
 *
 * Transition T5
 *
 *
 *
 * Transition T6
 *
 *
 *
 * Transition T7
 *
 *
 *
 * Transition T8
 *
 *
 *
 * Transition T9
 *
 *
 *
 * Transition T10
 *
 *
 *
 * Transition T11
 *
 *
 *
 * Transition T12
 *
 *
 *
 * Transition T13
 *
 *
 *
 * Transition T14
 *
 *
 *
 * Transition T15
 *
 * Request processing is completed (control returns from smb_dispatch)
 *
 * Transition T16
 *
 * Multipart (andx) request was cleaned up with smbsr_cleanup but more "andx"
 * sections remain to be processed.
 *
 */

#define	SMB_REQ_MAGIC 		0x534D4252	/* 'SMBR' */
#define	SMB_REQ_VALID(p)	ASSERT((p)->sr_magic == SMB_REQ_MAGIC)

typedef enum smb_req_state {
	SMB_REQ_STATE_FREE = 0,
	SMB_REQ_STATE_INITIALIZING,
	SMB_REQ_STATE_SUBMITTED,
	SMB_REQ_STATE_ACTIVE,
	SMB_REQ_STATE_WAITING_EVENT,
	SMB_REQ_STATE_EVENT_OCCURRED,
	SMB_REQ_STATE_WAITING_LOCK,
	SMB_REQ_STATE_COMPLETED,
	SMB_REQ_STATE_CANCELED,
	SMB_REQ_STATE_CLEANED_UP,
	SMB_REQ_STATE_SENTINEL
} smb_req_state_t;

typedef struct smb_request {
	uint32_t		sr_magic;
	kmutex_t		sr_mutex;
	list_node_t		sr_session_lnd;
	smb_req_state_t		sr_state;
	boolean_t		sr_keep;
	kmem_cache_t		*sr_cache;
	struct smb_server	*sr_server;
	pid_t			*sr_pid;
	int32_t			sr_gmtoff;
	smb_session_t		*session;
	smb_kmod_cfg_t		*sr_cfg;
	smb_notify_change_req_t	sr_ncr;

	/* Info from session service header */
	uint32_t		sr_req_length; /* Excluding NBT header */

	/* Request buffer excluding NBT header */
	void			*sr_request_buf;

	/* Fields for raw writes */
	uint32_t		sr_raw_data_length;
	void			*sr_raw_data_buf;

	smb_lock_t		*sr_awaiting;
	struct mbuf_chain	command;
	struct mbuf_chain	reply;
	struct mbuf_chain	raw_data;
	list_t			sr_storage;
	struct smb_xa		*r_xa;
	int			andx_prev_wct;
	int 			cur_reply_offset;
	int			orig_request_hdr;
	unsigned int		reply_seqnum;	/* reply sequence number */
	unsigned char		first_smb_com;	/* command code */
	unsigned char		smb_com;	/* command code */

	uint8_t			smb_rcls;	/* error code class */
	uint8_t			smb_reh;	/* rsvd (AH DOS INT-24 ERR) */
	uint16_t		smb_err;	/* error code */
	smb_error_t		smb_error;

	uint8_t			smb_flg;	/* flags */
	uint16_t		smb_flg2;	/* flags */
	uint16_t		smb_pid_high;	/* high part of pid */
	unsigned char		smb_sig[8];	/* signiture */
	uint16_t		smb_tid;	/* tree id #  */
	uint16_t		smb_pid;	/* caller's process id # */
	uint16_t		smb_uid;	/* user id # */
	uint16_t		smb_mid;	/* mutiplex id #  */
	unsigned char		smb_wct;	/* count of parameter words */
	uint16_t		smb_bcc;	/* data byte count */

	/* Parameters */
	struct mbuf_chain	smb_vwv;	/* variable width value */

	/* Data */
	struct mbuf_chain	smb_data;

	uint16_t		smb_fid;	/* not in hdr, but common */

	unsigned char		andx_com;
	uint16_t		andx_off;

	struct smb_tree		*tid_tree;
	struct smb_ofile	*fid_ofile;
	smb_user_t		*uid_user;

	union {
	    struct tcon {
		char		*path;
		char		*service;
		int		pwdlen;
		char		*password;
		uint16_t	flags;
		uint16_t	optional_support;
	    } tcon;

	    struct dirop {
		smb_fqi_t	fqi;
		smb_fqi_t	dst_fqi;
		uint16_t	info_level;
		uint16_t	flags;
	    } dirop;

	    open_param_t	open;
	    smb_rw_param_t	*rw;
	    uint32_t		timestamp;
	} arg;

	cred_t			*user_cr;
	kthread_t		*sr_worker;
} smb_request_t;

/*
 * SMB request-specific memory node.
 */
typedef struct smb_srm {
	list_node_t	srm_lnd;
	size_t		srm_size;
	smb_request_t	*srm_sr;
} smb_srm_t;

#define	SMB_READ_PROTOCOL(hdr) \
	LE_IN32(((smb_hdr_t *)(hdr))->protocol)

#define	SMB_PROTOCOL_MAGIC_INVALID(rd_sr) \
	(SMB_READ_PROTOCOL((rd_sr)->sr_request_buf) != SMB_PROTOCOL_MAGIC)

#define	SMB_READ_COMMAND(hdr) \
	(((smb_hdr_t *)(hdr))->command)

#define	SMB_IS_WRITERAW(rd_sr) \
	(SMB_READ_COMMAND((rd_sr)->sr_request_buf) == SMB_COM_WRITE_RAW)


#define	SR_FLG_OFFSET			9

#define	MAX_TRANS_NAME	64

#define	SMB_XA_FLAG_OPEN	0x0001
#define	SMB_XA_FLAG_CLOSE	0x0002
#define	SMB_XA_FLAG_COMPLETE	0x0004
#define	SMB_XA_CLOSED(xa) (!((xa)->xa_flags & SMB_XA_FLAG_OPEN))

#define	SMB_XA_MAGIC		0x534D4258	/* 'SMBX' */

typedef struct smb_xa {
	uint32_t		xa_magic;
	kmutex_t		xa_mutex;
	list_node_t		xa_lnd;

	uint32_t		xa_refcnt;
	uint32_t		xa_flags;

	struct smb_session	*xa_session;

	unsigned char		smb_com;	/* which TRANS type */
	unsigned char		smb_flg;	/* flags */
	uint16_t		smb_flg2;	/* flags */
	uint16_t		smb_tid;	/* tree id number */
	uint16_t		smb_pid;	/* caller's process id number */
	uint16_t		smb_uid;	/* user id number */
	uint32_t		smb_func;	/* NT_TRANS function */

	uint16_t		xa_smb_mid;	/* mutiplex id number */
	uint16_t		xa_smb_fid;	/* TRANS2 secondary */

	unsigned int		reply_seqnum;	/* reply sequence number */

	uint32_t	smb_tpscnt;	/* total parameter bytes being sent */
	uint32_t	smb_tdscnt;	/* total data bytes being sent */
	uint32_t	smb_mprcnt;	/* max parameter bytes to return */
	uint32_t	smb_mdrcnt;	/* max data bytes to return */
	uint32_t	smb_msrcnt;	/* max setup words to return */
	uint32_t	smb_flags;	/* additional information: */
				/*  bit 0 - if set, disconnect TID in smb_tid */
				/*  bit 1 - if set, transaction is one way */
				/*  (no final response) */
	int32_t	smb_timeout;	/* number of milliseconds to await completion */
	uint32_t	smb_suwcnt;	/* set up word count */

	char			*xa_pipe_name;

	int			req_disp_param;
	int			req_disp_data;

	struct mbuf_chain	req_setup_mb;
	struct mbuf_chain	req_param_mb;
	struct mbuf_chain	req_data_mb;

	struct mbuf_chain	rep_setup_mb;
	struct mbuf_chain	rep_param_mb;
	struct mbuf_chain	rep_data_mb;
} smb_xa_t;


#define	SDDF_NO_FLAGS			0
#define	SDDF_SUPPRESS_TID		0x0001
#define	SDDF_SUPPRESS_UID		0x0002

/*
 * SMB dispatch return codes.
 */
typedef enum {
	SDRC_SUCCESS = 0,
	SDRC_ERROR,
	SDRC_DROP_VC,
	SDRC_NO_REPLY,
	SDRC_SR_KEPT,
	SDRC_NOT_IMPLEMENTED
} smb_sdrc_t;

#define	VAR_BCC		((short)-1)

#define	SMB_SERVER_MAGIC	0x53534552	/* 'SSER' */

typedef struct {
	kstat_named_t	open_files;
	kstat_named_t	open_trees;
	kstat_named_t	open_users;
} smb_server_stats_t;

typedef struct {
	kthread_t		*ld_kth;
	kt_did_t		ld_ktdid;
	ksocket_t		ld_so;
	struct sockaddr_in	ld_sin;
	struct sockaddr_in6	ld_sin6;
	smb_session_list_t	ld_session_list;
} smb_listener_daemon_t;

typedef enum smb_server_state {
	SMB_SERVER_STATE_CREATED = 0,
	SMB_SERVER_STATE_CONFIGURED,
	SMB_SERVER_STATE_RUNNING,
	SMB_SERVER_STATE_DELETING,
	SMB_SERVER_STATE_SENTINEL
} smb_server_state_t;

typedef struct smb_server {
	uint32_t		sv_magic;
	kcondvar_t		sv_cv;
	kmutex_t		sv_mutex;
	list_node_t		sv_lnd;
	smb_server_state_t	sv_state;
	uint32_t		sv_refcnt;
	pid_t			sv_pid;
	zoneid_t		sv_zid;
	smb_listener_daemon_t	sv_nbt_daemon;
	smb_listener_daemon_t	sv_tcp_daemon;
	krwlock_t		sv_cfg_lock;
	smb_kmod_cfg_t		sv_cfg;
	smb_session_t		*sv_session;

	kstat_t			*sv_ksp;
	kmutex_t		sv_ksp_mutex;
	char			sv_ksp_name[KSTAT_STRLEN];
	smb_server_stats_t	sv_ks_data;

	door_handle_t		sv_lmshrd;

	int32_t			si_gmtoff;

	smb_thread_t		si_thread_timers;
	smb_thread_t		si_thread_unexport;

	taskq_t			*sv_thread_pool;

	kmem_cache_t		*si_cache_unexport;
	kmem_cache_t		*si_cache_vfs;
	kmem_cache_t		*si_cache_request;
	kmem_cache_t		*si_cache_session;
	kmem_cache_t		*si_cache_user;
	kmem_cache_t		*si_cache_tree;
	kmem_cache_t		*si_cache_ofile;
	kmem_cache_t		*si_cache_odir;

	volatile uint32_t	sv_open_trees;
	volatile uint32_t	sv_open_files;
	volatile uint32_t	sv_open_users;

	smb_node_t		*si_root_smb_node;
	smb_llist_t		sv_vfs_list;
	smb_slist_t		sv_unexport_list;
} smb_server_t;

#define	SMB_INFO_NETBIOS_SESSION_SVC_RUNNING	0x0001
#define	SMB_INFO_NETBIOS_SESSION_SVC_FAILED	0x0002
#define	SMB_INFO_USER_LEVEL_SECURITY		0x40000000
#define	SMB_INFO_ENCRYPT_PASSWORDS		0x80000000

#define	SMB_NEW_KID()	atomic_inc_64_nv(&smb_kids)
#define	SMB_UNIQ_FID()	atomic_inc_32_nv(&smb_fids)

#define	SMB_IS_STREAM(node) ((node)->n_unode)

typedef struct smb_tsd {
	void (*proc)();
	void *arg;
	char name[100];
} smb_tsd_t;

typedef struct smb_disp_entry {
	smb_sdrc_t		(*sdt_pre_op)(smb_request_t *);
	smb_sdrc_t		(*sdt_function)(smb_request_t *);
	void			(*sdt_post_op)(smb_request_t *);
	char			sdt_dialect;
	unsigned char		sdt_flags;
	kstat_named_t		sdt_dispatch_stats; /* invocations */
} smb_disp_entry_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SMBSRV_SMB_KTYPES_H */
