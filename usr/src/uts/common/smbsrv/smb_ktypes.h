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
#include <sys/fem.h>
#include <sys/door.h>
#include <smbsrv/smb.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/mbuf.h>
#include <smbsrv/smb_sid.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/netbios.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/mlsvc.h>

struct smb_request;
struct smb_server;
struct smb_sd;

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

#define	SMB_SEARCH_HIDDEN(sattr) ((sattr) & FILE_ATTRIBUTE_HIDDEN)
#define	SMB_SEARCH_SYSTEM(sattr) ((sattr) & FILE_ATTRIBUTE_SYSTEM)
#define	SMB_SEARCH_DIRECTORY(sattr) ((sattr) & FILE_ATTRIBUTE_DIRECTORY)


extern uint32_t smb_audit_flags;

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
 * Maximum size of a Transport Data Unit
 *     4 --> NBT/TCP Transport Header.
 *    32 --> SMB Header
 *     1 --> Word Count byte
 *   510 --> Maximum Number of bytes of the Word Table (2 * 255)
 *     2 --> Byte count of the data
 * 65535 --> Maximum size of the data
 * -----
 * 66084
 */
#define	SMB_REQ_MAX_SIZE	66080
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

typedef struct smb_malloc_list {
	struct smb_malloc_list	*forw;
	struct smb_malloc_list	*back;
} smb_malloc_list;

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

typedef struct smb_oplock {
	struct smb_ofile	*op_ofile;
	uint32_t		op_flags;
	uint32_t		op_ipaddr;
	uint64_t		op_kid;
} smb_oplock_t;

#define	OPLOCK_FLAG_BREAKING	1

#define	OPLOCK_RELEASE_LOCK_RELEASED	0
#define	OPLOCK_RELEASE_FILE_CLOSED	1

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

#define	SMB_NODE_MAGIC 0x4E4F4445	/* 'NODE' */

typedef enum {
	SMB_NODE_STATE_AVAILABLE = 0,
	SMB_NODE_STATE_DESTROYING
} smb_node_state_t;

typedef struct smb_node {
	uint32_t		n_magic;
	smb_rwx_t		n_lock;
	krwlock_t		n_share_lock;
	list_node_t		n_lnd;
	smb_node_state_t	n_state;
	uint32_t		n_refcnt;
	uint32_t		n_hashkey;
	struct smb_request	*n_sr;
	kmem_cache_t		*n_cache;
	smb_llist_t		*n_hash_bucket;
	uint64_t		n_orig_session_id;
	uint32_t		n_orig_uid;
	smb_llist_t		n_ofile_list;
	smb_llist_t		n_lock_list;
	struct smb_ofile	*readonly_creator;
	volatile int		flags;	/* FILE_NOTIFY_CHANGE_* */
	volatile int		waiting_event; /* # of clients requesting FCN */
	smb_attr_t		attr;
	unsigned int		what;
	u_offset_t		n_size;
	smb_oplock_t		n_oplock;
	struct smb_node		*dir_snode; /* Directory of node */
	struct smb_node		*unnamed_stream_node; /* set in stream nodes */
	/* Credentials for delayed delete */
	cred_t			*delete_on_close_cred;
	char			od_name[MAXNAMELEN];
	vnode_t			*vp;
	smb_audit_buf_node_t	*n_audit_buf;
} smb_node_t;

#define	NODE_FLAGS_NOTIFY_CHANGE	0x10000fff
#define	NODE_OPLOCKS_IN_FORCE		0x0000f000
#define	NODE_OPLOCK_NONE		0x00000000
#define	NODE_EXCLUSIVE_OPLOCK		0x00001000
#define	NODE_BATCH_OPLOCK		0x00002000
#define	NODE_LEVEL_II_OPLOCK		0x00003000
#define	NODE_CAP_LEVEL_II		0x00010000
#define	NODE_PROTOCOL_LOCK		0x00020000
#define	NODE_FLAGS_WRITE_THROUGH	0x00100000
#define	NODE_FLAGS_SYNCATIME		0x00200000
#define	NODE_FLAGS_LOCKED		0x00400000
#define	NODE_FLAGS_ATTR_VALID		0x00800000
#define	NODE_XATTR_DIR			0x01000000
#define	NODE_FLAGS_CREATED		0x04000000
#define	NODE_FLAGS_CHANGED		0x08000000
#define	NODE_FLAGS_WATCH_TREE		0x10000000
#define	NODE_FLAGS_SET_SIZE		0x20000000
#define	NODE_FLAGS_DELETE_ON_CLOSE	0x40000000
#define	NODE_FLAGS_EXECUTABLE		0x80000000

#define	OPLOCK_TYPE(n)			((n)->flags & NODE_OPLOCKS_IN_FORCE)
#define	OPLOCKS_IN_FORCE(n)		(OPLOCK_TYPE(n) != NODE_OPLOCK_NONE)
#define	EXCLUSIVE_OPLOCK_IN_FORCE(n)	\
	(OPLOCK_TYPE(n) == NODE_EXCLUSIVE_OPLOCK)
#define	BATCH_OPLOCK_IN_FORCE(n)	(OPLOCK_TYPE(n) == NODE_BATCH_OPLOCK)
#define	LEVEL_II_OPLOCK_IN_FORCE(n)	(OPLOCK_TYPE(n) == NODE_LEVEL_II_OPLOCK)

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

#define	SMB_SESSION_OFILE_MAX				(16 * 1024)

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
#define	SMB_SESSION_MAGIC 0x53455353	/* 'SESS' */

typedef enum {
	SMB_SESSION_STATE_INITIALIZED = 0,
	SMB_SESSION_STATE_DISCONNECTED,
	SMB_SESSION_STATE_CONNECTED,
	SMB_SESSION_STATE_ESTABLISHED,
	SMB_SESSION_STATE_NEGOTIATED,
	SMB_SESSION_STATE_OPLOCK_BREAKING,
	SMB_SESSION_STATE_WRITE_RAW_ACTIVE,
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
	uint32_t		ipaddr;
	uint32_t		local_ipaddr;
	char 			workstation[SMB_PI_MAX_HOST];
	int			dialect;
	int			native_os;
	uint32_t		capabilities;
	struct smb_sign		signing;

	struct sonode		*sock;

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
	smb_idpool_t		t_sid_pool;

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
} smb_tree_t;

#define	SMB_TREE_VFS(tree)	((tree)->t_snode->vp->v_vfsp)
#define	SMB_TREE_FSID(tree)	((tree)->t_snode->vp->v_vfsp->vfs_fsid)

#define	SMB_TREE_IS_READONLY(sr)                                        \
	(((sr) && (sr)->tid_tree) ?                                     \
	smb_tree_has_feature((sr)->tid_tree, SMB_TREE_READONLY) : 0)

#define	SMB_TREE_IS_CASEINSENSITIVE(sr)                                 \
	(((sr) && (sr)->tid_tree) ?                                     \
	smb_tree_has_feature((sr)->tid_tree, SMB_TREE_CASEINSENSITIVE) : 0)

/*
 * SMB_TREE_CONTAINS_NODE is used to check that a node is in the same
 * file system as the tree.
 */
#define	SMB_TREE_CONTAINS_NODE(sr, node)                                \
	(((sr) && (sr)->tid_tree) ?                                     \
	(SMB_TREE_VFS((sr)->tid_tree) == SMB_NODE_VFS(node)) : 1)

/*
 * SMB_NODE_IS_READONLY(node)
 *
 * This macro indicates whether the DOS readonly bit is set in the node's
 * attribute cache.  The cache reflects what is on-disk.
 */

#define	SMB_NODE_IS_READONLY(node) \
	((node) && (node)->attr.sa_dosattr & FILE_ATTRIBUTE_READONLY)

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
	SMB_NODE_IS_READONLY((of)->f_node) ||                   \
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
	SMB_NODE_IS_READONLY((node)) ||                          \
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
	smb_opipe_context_t p_context;
	uint8_t *p_doorbuf;
	uint8_t *p_data;
} smb_opipe_t;

/*
 * The of_ftype	of an open file should contain the SMB_FTYPE value
 * (cifs.h) returned when the file/pipe was opened. The following
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
 */

#define	SMB_OFLAGS_READONLY		0x0001
#define	SMB_OFLAGS_SET_DELETE_ON_CLOSE	0x0004
#define	SMB_OFLAGS_LLF_POS_VALID	0x0008

#define	SMB_OFILE_MAGIC 	0x4F464C45	/* 'OFLE' */

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
} smb_ofile_t;

/* odir flags bits */
#define	SMB_DIR_FLAG_OPEN	0x0001
#define	SMB_DIR_FLAG_CLOSE	0x0002
#define	SMB_DIR_CLOSED(dir) ((dir)->d_flags & SMB_DIR_FLAG_CLOSE)

#define	SMB_ODIR_MAGIC 	0x4F444952	/* 'ODIR' */

typedef enum {
	SMB_ODIR_STATE_OPEN = 0,
	SMB_ODIR_STATE_CLOSING,
	SMB_ODIR_STATE_CLOSED,
	SMB_ODIR_STATE_SENTINEL
} smb_odir_state_t;

typedef struct smb_odir {
	uint32_t		d_magic;
	kmutex_t		d_mutex;
	list_node_t		d_lnd;
	smb_odir_state_t	d_state;

	smb_session_t		*d_session;
	smb_user_t		*d_user;
	smb_tree_t		*d_tree;

	uint32_t		d_refcnt;
	uint32_t		d_cookie;
	uint32_t		d_cookies[SMB_MAX_SEARCH];
	uint16_t		d_sid;
	uint16_t		d_opened_by_pid;
	uint16_t		d_sattr;
	char			d_pattern[MAXNAMELEN];
	struct smb_node		*d_dir_snode;
	unsigned int 		d_wildcards;
} smb_odir_t;

typedef struct smb_odir_context {
	uint32_t	dc_cookie;
	uint16_t	dc_dattr;
	char		dc_name[MAXNAMELEN]; /* Real 'Xxxx.yyy.xx' */
	char		dc_name83[SMB_SHORTNAMELEN]; /* w/ dot 'XXXX    .XX ' */
	char		dc_shortname[SMB_SHORTNAMELEN]; /* w/ dot 'XXXX.XX' */
	smb_attr_t	dc_attr;
} smb_odir_context_t;

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
	uint8_t			tag;
	uint16_t		len;
	struct uio 		uio;
	struct iovec		iovec[MAX_IOVEC];
} smb_vdb_t;

#define	SMB_RW_MAGIC		0x52445257	/* 'RDRW' */

typedef struct smb_rw_param {
	uint32_t rw_magic;
	smb_vdb_t rw_vdb;
	uint64_t rw_offset;
	uint32_t rw_last_write;
	uint16_t rw_mode;
	uint16_t rw_count;
	uint16_t rw_mincnt;
	uint16_t rw_dsoff;		/* SMB data offset */
	uint8_t rw_andx;		/* SMB secondary andx command */
} smb_rw_param_t;

/*
 * fs_query_info
 */
typedef struct smb_fqi {
	char		*path;
	uint16_t	srch_attr;
	smb_node_t	*dir_snode;
	smb_attr_t	dir_attr;
	char		last_comp[MAXNAMELEN];
	int		last_comp_was_found;
	char		last_comp_od[MAXNAMELEN];
	smb_node_t	*last_snode;
	smb_attr_t	last_attr;
} smb_fqi_t;

#define	SMB_NULL_FQI_NODES(fqi) \
	(fqi).last_snode = NULL;	\
	(fqi).dir_snode = NULL;

#define	FQM_DIR_MUST_EXIST	1
#define	FQM_PATH_MUST_EXIST	2
#define	FQM_PATH_MUST_NOT_EXIST 3

#define	MYF_OPLOCK_MASK		0x000000F0
#define	MYF_OPLOCK_NONE		0x00000000
#define	MYF_EXCLUSIVE_OPLOCK	0x00000010
#define	MYF_BATCH_OPLOCK	0x00000020
#define	MYF_LEVEL_II_OPLOCK	0x00000030
#define	MYF_MUST_BE_DIRECTORY	0x00000100

#define	MYF_OPLOCK_TYPE(o)	    ((o) & MYF_OPLOCK_MASK)
#define	MYF_OPLOCKS_REQUEST(o)	    (MYF_OPLOCK_TYPE(o) != MYF_OPLOCK_NONE)
#define	MYF_IS_EXCLUSIVE_OPLOCK(o)  (MYF_OPLOCK_TYPE(o) == MYF_EXCLUSIVE_OPLOCK)
#define	MYF_IS_BATCH_OPLOCK(o)	    (MYF_OPLOCK_TYPE(o) == MYF_BATCH_OPLOCK)
#define	MYF_IS_LEVEL_II_OPLOCK(o)   (MYF_OPLOCK_TYPE(o) == MYF_LEVEL_II_OPLOCK)

#define	OPLOCK_MIN_TIMEOUT	(5 * 1000)
#define	OPLOCK_STD_TIMEOUT	(15 * 1000)
#define	OPLOCK_RETRIES		2

typedef struct {
	uint32_t severity;
	uint32_t status;
	uint16_t errcls;
	uint16_t errcode;
} smb_error_t;

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
	smb_malloc_list		request_storage;
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
	uint16_t		smb_sid;	/* not in hdr, but common */

	unsigned char		andx_com;
	uint16_t		andx_off;

	struct smb_tree		*tid_tree;
	struct smb_ofile	*fid_ofile;
	struct smb_odir		*sid_odir;
	smb_user_t		*uid_user;

	union {
	    struct tcon {
		char		*path;
		char		*service;
		int		pwdlen;
		char		*password;
		uint16_t	flags;
	    } tcon;

	    struct open_param {
		smb_fqi_t	fqi;
		uint16_t	omode;
		uint16_t	oflags;
		uint16_t	ofun;
		uint32_t	my_flags;
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
		uint32_t	ftype, devstate;
		uint32_t	action_taken;
		uint64_t	fileid;
		uint32_t	rootdirfid;
		/* This is only set by NTTransactCreate */
		struct smb_sd	*sd;
	    } open;

	    struct dirop {
		smb_fqi_t	fqi;
		smb_fqi_t	dst_fqi;
	    } dirop;

	    smb_rw_param_t	*rw;
	    uint32_t		timestamp;
	} arg;

	cred_t			*user_cr;
} smb_request_t;

#define	SMB_READ_PROTOCOL(smb_nh_ptr) \
	LE_IN32(((smb_nethdr_t *)(smb_nh_ptr))->sh_protocol)

#define	SMB_PROTOCOL_MAGIC_INVALID(rd_sr) \
	(SMB_READ_PROTOCOL((rd_sr)->sr_request_buf) != SMB_PROTOCOL_MAGIC)

#define	SMB_READ_COMMAND(smb_nh_ptr) \
	(((smb_nethdr_t *)(smb_nh_ptr))->sh_command)

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


	char			*xa_smb_trans_name;

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
	struct sonode		*ld_so;
	struct sockaddr_in	ld_sin;
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
	kmem_cache_t		*si_cache_node;

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

/*
 * This is to be used by Trans2SetFileInfo
 * and Trans2SetPathInfo
 */
typedef struct smb_trans2_setinfo {
	uint16_t level;
	struct smb_xa *ts_xa;
	struct smb_node *node;
	char *path;
	char name[MAXNAMELEN];
} smb_trans2_setinfo_t;

#define	SMB_IS_STREAM(node) ((node)->unnamed_stream_node)

#ifdef DEBUG
extern uint_t smb_tsd_key;
#endif

typedef struct smb_tsd {
	void (*proc)();
	void *arg;
	char name[100];
} smb_tsd_t;

#define	SMB_INVALID_AMASK		-1
#define	SMB_INVALID_SHAREMODE		-1
#define	SMB_INVALID_CRDISPOSITION	-1

typedef struct smb_dispatch_table {
	smb_sdrc_t		(*sdt_pre_op)(smb_request_t *);
	smb_sdrc_t		(*sdt_function)(smb_request_t *);
	void			(*sdt_post_op)(smb_request_t *);
	char			sdt_dialect;
	unsigned char		sdt_flags;
	krw_t			sdt_slock_mode;
	kstat_named_t		sdt_dispatch_stats; /* invocations */
} smb_dispatch_table_t;

/*
 * Discretionary Access Control List (DACL)
 *
 * A Discretionary Access Control List (DACL), often abbreviated to
 * ACL, is a list of access controls which either allow or deny access
 * for users or groups to a resource. There is a list header followed
 * by a list of access control entries (ACE). Each ACE specifies the
 * access allowed or denied to a single user or group (identified by
 * a SID).
 *
 * There is another access control list object called a System Access
 * Control List (SACL), which is used to control auditing, but no
 * support is provideed for SACLs at this time.
 *
 * ACL header format:
 *
 *    3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *    1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +-------------------------------+---------------+---------------+
 *   |            AclSize            |      Sbz1     |  AclRevision  |
 *   +-------------------------------+---------------+---------------+
 *   |              Sbz2             |           AceCount            |
 *   +-------------------------------+-------------------------------+
 *
 * AclRevision specifies the revision level of the ACL. This value should
 * be ACL_REVISION, unless the ACL contains an object-specific ACE, in which
 * case this value must be ACL_REVISION_DS. All ACEs in an ACL must be at the
 * same revision level.
 *
 * ACE header format:
 *
 *    3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *    1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +---------------+-------+-------+---------------+---------------+
 *   |            AceSize            |    AceFlags   |     AceType   |
 *   +---------------+-------+-------+---------------+---------------+
 *
 * Access mask format:
 *
 *    3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *    1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +---------------+---------------+-------------------------------+
 *   |G|G|G|G|Res'd|A| StandardRights|         SpecificRights        |
 *   |R|W|E|A|     |S|               |                               |
 *   +-+-------------+---------------+-------------------------------+
 *
 *   typedef struct ACCESS_MASK {
 *       WORD SpecificRights;
 *       BYTE StandardRights;
 *       BYTE AccessSystemAcl : 1;
 *       BYTE Reserved : 3;
 *       BYTE GenericAll : 1;
 *       BYTE GenericExecute : 1;
 *       BYTE GenericWrite : 1;
 *       BYTE GenericRead : 1;
 *   } ACCESS_MASK;
 *
 */

#define	ACL_REVISION1			1
#define	ACL_REVISION2			2
#define	MIN_ACL_REVISION2		ACL_REVISION2
#define	ACL_REVISION3			3
#define	ACL_REVISION4			4
#define	MAX_ACL_REVISION		ACL_REVISION4

/*
 * Current ACE and ACL revision Levels
 */
#define	ACE_REVISION			1
#define	ACL_REVISION			ACL_REVISION2
#define	ACL_REVISION_DS			ACL_REVISION4


#define	ACCESS_ALLOWED_ACE_TYPE		0
#define	ACCESS_DENIED_ACE_TYPE		1
#define	SYSTEM_AUDIT_ACE_TYPE		2
#define	SYSTEM_ALARM_ACE_TYPE		3

/*
 *  se_flags
 * ----------
 * Specifies a set of ACE type-specific control flags. This member can be a
 * combination of the following values.
 *
 * CONTAINER_INHERIT_ACE: Child objects that are containers, such as
 *		directories, inherit the ACE as an effective ACE. The inherited
 *		ACE is inheritable unless the NO_PROPAGATE_INHERIT_ACE bit flag
 *		is also set.
 *
 * INHERIT_ONLY_ACE: Indicates an inherit-only ACE which does not control
 *		access to the object to which it is attached.
 *		If this flag is not set,
 *		the ACE is an effective ACE which controls access to the object
 *		to which it is attached.
 * 		Both effective and inherit-only ACEs can be inherited
 *		depending on the state of the other inheritance flags.
 *
 * INHERITED_ACE: Windows 2000/XP: Indicates that the ACE was inherited.
 *		The system sets this bit when it propagates an
 *		inherited ACE to a child object.
 *
 * NO_PROPAGATE_INHERIT_ACE: If the ACE is inherited by a child object, the
 *		system clears the OBJECT_INHERIT_ACE and CONTAINER_INHERIT_ACE
 *		flags in the inherited ACE.
 *		This prevents the ACE from being inherited by
 *		subsequent generations of objects.
 *
 * OBJECT_INHERIT_ACE: Noncontainer child objects inherit the ACE as an
 *		effective ACE.  For child objects that are containers,
 *		the ACE is inherited as an inherit-only ACE unless the
 *		NO_PROPAGATE_INHERIT_ACE bit flag is also set.
 */
#define	OBJECT_INHERIT_ACE		0x01
#define	CONTAINER_INHERIT_ACE		0x02
#define	NO_PROPOGATE_INHERIT_ACE	0x04
#define	INHERIT_ONLY_ACE		0x08
#define	INHERITED_ACE			0x10
#define	INHERIT_MASK_ACE		0x1F


/*
 * These flags are only used in system audit or alarm ACEs to
 * indicate when an audit message should be generated, i.e.
 * on successful access or on unsuccessful access.
 */
#define	SUCCESSFUL_ACCESS_ACE_FLAG	0x40
#define	FAILED_ACCESS_ACE_FLAG		0x80

/*
 * se_bsize is the size, in bytes, of ACE as it appears on the wire.
 * se_sln is used to sort the ACL when it's required.
 */
typedef struct smb_acehdr {
	uint8_t		se_type;
	uint8_t		se_flags;
	uint16_t	se_bsize;
} smb_acehdr_t;

typedef struct smb_ace {
	smb_acehdr_t	se_hdr;
	uint32_t	se_mask;
	list_node_t	se_sln;
	smb_sid_t	*se_sid;
} smb_ace_t;

/*
 * sl_bsize is the size of ACL in bytes as it appears on the wire.
 */
typedef struct smb_acl {
	uint8_t		sl_revision;
	uint16_t	sl_bsize;
	uint16_t	sl_acecnt;
	smb_ace_t	*sl_aces;
	list_t		sl_sorted;
} smb_acl_t;

/*
 * ACE/ACL header size, in byte, as it appears on the wire
 */
#define	SMB_ACE_HDRSIZE		4
#define	SMB_ACL_HDRSIZE		8

/*
 * Security Descriptor (SD)
 *
 * Security descriptors provide protection for objects, for example
 * files and directories. It identifies the owner and primary group
 * (SIDs) and contains an access control list. When a user tries to
 * access an object his SID is compared to the permissions in the
 * DACL to determine if access should be allowed or denied. Note that
 * this is a simplification because there are other factors, such as
 * default behavior and privileges to be taken into account (see also
 * access tokens).
 *
 * The boolean flags have the following meanings when set:
 *
 * SE_OWNER_DEFAULTED indicates that the SID pointed to by the Owner
 * field was provided by a defaulting mechanism rather than explicitly
 * provided by the original provider of the security descriptor. This
 * may affect the treatment of the SID with respect to inheritance of
 * an owner.
 *
 * SE_GROUP_DEFAULTED indicates that the SID in the Group field was
 * provided by a defaulting mechanism rather than explicitly provided
 * by the original provider of the security descriptor.  This may
 * affect the treatment of the SID with respect to inheritance of a
 * primary group.
 *
 * SE_DACL_PRESENT indicates that the security descriptor contains a
 * discretionary ACL. If this flag is set and the Dacl field of the
 * SECURITY_DESCRIPTOR is null, then a null ACL is explicitly being
 * specified.
 *
 * SE_DACL_DEFAULTED indicates that the ACL pointed to by the Dacl
 * field was provided by a defaulting mechanism rather than explicitly
 * provided by the original provider of the security descriptor. This
 * may affect the treatment of the ACL with respect to inheritance of
 * an ACL. This flag is ignored if the DaclPresent flag is not set.
 *
 * SE_SACL_PRESENT indicates that the security descriptor contains a
 * system ACL pointed to by the Sacl field. If this flag is set and
 * the Sacl field of the SECURITY_DESCRIPTOR is null, then an empty
 * (but present) ACL is being specified.
 *
 * SE_SACL_DEFAULTED indicates that the ACL pointed to by the Sacl
 * field was provided by a defaulting mechanism rather than explicitly
 * provided by the original provider of the security descriptor. This
 * may affect the treatment of the ACL with respect to inheritance of
 * an ACL. This flag is ignored if the SaclPresent flag is not set.
 *
 * SE_DACL_PROTECTED Prevents ACEs set on the DACL of the parent container
 * (and any objects above the parent container in the directory hierarchy)
 * from being applied to the object's DACL.
 *
 * SE_SACL_PROTECTED Prevents ACEs set on the SACL of the parent container
 * (and any objects above the parent container in the directory hierarchy)
 * from being applied to the object's SACL.
 *
 * Note that the SE_DACL_PRESENT flag needs to be present to set
 * SE_DACL_PROTECTED and SE_SACL_PRESENT needs to be present to set
 * SE_SACL_PROTECTED.
 *
 * SE_SELF_RELATIVE indicates that the security descriptor is in self-
 * relative form. In this form, all fields of the security descriptor
 * are contiguous in memory and all pointer fields are expressed as
 * offsets from the beginning of the security descriptor.
 *
 *    3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *    1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +---------------------------------------------------------------+
 *   |            Control            |Reserved1 (SBZ)|   Revision    |
 *   +---------------------------------------------------------------+
 *   |                            Owner                              |
 *   +---------------------------------------------------------------+
 *   |                            Group                              |
 *   +---------------------------------------------------------------+
 *   |                            Sacl                               |
 *   +---------------------------------------------------------------+
 *   |                            Dacl                               |
 *   +---------------------------------------------------------------+
 *
 */

#define	SMB_OWNER_SECINFO	0x0001
#define	SMB_GROUP_SECINFO	0x0002
#define	SMB_DACL_SECINFO	0x0004
#define	SMB_SACL_SECINFO	0x0008
#define	SMB_ALL_SECINFO		0x000F
#define	SMB_ACL_SECINFO		(SMB_DACL_SECINFO | SMB_SACL_SECINFO)

#define	SECURITY_DESCRIPTOR_REVISION	1


#define	SE_OWNER_DEFAULTED		0x0001
#define	SE_GROUP_DEFAULTED		0x0002
#define	SE_DACL_PRESENT			0x0004
#define	SE_DACL_DEFAULTED		0x0008
#define	SE_SACL_PRESENT			0x0010
#define	SE_SACL_DEFAULTED		0x0020
#define	SE_DACL_AUTO_INHERIT_REQ	0x0100
#define	SE_SACL_AUTO_INHERIT_REQ	0x0200
#define	SE_DACL_AUTO_INHERITED		0x0400
#define	SE_SACL_AUTO_INHERITED		0x0800
#define	SE_DACL_PROTECTED		0x1000
#define	SE_SACL_PROTECTED		0x2000
#define	SE_SELF_RELATIVE		0x8000

#define	SE_DACL_INHERITANCE_MASK	0x1500
#define	SE_SACL_INHERITANCE_MASK	0x2A00

/*
 * Security descriptor structures:
 *
 * smb_sd_t     SD in SMB pointer form
 * smb_fssd_t   SD in filesystem form
 *
 * Filesystems (e.g. ZFS/UFS) don't have something equivalent
 * to SD. The items comprising a SMB SD are kept separately in
 * filesystem. smb_fssd_t is introduced as a helper to provide
 * the required abstraction for CIFS code.
 */

typedef struct smb_sd {
	uint8_t		sd_revision;
	uint16_t	sd_control;
	smb_sid_t 	*sd_owner;	/* SID file owner */
	smb_sid_t 	*sd_group;	/* SID group (for POSIX) */
	smb_acl_t 	*sd_sacl;	/* ACL System (audits) */
	smb_acl_t 	*sd_dacl;	/* ACL Discretionary (perm) */
} smb_sd_t;

/*
 * SD header size as it appears on the wire
 */
#define	SMB_SD_HDRSIZE	20

/*
 * values for smb_fssd.sd_flags
 */
#define	SMB_FSSD_FLAGS_DIR	0x01

typedef struct smb_fssd {
	uint32_t	sd_secinfo;
	uint32_t	sd_flags;
	uid_t		sd_uid;
	gid_t		sd_gid;
	acl_t		*sd_zdacl;
	acl_t		*sd_zsacl;
} smb_fssd_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SMBSRV_SMB_KTYPES_H */
