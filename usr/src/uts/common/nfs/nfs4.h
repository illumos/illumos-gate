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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NFS4_H
#define	_NFS4_H

#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/fem.h>
#include <rpc/rpc.h>
#include <nfs/nfs.h>

#ifdef _KERNEL
#include <nfs/nfs4_kprot.h>
#include <sys/nvpair.h>
#else
#include <rpcsvc/nfs4_prot.h>
#endif
#include <nfs/nfs4_attr.h>
#include <sys/acl.h>
#include <sys/list.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	NFS4_MAX_SECOID4	65536
#define	NFS4_MAX_UTF8STRING	65536
#define	NFS4_MAX_LINKTEXT4	65536
#define	NFS4_MAX_PATHNAME4	65536

struct nfs_fsl_info {
	uint_t netbuf_len;
	uint_t netnm_len;
	uint_t knconf_len;
	char *netname;
	struct netbuf *addr;
	struct knetconfig *knconf;
};

#ifdef _KERNEL

typedef struct nfs4_fhandle {
	int fh_len;
	char fh_buf[NFS4_FHSIZE];
} nfs4_fhandle_t;

#define	NFS4_MINORVERSION 0
#define	CB4_MINORVERSION 0

/*
 * Set the fattr4_change variable using a time struct. Note that change
 * is 64 bits, but timestruc_t is 128 bits in a 64-bit kernel.
 */
#define	NFS4_SET_FATTR4_CHANGE(change, ts)			\
{							\
	change = (ts).tv_sec;				\
	change <<= 32;					\
	change |= (uint32_t)((ts).tv_nsec);		\
}

/*
 * Server lease period.  Value is in seconds;  Also used for grace period
 */
extern time_t rfs4_lease_time;

/*
 * This set of typedefs and interfaces represent the core or base set
 * of functionality that backs the NFSv4 server's state related data
 * structures.  Since the NFSv4 server needs inter-RPC state to be
 * available that is unrelated to the filesystem (in other words,
 * soft-state), this functionality is needed to maintain that and is
 * written to be somewhat flexible to adapt to the various types of
 * data structures contained within the server.
 *
 * The basic structure at this level is that the server maintains a
 * global "database" which consists of a set of tables.  Each table
 * contains a set of like data structures.  Each table is indexed by
 * at least one hash function and in most cases two hashes.  Each
 * table's characteristics is set when it is created at run-time via
 * rfs4_table_create().  All table creation and related functions are
 * located in nfs4_state.c.  The generic database functionality is
 * located in nfs4_db.c.
 */

typedef struct rfs4_dbe rfs4_dbe_t;		/* basic opaque db entry */
typedef struct rfs4_table rfs4_table_t;		/* basic table type */
typedef struct rfs4_index rfs4_index_t;		/* index */
typedef struct rfs4_database rfs4_database_t;	/* and database */

typedef struct {		/* opaque entry type for later use */
	rfs4_dbe_t *dbe;
} *rfs4_entry_t;

extern rfs4_table_t *rfs4_client_tab;

/* database, table, index creation entry points */
extern rfs4_database_t *rfs4_database_create(uint32_t);
extern void		rfs4_database_shutdown(rfs4_database_t *);
extern void		rfs4_database_destroy(rfs4_database_t *);

extern void		rfs4_database_destroy(rfs4_database_t *);

extern rfs4_table_t	*rfs4_table_create(rfs4_database_t *, char *,
				time_t, uint32_t,
				bool_t (*create)(rfs4_entry_t, void *),
				void (*destroy)(rfs4_entry_t),
				bool_t (*expiry)(rfs4_entry_t),
				uint32_t, uint32_t, uint32_t, id_t);
extern void		rfs4_table_destroy(rfs4_database_t *, rfs4_table_t *);
extern rfs4_index_t	*rfs4_index_create(rfs4_table_t *, char *,
				uint32_t (*hash)(void *),
				bool_t (compare)(rfs4_entry_t, void *),
				void *(*mkkey)(rfs4_entry_t), bool_t);
extern void		rfs4_index_destroy(rfs4_index_t *);

/* Type used to direct rfs4_dbsearch() in what types of records to inspect */
typedef enum {RFS4_DBS_VALID, RFS4_DBS_INVALID} rfs4_dbsearch_type_t;
/* search and db entry manipulation entry points */
extern rfs4_entry_t	rfs4_dbsearch(rfs4_index_t *, void *,
				bool_t *, void *, rfs4_dbsearch_type_t);
extern void		rfs4_dbe_lock(rfs4_dbe_t *);
extern void		rfs4_dbe_unlock(rfs4_dbe_t *);
extern clock_t		rfs4_dbe_twait(rfs4_dbe_t *, clock_t);
extern void		rfs4_dbe_cv_broadcast(rfs4_dbe_t *);
extern void		rfs4_dbe_hold(rfs4_dbe_t *);
extern void		rfs4_dbe_hold_nolock(rfs4_dbe_t *);
extern void		rfs4_dbe_rele_nolock(rfs4_dbe_t *);
extern void		rfs4_dbe_rele(rfs4_dbe_t *);
extern uint32_t	rfs4_dbe_refcnt(rfs4_dbe_t *);
extern id_t		rfs4_dbe_getid(rfs4_dbe_t *);
extern void		rfs4_dbe_invalidate(rfs4_dbe_t *);
extern bool_t		rfs4_dbe_is_invalid(rfs4_dbe_t *);
extern time_t		rfs4_dbe_get_timerele(rfs4_dbe_t *);
extern void		rfs4_dbe_hide(rfs4_dbe_t *);
extern void		rfs4_dbe_unhide(rfs4_dbe_t *);
#ifdef DEBUG
extern bool_t		rfs4_dbe_islocked(rfs4_dbe_t *);
#endif
extern void		rfs4_dbe_walk(rfs4_table_t *,
			void (*callout)(rfs4_entry_t, void *), void *);

/*
 * Minimal server stable storage.
 *
 * Currently the NFSv4 server will only save the client
 * ID (the long version) so that it will be able to
 * grant possible reclaim requests during the infamous
 * grace_period.
 */

#define	RFS4_SS_DIRSIZE	64 * 1024
#define	NFS4_SS_VERSION 1

/* handy pathname structure */
typedef struct ss_pn {
	char *leaf;
	char pn[MAXPATHLEN];
} rfs4_ss_pn_t;

/*
 * The server will build this link list on startup. It represents the
 * clients that have had valid state on the server in a prior instance.
 *
 */
typedef struct rfs4_oldstate {
	struct rfs4_oldstate 	*next;
	struct rfs4_oldstate 	*prev;
	rfs4_ss_pn_t		*ss_pn;
	nfs_client_id4		cl_id4;
} rfs4_oldstate_t;

/*
 * This union is used to overlay the server's internal treatment of
 * the protocols stateid4 datatype.  Therefore, "bits" must not exceed
 * the size of stateid4 and more importantly should match the size of
 * stateid4.  The chgseq field must the first entry since it overlays
 * stateid4.seqid.
 */
typedef union {
	stateid4 stateid;
	struct {
		uint32_t chgseq;	/* State changes / protocol's seqid */
		uint32_t boottime;	/* boot time  */
		uint32_t type:2;	/* stateid_type_t as define below */
		uint32_t clnodeid:8;	/* cluster server nodeid */
		uint32_t ident:22;	/* 2^22-1 openowner x fhs */
		pid_t	 pid;		/* pid of corresponding lock owner */
	} bits;
} stateid_t;
/*
 * Note that the way the type field above is defined, this enum must
 * not have more than 4 members.
 */
typedef enum {OPENID, LOCKID, DELEGID} stateid_type_t;


/*
 * Set of RPC credentials used for a particular operation.
 * Used for operations like SETCLIENTID_CONFIRM where the
 * credentials needs to match those used at SETCLIENTID.
 */
typedef void *cred_set_t;		/* For now XXX */

/*
 * "wait" struct for use in the open open and lock owner state
 * structures to provide serialization between server threads that are
 * handling requests for the same open owner or lock stateid.  This
 * way only one thread will be updating things like sequence ids,
 * replay cache and stateid at a time.
 */
typedef struct rfs4_state_wait {
	uint32_t		sw_active;
	uint32_t		sw_wait_count;
	kmutex_t		sw_cv_lock[1];
	kcondvar_t		sw_cv[1];
} rfs4_state_wait_t;

extern void	rfs4_sw_enter(rfs4_state_wait_t *);
extern void	rfs4_sw_exit(rfs4_state_wait_t *);

/*
 * This enum and the following rfs4_cbinfo_t struct are used to
 * maintain information about the callback path used from the server
 * to client for operations like CB_GETATTR and CB_RECALL.  The
 * rfs4_cbinfo_t struct is meant to be encompassed in the client
 * struct and managed within that structure's locking scheme.
 *
 * The various states of the callback path are used by the server to
 * determine if delegations should initially be provided to a client
 * and then later on if connectivity has been lost and delegations
 * should be revoked.
 */

/*
 * CB_NOCHANGE - Special value used for interfaces within the delegation
 *		code to signify that "no change" has occurred to the
 *		callback path
 * CB_UNINIT	- No callback info provided by the client
 * CB_NONE	- Callback info provided but CB_NULL call
 *		  has yet to be attempted
 * CB_OK	- Callback path tested with CB_NULL with success
 * CB_INPROG	- Callback path currently being tested with CB_NULL
 * CB_FAILED	- Callback path was == CB_OK but has failed
 *		  with timeout/rpc error
 * CB_BAD	- Callback info provided but CB_NULL failed
 */
typedef enum {
	CB_NOCHANGE = 0,
	CB_UNINIT = 1,
	CB_NONE = 2,
	CB_OK = 3,
	CB_INPROG = 4,
	CB_FAILED = 5,
	CB_BAD = 6
} rfs4_cbstate_t;

#define	RFS4_CBCH_MAX	10	/* size callback client handle cache */
/*
 * Callback info for a client.
 * Client only provides: cb_client4 and cb_ident
 * The rest of the information is used to track callback path status
 * and usage.
 *
 * cb_state - used as comments for the rfs4_cbstate_t enum indicate
 * cb_notified_of_cb_path_down - if the callback path was once CB_OK and
 *	has hence CB_FAILED, the client needs to be notified via RENEW.
 * cb_timefailed - current time when cb_state transitioned from
 *	CB_OK -> CB_FAILED.  Meant for observability.  When did that happen?
 * cb_chc_free/cb_chc - cache of client handles for the callback path
 * cb_ident - SETCLIENTID provided callback_ident value
 * callback - SETCLIENTID provided cb_client4 value
 * cb_refcnt - current number of users of this structure's content
 *	protected by cb_lock
 * cb_badbehavior - how many times did a client do something we didn't like?
 * cb_lock - lock for contents of cbinfo
 * cb_cv - used to allow threads to wait on CB_NULL completion
 * cb_nullcaller - is there a thread currently taking care of
 *	new callback information?
 * cb_cv_nullcaller - used by the thread doing CB_NULL to wait on
 *	threads that may be using client handles of the current
 *	client handle cache.
 * newer - new callback info provided by a client and awaiting
 *	CB_NULL testing and move to regular cbinfo.
 */
typedef struct {
	rfs4_cbstate_t	cb_state;
	unsigned	cb_notified_of_cb_path_down:1;
	time_t		cb_timefailed;
	int		cb_chc_free;
	CLIENT		*cb_chc[RFS4_CBCH_MAX];
	uint32_t	cb_ident;
	cb_client4	cb_callback;
	uint32_t	cb_refcnt;
	uint32_t	cb_badbehavior;
	kmutex_t	cb_lock[1];
	kcondvar_t	cb_cv[1];
	bool_t		cb_nullcaller;
	kcondvar_t	cb_cv_nullcaller[1];
	struct {
		bool_t		cb_new;
		bool_t		cb_confirmed;
		uint32_t	cb_ident;
		cb_client4	cb_callback;
	} cb_newer;
} rfs4_cbinfo_t;

/*
 * A server instance. We can associate sets of clients - via a pointer in
 * rfs4_client_t - with a given server instance, allowing us to treat clients
 * in the set differently to clients in other sets.
 *
 * Currently used only for Sun Cluster HA-NFS support, to group clients
 * on NFS resource failover so each set of clients gets its own dedicated
 * grace period and distributed stable storage data.
 */
typedef struct rfs4_servinst {
	int			dss_npaths;
	krwlock_t		rwlock;
	krwlock_t		oldstate_lock;
	time_t			start_time;
	time_t			grace_period;
	rfs4_oldstate_t		*oldstate;
	struct rfs4_dss_path	**dss_paths;
	struct rfs4_servinst	*next;
	struct rfs4_servinst	*prev;
} rfs4_servinst_t;

/*
 * DSS: distributed stable storage
 */

typedef struct rfs4_dss_path {
	struct rfs4_dss_path	*next; /* for insque/remque */
	struct rfs4_dss_path	*prev; /* for insque/remque */
	char			*path;
	struct rfs4_servinst	*sip;
	unsigned		index; /* offset in servinst's array */
} rfs4_dss_path_t;

/* array of paths passed-in from nfsd command-line; stored in nvlist */
char		**rfs4_dss_newpaths;
uint_t		rfs4_dss_numnewpaths;

/*
 * Circular doubly-linked list of paths for currently-served RGs.
 * No locking required: only changed on warmstart. Managed with insque/remque.
 */
rfs4_dss_path_t	*rfs4_dss_pathlist;

/* nvlists of all DSS paths: current, and before last warmstart */
nvlist_t *rfs4_dss_paths, *rfs4_dss_oldpaths;

/*
 * The server maintains a set of state on a per client basis that
 * matches that of the protocol requirements.  A client's state is
 * rooted with the rfs4_client_t struct of which there is one per
 * client and is created when SETCLIENTID/SETCLIENTID_CONFIRM are
 * received.  From there, the server then creates rfs4_openowner_t
 * structs for each new open owner from that client and are initiated
 * at OPEN/OPEN_CONFIRM (when the open owner is new to the server).
 * At OPEN, at least two other structures are created, and potentially a
 * third.  rfs4_state_t is created to track the association between an
 * open owner and a particular file. An rfs4_file_t struct may be
 * created (if the file is not already open) at OPEN as well.  The
 * rfs4_file_t struct is the only one that is per server and not per
 * client.  The rfs4_deleg_state_t struct is created in the
 * instance that the server is going to provide a delegation for the
 * file being OPENed.  Finally, the rfs4_lockowner_t is created at the
 * first use of a lock owner at the server and is a result of the LOCK
 * operation.  The rfs4_lo_state_t struct is then created to represent
 * the relation between the lock owner and the file.
 *
 */
/*
 * The following ascii art represents each of these data structs and
 * their references to each other.  Note: "<-(x)->" represents the
 * doubly link lists (list_t).
 *
 *                          ____________________
 *                         |                    |
 *                         |    rfs4_client_t   |
 *                       ->|         (1)        |<-
 *                      /  |____________________|  \
 *                     /              ^             \
 *                    /               |              \
 *  ____________________    ____________________    ____________________
 * |                    |  |                    |  |                    |
 * |  rfs4_lockowner_t  |  |  rfs4_openowner_t  |  | rfs4_deleg_state_t |
 * |                    |  |     (3)    <-(1)-> |  |            <-(2)-> |
 * |____________________|  |____________________|  |____________________|
 *           ^                        ^                       |
 *           |                        |                       V
 *  ____________________    ____________________    ____________________
 * |                    |  |                    |  |                    |
 * |  rfs4_lo_state_t   |->|    rfs4_state_t    |->|     rfs4_file_t    |
 * |            <-(4)-> |  |     (4)    <-(3)-> |  |        (2)         |
 * |____________________|  |____________________|  |____________________|
 */
/*
 * Each of these data types are kept in a separate rfs4_table_t and is
 * actually encapsulated within a rfs4_dbe_t struct.  The various
 * tables and their construction is done in nfs4_state.c but
 * documented here to completeness.
 *
 * Table		Data struct stored	Indexed by
 * -----		------------------	----------
 * rfs4_client_tab	rfs4_client_t		nfs_client_id4
 *						clientid4
 *
 * rfs4_openowner_tab	rfs4_openowner_t	open_owner4
 *
 * rfs4_state_tab	rfs4_state_t		open_owner4 | file
 *						stateid
 *
 * rfs4_lo_state_tab	rfs4_lo_state_t		lockowner | stateid
 *						lock_stateid
 *
 * rfs4_lockowner_tab	rfs4_lockowner_t	lockowner
 *						pid
 *
 * rfs4_file_tab	rfs4_file_t		filehandle
 *
 * rfs4_deleg_state_tab	rfs4_deleg_state_t	clientid4 | file
 *						deleg_stateid
 */

/*
 * The client struct, it is the root of all state for a particular
 * client.  The client is identified by the nfs_client_id4 via
 * SETCLIENTID and the server returns the clientid4 as short hand reference
 */
/*
 * Client struct - as mentioned above it is the root of all state for
 * a single client as identified by the client supplied nfs_client_id4
 *
 * dbe - encapsulation struct
 * clientid - server assigned short hand reference to client
 * nfs_client - client supplied identifier for itself
 * confirm_verf - the value provided to the client for SETCLIENTID_CONFIRM
 * need_confirm - does this client need to be SETCLIENTID_CONFIRMed?
 *
 * unlksys_completed - has an F_UNLKSYS been done for this client which
 *		says that the use of cleanlocks() on individual files
 *		is not required?
 * can_reclaim - indicates if client is allowed to reclaim after server
 * 		start-up (client had previous state at server)
 * ss_remove - indicates that the rfs4_client_destroy function should
 * 		clean up stable storage file.
 * forced_expire - set if the sysadmin has used clear_locks for this client.
 * no_referrals - set if the client is Solaris and pre-dates referrals
 * deleg_revoked - how many delegations have been revoked for this client?
 *
 * cp_confirmed - this refers to a confirmed client struct that has
 * the same nfs_client_id4 as this client struct.  When/if this client
 * struct is confirmed via SETCLINETID_CONFIRM, the previously
 * confirmed client struct will be "closed" and hence this reference.
 *
 * last_access - used to determine if the client has let its lease expire
 * cbinfo - struct containing all callback related information
 * cr_set - credentials used for the SETCLIENTID/SETCLIENTID_CONFIRM pair
 * sysid - the lock manager sysid allocated for this client's file locks
 * openownerlist - root of openowners list associated with this client
 * ss_pn - Pathname to the stable storage file.
 * cl_addr - Clients network address.
 * server_instance - pointer to the currently associated server instance
 */
typedef struct rfs4_client {
	rfs4_dbe_t		*rc_dbe;
	clientid4		rc_clientid;
	nfs_client_id4		rc_nfs_client;
	verifier4		rc_confirm_verf;
	unsigned		rc_need_confirm:1;
	unsigned		rc_unlksys_completed:1;
	unsigned		rc_can_reclaim:1;
	unsigned 		rc_ss_remove:1;
	unsigned		rc_forced_expire:1;
	uint_t			rc_deleg_revoked;
	struct rfs4_client	*rc_cp_confirmed;
	time_t			rc_last_access;
	rfs4_cbinfo_t		rc_cbinfo;
	cred_set_t		rc_cr_set;
	sysid_t			rc_sysidt;
	list_t			rc_openownerlist;
	rfs4_ss_pn_t		*rc_ss_pn;
	struct sockaddr_storage rc_addr;
	rfs4_servinst_t		*rc_server_instance;
} rfs4_client_t;

/*
 * ClntIP struct - holds the diagnosis about whether the client
 * cannot support referrals.  Set to true for old Solaris clients.
 */

typedef struct rfs4_clntip {
	rfs4_dbe_t		*ri_dbe;
	struct sockaddr_storage ri_addr;
	unsigned		ri_no_referrals:1;
} rfs4_clntip_t;

/*
 * The openowner contains the client supplied open_owner4 as well as
 * the matching sequence id and is used to track the client's usage of
 * the open_owner4.  Note that a reply is saved here as well for
 * processing of retransmissions.
 *
 * dbe - encapsulation struct
 * client - reference to rfs4_client_t for this openowner
 * owner - actual client supplied open_owner4
 * need_confirm - does this openowner need to be OPEN_CONFIRMed
 * postpone_confirm - set if error received on first use of open_owner
 * state2confirm - what stateid4 should be used on the OPEN_CONFIRM
 * open_seqid - what is the next open_seqid expected for this openowner
 * oo_sw - used to serialize access to the open seqid/reply handling
 * cr_set - credential used for the OPEN
 * statelist - root of state struct list associated with this openowner
 * node - node for client struct list of openowners
 * reply_fh - open replay processing needs the filehandle so that it is
 *	able to reset the current filehandle for appropriate compound
 *	processing and reply.
 * reply - last reply sent in relation to this openowner
 */
typedef struct rfs4_openowner {
	rfs4_dbe_t		*ro_dbe;
	rfs4_client_t		*ro_client;
	open_owner4		ro_owner;
	unsigned		ro_need_confirm:1;
	unsigned		ro_postpone_confirm:1;
	seqid4			ro_open_seqid;
	rfs4_state_wait_t	ro_sw;
	cred_set_t		ro_cr_set;
	list_t			ro_statelist;
	list_node_t		ro_node;
	nfs_fh4			ro_reply_fh;
	nfs_resop4		ro_reply;
} rfs4_openowner_t;

/*
 * This state struct represents the association between an openowner
 * and a file that has been OPENed by that openowner.
 *
 * dbe - encapsulation struct
 * stateid - server provided stateid
 * owner - reference back to the openowner for this state
 * finfo - reference to the open file for this state
 * open_access - how did the openowner OPEN the file (access)
 * open_deny - how did the openowner OPEN the file (deny)
 * share_access - what share reservation is on the file (access)
 * share_deny - what share reservation is on the file (deny)
 * closed - has this file been closed?
 * lostatelist - root of list of lo_state associated with this state/file
 * node - node for state struct list of states
 */
typedef struct rfs4_state {
	rfs4_dbe_t		*rs_dbe;
	stateid_t		rs_stateid;
	rfs4_openowner_t	*rs_owner;
	struct rfs4_file	*rs_finfo;
	uint32_t		rs_open_access;
	uint32_t		rs_open_deny;
	uint32_t		rs_share_access;
	uint32_t		rs_share_deny;
	unsigned		rs_closed:1;
	list_t			rs_lostatelist;
	list_node_t		rs_node;
} rfs4_state_t;

/*
 * Lockowner - track the lockowner and its related info
 *
 * dbe - encapsulation struct
 * client - reference to the client
 * owner - lockowner supplied by the client
 * pid - local identifier used for file locking
 */
typedef struct rfs4_lockowner {
	rfs4_dbe_t		*rl_dbe;
	rfs4_client_t		*rl_client;
	lock_owner4		rl_owner;
	pid_t			rl_pid;
} rfs4_lockowner_t;

/*
 * Lockowner_state associated with a state struct and lockowner
 *
 * dbe - encapsulation struct
 * state - reference back to state struct for open file
 * lockid - stateid for this lockowner/state
 * locker - reference to lockowner
 * seqid - sequence id for this lockowner/state
 * skip_seqid_check - used on initialization of struct
 * locks_cleaned - have all locks been released for this lockowner/file?
 * lock_completed - successful LOCK with lockowner/file?
 * ls_sw - used to serialize update seqid/reply/stateid handling
 * node - node for state struct list of lo_states
 * reply - last reply sent in relation to this lockowner/state
 */
typedef struct rfs4_lo_state {
	rfs4_dbe_t		*rls_dbe;
	rfs4_state_t		*rls_state;
	stateid_t		rls_lockid;
	rfs4_lockowner_t	*rls_locker;
	seqid4			rls_seqid;
	unsigned		rls_skip_seqid_check:1;
	unsigned		rls_locks_cleaned:1;
	unsigned		rls_lock_completed:1;
	rfs4_state_wait_t	rls_sw;
	list_node_t		rls_node;
	nfs_resop4		rls_reply;
} rfs4_lo_state_t;

/*
 * Delegation state - per client
 *
 * dbe - encapsulation struct
 * dtype - type of delegation (NONE, READ, WRITE)
 * delegid - stateid for this delegation
 * time_granted - time this delegation was assigned to client
 * time_recalled - time when the server started recall process
 * time_revoked - if revoked, time that the revoke occurred
 * finfo - reference to the file associated with this delegation
 * client - reference to client for which this delegation is associated
 * node - list of delegations for the file (WRITE == 1, READ == )
 */
typedef struct rfs4_deleg_state {
	rfs4_dbe_t		*rds_dbe;
	open_delegation_type4	rds_dtype;
	stateid_t		rds_delegid;
	time_t			rds_time_granted;
	time_t			rds_time_recalled;
	time_t			rds_time_revoked;
	struct rfs4_file	*rds_finfo;
	rfs4_client_t		*rds_client;
	list_node_t		rds_node;
} rfs4_deleg_state_t;

/*
 * Delegation info associated with the file
 *
 * dtype - type of delegation for file (NONE, READ, WRITE)
 * time_returned - time that last delegation was returned for file
 * time_recalled - time that recall sequence started
 * time_lastgrant - time that last delegation was provided to a client
 * time_lastwrite - time of last write to use the delegation stateid
 * time_rm_delayed - time of last remove/rename which was DELAYed
 * rdgrants - how many read delegations have been provided for this file
 * wrgrants - how many write delegations provided (can only be one)
 * recall_count - how many recall threads are outstanding
 * recall_lock - lock to protect contents of this struct
 * recall_cv - condition var for the "parent" thread to wait upon
 * deleg_change_grant - value for change attribute at time of write grant
 * deleg_change - most recent value of change obtained from client
 * deleg_change_ts - time of last deleg_change update
 * ever_recalled - has this particular delegation ever been recalled?
 * dont_grant - file deletion is impending, don't grant a delegation
 * conflicted_client - clientid of the client that caused a CB_RECALL
 *	to occur. This is used for delegation policy (should a delegation
 *	be granted shortly after it has been returned?)
 */
typedef struct rfs4_dinfo {
	open_delegation_type4 rd_dtype;
	time_t		rd_time_returned;
	time_t		rd_time_recalled;
	time_t		rd_time_lastgrant;
	time_t		rd_time_lastwrite;
	time_t		rd_time_rm_delayed;
	uint32_t	rd_rdgrants;
	uint32_t	rd_wrgrants;
	int32_t		rd_recall_count;
	kmutex_t	rd_recall_lock[1];
	kcondvar_t	rd_recall_cv[1];
	bool_t		rd_ever_recalled;
	uint32_t	rd_hold_grant;
	clientid4	rd_conflicted_client;
} rfs4_dinfo_t;

/*
 * File
 *
 * dbe - encapsulation struct
 * vp - vnode for the file that is open or has a delegation
 * filehandle - the filehandle generated by the server for this file
 * delegstatelist - root of delegation list for this file
 * dinfo - see struct definition above
 * share_deny - union of all deny modes on file
 * share_access - union of all access modes on file
 * access_read - count of read access
 * access_write - count of write access
 * deny_read - count of deny reads
 * deny_write - count of deny writes
 * file_rwlock - lock for serializing the removal of a file while
 *	the state structures are active within the server
 *
 * 	The only requirement for locking file_rwlock is that the
 * 	caller have a reference to the containing rfs4_file.  The dbe
 * 	lock may or may not be held for lock/unlock of file_rwlock.
 * 	As mentioned above, the file_rwlock is used for serialization
 * 	of file removal and more specifically reference to the held
 * 	vnode (e.g. vp).
 */
typedef struct rfs4_file {
	rfs4_dbe_t	*rf_dbe;
	vnode_t		*rf_vp;
	nfs_fh4		rf_filehandle;
	list_t		rf_delegstatelist;
	rfs4_dinfo_t	rf_dinfo;
	uint32_t	rf_share_deny;
	uint32_t	rf_share_access;
	uint32_t	rf_access_read;
	uint32_t	rf_access_write;
	uint32_t	rf_deny_read;
	uint32_t	rf_deny_write;
	krwlock_t	rf_file_rwlock;
} rfs4_file_t;

extern int	rfs4_seen_first_compound;	/* set first time we see one */

extern rfs4_servinst_t	*rfs4_cur_servinst;	/* current server instance */
extern kmutex_t		rfs4_servinst_lock;	/* protects linked list */
extern void		rfs4_servinst_create(int, int, char **);
extern void		rfs4_servinst_destroy_all(void);
extern void		rfs4_servinst_assign(rfs4_client_t *,
			    rfs4_servinst_t *);
extern rfs4_servinst_t	*rfs4_servinst(rfs4_client_t *);
extern int		rfs4_clnt_in_grace(rfs4_client_t *);
extern int		rfs4_servinst_in_grace(rfs4_servinst_t *);
extern int		rfs4_servinst_grace_new(rfs4_servinst_t *);
extern void		rfs4_grace_start(rfs4_servinst_t *);
extern void		rfs4_grace_start_new(void);
extern void		rfs4_grace_reset_all(void);
extern void		rfs4_ss_oldstate(rfs4_oldstate_t *, char *, char *);
extern void		rfs4_dss_readstate(int, char **);

/*
 * rfs4_deleg_policy is used to signify the server's global delegation
 * policy.  The default is to NEVER delegate files and the
 * administrator must configure the server to enable delegations.
 *
 * The disable/enable delegation functions are used to eliminate a
 * race with exclusive creates.
 */
typedef enum {
	SRV_NEVER_DELEGATE = 0,
	SRV_NORMAL_DELEGATE = 1
} srv_deleg_policy_t;

extern srv_deleg_policy_t rfs4_deleg_policy;
extern kmutex_t rfs4_deleg_lock;
extern void rfs4_disable_delegation(void), rfs4_enable_delegation(void);

/*
 * Request types for delegation. These correspond with
 * open_delegation_type4 with the addition of a new value, DELEG_ANY,
 * to reqequest any delegation.
 */
typedef enum {
	DELEG_NONE = 0,		/* Corresponds to OPEN_DELEG_NONE */
	DELEG_READ = 1,		/* Corresponds to OPEN_DELEG_READ */
	DELEG_WRITE = 2,	/* Corresponds to OPEN_DELEG_WRITE */
	DELEG_ANY = -1		/* New value to request any delegation type */
} delegreq_t;

#define	NFS4_DELEG4TYPE2REQTYPE(x) (delegreq_t)(x)

/*
 * Various interfaces to manipulate the state structures introduced
 * above
 */
extern	kmutex_t	rfs4_state_lock;
extern	void		rfs4_clean_state_exi(struct exportinfo *exi);
extern	void		rfs4_free_reply(nfs_resop4 *);
extern	void		rfs4_copy_reply(nfs_resop4 *, nfs_resop4 *);

/* rfs4_client_t handling */
extern	rfs4_client_t	*rfs4_findclient(nfs_client_id4 *,
					bool_t *, rfs4_client_t *);
extern	rfs4_client_t	*rfs4_findclient_by_id(clientid4, bool_t);
extern	rfs4_client_t	*rfs4_findclient_by_addr(struct sockaddr *);
extern	void		rfs4_client_rele(rfs4_client_t *);
extern	void		rfs4_client_close(rfs4_client_t *);
extern	void		rfs4_client_state_remove(rfs4_client_t *);
extern	void		rfs4_client_scv_next(rfs4_client_t *);
extern	void		rfs4_update_lease(rfs4_client_t *);
extern	bool_t		rfs4_lease_expired(rfs4_client_t *);
extern	nfsstat4	rfs4_check_clientid(clientid4 *, int);

/* rfs4_clntip_t handling */
extern	rfs4_clntip_t	*rfs4_find_clntip(struct sockaddr *, bool_t *);
extern	void		rfs4_invalidate_clntip(struct sockaddr *);

/* rfs4_openowner_t handling */
extern	rfs4_openowner_t *rfs4_findopenowner(open_owner4 *, bool_t *, seqid4);
extern	void		rfs4_update_open_sequence(rfs4_openowner_t *);
extern	void		rfs4_update_open_resp(rfs4_openowner_t *,
					nfs_resop4 *, nfs_fh4 *);
extern	void		rfs4_openowner_rele(rfs4_openowner_t *);
extern	void		rfs4_free_opens(rfs4_openowner_t *, bool_t, bool_t);

/* rfs4_lockowner_t handling */
extern	rfs4_lockowner_t *rfs4_findlockowner(lock_owner4 *, bool_t *);
extern	rfs4_lockowner_t *rfs4_findlockowner_by_pid(pid_t);
extern	void		rfs4_lockowner_rele(rfs4_lockowner_t *);

/* rfs4_state_t handling */
extern	rfs4_state_t	*rfs4_findstate_by_owner_file(rfs4_openowner_t *,
					rfs4_file_t *, bool_t *);
extern	void		rfs4_state_rele(rfs4_state_t *);
extern	void		rfs4_state_close(rfs4_state_t *, bool_t,
					bool_t, cred_t *);
extern	void		rfs4_release_share_lock_state(rfs4_state_t *,
					cred_t *, bool_t);
extern	void		rfs4_close_all_state(rfs4_file_t *);

/* rfs4_lo_state_t handling */
extern	rfs4_lo_state_t *rfs4_findlo_state_by_owner(rfs4_lockowner_t *,
						rfs4_state_t *, bool_t *);
extern	void		rfs4_lo_state_rele(rfs4_lo_state_t *, bool_t);
extern	void		rfs4_update_lock_sequence(rfs4_lo_state_t *);
extern	void		rfs4_update_lock_resp(rfs4_lo_state_t *,
					nfs_resop4 *);

/* rfs4_file_t handling */
extern	rfs4_file_t	*rfs4_findfile(vnode_t *, nfs_fh4 *, bool_t *);
extern	rfs4_file_t	*rfs4_findfile_withlock(vnode_t *, nfs_fh4 *,
						bool_t *);
extern	void		rfs4_file_rele(rfs4_file_t *);

/* General collection of "get state" functions */
extern	nfsstat4	rfs4_get_state(stateid4 *, rfs4_state_t **,
					rfs4_dbsearch_type_t);
extern	nfsstat4	rfs4_get_deleg_state(stateid4 *,
					rfs4_deleg_state_t **);
extern	nfsstat4	rfs4_get_lo_state(stateid4 *, rfs4_lo_state_t **,
					bool_t);
extern	nfsstat4	rfs4_check_stateid(int, vnode_t *, stateid4 *,
					bool_t, bool_t *, bool_t,
					caller_context_t *);
extern	int		rfs4_check_stateid_seqid(rfs4_state_t *, stateid4 *);
extern	int		rfs4_check_lo_stateid_seqid(rfs4_lo_state_t *,
					stateid4 *);

/* return values for rfs4_check_stateid_seqid() */
#define	NFS4_CHECK_STATEID_OKAY	1
#define	NFS4_CHECK_STATEID_OLD	2
#define	NFS4_CHECK_STATEID_BAD	3
#define	NFS4_CHECK_STATEID_EXPIRED	4
#define	NFS4_CHECK_STATEID_REPLAY	5
#define	NFS4_CHECK_STATEID_CLOSED	6
#define	NFS4_CHECK_STATEID_UNCONFIRMED	7

/* delay() time that server is willing to briefly wait for a delegreturn */
#define	NFS4_DELEGATION_CONFLICT_DELAY	(hz/10)

/*
 * Interfaces for handling of callback's client handle cache and
 * callback interfaces themselves.
 */
extern	void		rfs4_cbinfo_free(rfs4_cbinfo_t *);
extern	void		rfs4_client_setcb(rfs4_client_t *, cb_client4 *,
					uint32_t);
extern	void		rfs4_deleg_cb_check(rfs4_client_t *);
extern	nfsstat4	rfs4_vop_getattr(vnode_t *, vattr_t *, int, cred_t *);

/* rfs4_deleg_state_t handling and other delegation interfaces */
extern	rfs4_deleg_state_t *rfs4_finddeleg(rfs4_state_t *, bool_t *);
extern	rfs4_deleg_state_t *rfs4_finddelegstate(stateid_t *);
extern	bool_t		rfs4_check_recall(rfs4_state_t *, uint32_t);
extern	void		rfs4_recall_deleg(rfs4_file_t *,
				bool_t, rfs4_client_t *);
extern	int		rfs4_get_deleg(rfs4_state_t *,  open_delegation_type4,
			open_delegation_type4 (*policy)(rfs4_state_t *,
				open_delegation_type4 dtype));
extern	rfs4_deleg_state_t *rfs4_grant_delegation(delegreq_t, rfs4_state_t *,
				int *);
extern	void		rfs4_set_deleg_response(rfs4_deleg_state_t *,
				open_delegation4 *, nfsace4 *, int);
extern	void		rfs4_return_deleg(rfs4_deleg_state_t *, bool_t);
extern	bool_t		rfs4_is_deleg(rfs4_state_t *);
extern	void		rfs4_deleg_state_rele(rfs4_deleg_state_t *);
extern	bool_t		rfs4_check_delegated_byfp(int, rfs4_file_t *,
					bool_t, bool_t, bool_t, clientid4 *);
extern	void		rfs4_clear_dont_grant(rfs4_file_t *);

/*
 * nfs4 monitored operations.
 */
extern int deleg_rd_open(femarg_t *, int, cred_t *, caller_context_t *);
extern int deleg_wr_open(femarg_t *, int, cred_t *, caller_context_t *);
extern int deleg_wr_read(femarg_t *, uio_t *, int, cred_t *,
	    caller_context_t *);
extern int deleg_rd_write(femarg_t *, uio_t *, int, cred_t *,
	    caller_context_t *);
extern int deleg_wr_write(femarg_t *, uio_t *, int, cred_t *,
	    caller_context_t *);
extern int deleg_rd_setattr(femarg_t *, vattr_t *, int, cred_t *,
		caller_context_t *);
extern int deleg_wr_setattr(femarg_t *, vattr_t *, int, cred_t *,
		caller_context_t *);
extern int deleg_rd_rwlock(femarg_t *, int, caller_context_t *);
extern int deleg_wr_rwlock(femarg_t *, int, caller_context_t *);
extern int deleg_rd_space(femarg_t *, int, flock64_t *, int, offset_t, cred_t *,
		caller_context_t *);
extern int deleg_wr_space(femarg_t *, int, flock64_t *, int, offset_t, cred_t *,
		caller_context_t *);
extern int deleg_rd_setsecattr(femarg_t *, vsecattr_t *, int, cred_t *,
		caller_context_t *);
extern int deleg_wr_setsecattr(femarg_t *, vsecattr_t *, int, cred_t *,
		caller_context_t *);
extern int deleg_rd_vnevent(femarg_t *, vnevent_t, vnode_t *, char *,
		caller_context_t *);
extern int deleg_wr_vnevent(femarg_t *, vnevent_t, vnode_t *, char *,
		caller_context_t *);

extern void rfs4_mon_hold(void *);
extern void rfs4_mon_rele(void *);

extern fem_t	*deleg_rdops;
extern fem_t	*deleg_wrops;

extern int rfs4_share(rfs4_state_t *, uint32_t, uint32_t);
extern int rfs4_unshare(rfs4_state_t *);
extern	void		rfs4_set_deleg_policy(srv_deleg_policy_t);
#ifdef DEBUG
#define	NFS4_DEBUG(var, args) if (var) cmn_err args

extern int rfs4_debug;
extern int nfs4_client_attr_debug;
extern int nfs4_client_state_debug;
extern int nfs4_client_shadow_debug;
extern int nfs4_client_lock_debug;
extern int nfs4_client_lease_debug;
extern int nfs4_seqid_sync;
extern int nfs4_client_map_debug;
extern int nfs4_client_inactive_debug;
extern int nfs4_client_recov_debug;
extern int nfs4_client_failover_debug;
extern int nfs4_client_call_debug;
extern int nfs4_client_foo_debug;
extern int nfs4_client_zone_debug;
extern int nfs4_lost_rqst_debug;
extern int nfs4_open_stream_debug;
extern int nfs4_client_open_dg;
extern int nfs4_srvmnt_debug;
extern int nfs4_utf8_debug;

void rfs4_dbe_debug(rfs4_dbe_t *e);

#ifdef NFS4_DEBUG_MUTEX
void nfs4_debug_mutex_enter(kmutex_t *, char *, int);
void nfs4_debug_mutex_exit(kmutex_t *, char *, int);

#define	mutex_enter(m) nfs4_debug_mutex_enter((m), __FILE__, __LINE__)
#define	mutex_exit(m) nfs4_debug_mutex_exit((m), __FILE__, __LINE__)
#endif /* NFS4_DEBUG_MUTEX */

#else  /* ! DEBUG */
#define	NFS4_DEBUG(var, args)
#endif /* DEBUG */

/*
 * XXX - temporary for testing of volatile fh
 */

#ifdef VOLATILE_FH_TEST

struct nfs_fh4_fmt {
	fhandle4_t	fh4_i;
	uint32_t	fh4_flag;
	uint32_t	fh4_volatile_id;
};

#else /* VOLATILE_FH_TEST */

struct nfs_fh4_fmt {
	fhandle4_t	fh4_i;
	uint32_t	fh4_flag;
};

#endif /* VOLATILE_FH_TEST */

#define	FH4_NAMEDATTR	1
#define	FH4_ATTRDIR	2

#define	fh4_fsid	fh4_i.fhx_fsid
#define	fh4_len		fh4_i.fhx_len 	/* fid length */
#define	fh4_data	fh4_i.fhx_data 	/* fid bytes */
#define	fh4_xlen	fh4_i.fhx_xlen
#define	fh4_xdata	fh4_i.fhx_xdata
typedef struct nfs_fh4_fmt nfs_fh4_fmt_t;

#define	fh4_to_fmt4(fh4p) ((nfs_fh4_fmt_t *)(fh4p)->nfs_fh4_val)
#define	get_fh4_flag(fh4p, flag) ((fh4_to_fmt4(fh4p)->fh4_flag) & (flag))
#define	set_fh4_flag(fh4p, flag) ((fh4_to_fmt4(fh4p)->fh4_flag) |= (flag))
#define	clr_fh4_flag(fh4p, flag) ((fh4_to_fmt4(fh4p)->fh4_flag) &= ~(flag))

#define	NFS_FH4_LEN	sizeof (nfs_fh4_fmt_t)

/*
 * Copy fields from external (fhandle_t) to in-memory (nfs_fh4_fmt_t)
 * format to support export info checking.  It does not copy over
 * the complete filehandle, just the fsid, xlen and xdata.  It may
 * need to be changed to be used in other places.
 *
 * NOTE: The macro expects the space to be  pre-allocated for
 * the contents of nfs_fh4_fmt_t.
 */
#define	FH_TO_FMT4(exifh, nfs_fmt) {				\
	bzero((nfs_fmt), NFS_FH4_LEN);				\
	(nfs_fmt)->fh4_fsid = (exifh)->fh_fsid;			\
	(nfs_fmt)->fh4_xlen = (exifh)->fh_xlen;			\
	bcopy((exifh)->fh_xdata, (nfs_fmt)->fh4_xdata,		\
	    (exifh)->fh_xlen);					\
}

/*
 * A few definitions of repeatedly used constructs for nfsv4
 */
#define	UTF8STRING_FREE(str)					\
	kmem_free((str).utf8string_val,	(str).utf8string_len);	\
	(str).utf8string_val = NULL;				\
	(str).utf8string_len = 0;

/*
 * NFS4_VOLATILE_FH yields non-zero if the filesystem uses non-persistent
 * filehandles.
 */
#define	NFS4_VOLATILE_FH(mi)					\
	((mi)->mi_fh_expire_type &				\
	(FH4_VOLATILE_ANY | FH4_VOL_MIGRATION | FH4_VOL_RENAME))

/*
 * NFS_IS_DOTNAME checks if the name given represents a dot or dotdot entry
 */
#define	NFS_IS_DOTNAME(name)					\
	(((name)[0] == '.') &&					\
	(((name)[1] == '\0') || (((name)[1] == '.') && ((name)[2] == '\0'))))

/*
 * Define the number of bits in a bitmap word (uint32)
 */
#define	NFS4_BITMAP4_BITSPERWORD	(sizeof (uint32_t) * 8)

/*
 * Define the value for the access field of the compound_state structure
 * based on the result of nfsauth access checking.
 */
#define	CS_ACCESS_OK		0x1
#define	CS_ACCESS_DENIED	0x2
#define	CS_ACCESS_LIMITED	0x4

/*
 * compound state in nfsv4 server
 */
struct compound_state {
	struct exportinfo *exi;
	struct exportinfo *saved_exi;	/* export struct for saved_vp */
	cred_t 		*basecr;	/* UNIX cred:  only RPC request */
	caddr_t 	principal;
	int 		nfsflavor;
	cred_t 		*cr;		/* UNIX cred: RPC request and */
					/* target export */
	bool_t  	cont;
	uint_t 		access;		/* access perm on vp per request */
	bool_t 		deleg;		/* TRUE if current fh has */
					/* write delegated */
	vnode_t 	*vp;		/* modified by PUTFH, and by ops that */
					/* input to GETFH */
	bool_t 		mandlock;	/* Is mandatory locking in effect */
					/* for vp */
	vnode_t 	*saved_vp;	/* modified by SAVEFH, copied to */
					/* vp by RESTOREFH */
	nfsstat4 	*statusp;
	nfs_fh4 	fh;		/* ditto. valid only if vp != NULL */
	nfs_fh4 	saved_fh;	/* ditto. valid only if */
					/* 	saved_vp != NULL */
	struct svc_req	*req;
	char 		fhbuf[NFS4_FHSIZE];
};

/*
 * Conversion commands for nfsv4 server attr checking
 */
enum nfs4_attr_cmd {
	NFS4ATTR_SUPPORTED = 0,		/* check which attrs supported */
	NFS4ATTR_GETIT = 1,		/* getattr - sys to fattr4 (r) */
	NFS4ATTR_SETIT = 2,		/* setattr - fattr4 to sys (w) */
	NFS4ATTR_VERIT = 3,		/* verify - fattr4 to sys (r) */
	NFS4ATTR_FREEIT = 4		/* free any alloc'd space for attr */
};

typedef enum nfs4_attr_cmd nfs4_attr_cmd_t;

struct nfs4_svgetit_arg {
	nfs4_attr_cmd_t op;		/* getit or setit */
	struct compound_state *cs;
	struct statvfs64 *sbp;
	uint_t 		flag;		/* VOP_GETATTR/VOP_SETATTR flag */
	uint_t 		xattr;		/* object is xattr */
	bool_t 		rdattr_error_req; /* if readdir & client wants */
						/* rdattr_error */
	nfsstat4	rdattr_error;	/* used for per-entry status */
					/* (if rdattr_err) */
	bool_t		is_referral;	/* because sometimes we tell lies */
	bool_t		mntdfid_set;
	fattr4_mounted_on_fileid
			mounted_on_fileid;
					/* readdir op can always return	*/
					/* d_ino from server fs dirent  */
					/* for mounted_on_fileid attr.	*/
					/* This field holds d_ino so	*/
					/* srv attr conv code can avoid */
					/* doing an untraverse.		*/
	vattr_t		vap[1];
};

struct nfs4_ntov_map {
	bitmap4		fbit; 		/* FATTR4_XXX_MASKY */
	uint_t 		vbit; 		/* AT_XXX */
	bool_t 		vfsstat;
	bool_t 		mandatory; 	/* attribute mandatory to implement? */
	uint_t 		nval;
	int		xdr_size;	/* Size of XDR'd attr */
	xdrproc_t 	xfunc;
	int (*sv_getit)(nfs4_attr_cmd_t, struct nfs4_svgetit_arg *,
		union nfs4_attr_u *);	/* subroutine for getting attr. */
	char 		*prtstr;	/* string attr for printing */
};

struct nfs4attr_to_vattr {
	vnode_t 	*vp;
	vattr_t 	*vap;
	nfs_fh4   	*fhp;
	nfsstat4	rdattr_error;
	uint32_t	flag;
	fattr4_change	change;
	fattr4_fsid	srv_fsid;
	fattr4_mounted_on_fileid	mntd_fid;
};

typedef struct nfs4attr_to_vattr ntov4_t;

/*
 * nfs4attr_to_vattr flags
 */
#define	NTOV_FHP_VALID			0x01
#define	NTOV_RDATTR_ERROR_VALID		0x02
#define	NTOV_CHANGE_VALID		0x04
#define	NTOV_SUPP_VALID			0x08
#define	NTOV_SRV_FSID_VALID		0x10
#define	NTOV_MOUNTED_ON_FILEID_VALID	0x20


#define	FATTR4_MANDATTR_MASK (		\
	FATTR4_SUPPORTED_ATTRS_MASK |	\
	FATTR4_TYPE_MASK |		\
	FATTR4_FH_EXPIRE_TYPE_MASK |	\
	FATTR4_CHANGE_MASK |		\
	FATTR4_SIZE_MASK |		\
	FATTR4_LINK_SUPPORT_MASK |	\
	FATTR4_SYMLINK_SUPPORT_MASK |	\
	FATTR4_NAMED_ATTR_MASK |	\
	FATTR4_FSID_MASK |		\
	FATTR4_UNIQUE_HANDLES_MASK |	\
	FATTR4_LEASE_TIME_MASK |	\
	FATTR4_RDATTR_ERROR_MASK |	\
	FATTR4_FILEHANDLE_MASK)


struct nfs4attr_to_osattr {
	void *attrconv_arg;
	uint_t mask;
};

struct mntinfo4;

/*
 * lkp4_attr_setup lists the different options for attributes when calling
 * nfs4lookup_setup - either no attributes (just lookups - e.g., secinfo),
 * one component only (normal component lookup), get attributes for the
 * last component (e.g., mount), attributes for each component (e.g.,
 * failovers later), just the filehandle for the last component (e.g.,
 * volatile filehandle recovery), or stuff that needs OPENATTR (e.g.
 * looking up a named attribute or it's hidden directory).
 */
enum lkp4_attr_setup {
	LKP4_NO_ATTRIBUTES = 0,		/* no attrs or filehandles */
	LKP4_ALL_ATTRIBUTES = 3,	/* multi-comp: attrs for all comps */
	LKP4_LAST_NAMED_ATTR = 5,	/* multi-comp: named attr & attrdir */
	LKP4_LAST_ATTRDIR = 6,		/* multi-comp: just attrdir */
	LKP4_ALL_ATTR_SECINFO = 7	/* multi-comp: attrs for all comp and */
					/*	secinfo for last comp */
};

/*
 * lookup4_param a set of parameters to nfs4lookup_setup -
 * used to setup a path lookup compound request.
 */
typedef struct lookup4_param {
	enum lkp4_attr_setup l4_getattrs; /* (in) get attrs in the lookup? */
	int 		header_len;	/* (in) num ops before first lookup  */
	int 		trailer_len;	/* (in) num ops after last	*/
					/*	Lookup/Getattr		*/
	bitmap4 	ga_bits;	/* (in) Which attributes for Getattr */
	COMPOUND4args_clnt *argsp;	/* (in/out) args for compound struct */
	COMPOUND4res_clnt  *resp;	/* (in/out) res for compound  struct */
	int 		arglen;		/* (out) argop buffer alloc'd length */
	struct mntinfo4 *mi;
} lookup4_param_t;


#define	NFS4_FATTR4_FINISH	-1	/* fattr4 index indicating finish */

typedef int (*nfs4attr_to_os_t)(int, union nfs4_attr_u *,
		struct nfs4attr_to_osattr *);

/*
 * The nfs4_error_t is the basic structure to return error values
 * from rfs4call.  It encapsulates the unix errno
 * value, the nfsstat4 value and the rpc status value into a single
 * structure.
 *
 * If error is set, then stat is ignored and rpc_status may be
 * set if the error occurred as the result of a CLNT_CALL.  If
 * stat is set, then rpc request succeeded, error and
 * rpc_status are set to 0 and stat contains the result of
 * operation, NFS4_OK or one of the NFS4ERR_* values.
 *
 * Functions which want to generate errors independently from
 * rfs4call should set error to the desired errno value and
 * set stat and rpc_status to 0.  nfs4_error_init() is a
 * convenient function to do this.
 */
typedef struct {
	int		error;
	nfsstat4	stat;
	enum clnt_stat	rpc_status;
} nfs4_error_t;

/*
 * Shared functions
 */
extern void	rfs4_op_readdir(nfs_argop4 *, nfs_resop4 *,
			struct svc_req *, struct compound_state *);
extern void	nfs_fh4_copy(nfs_fh4 *, nfs_fh4 *);

extern void	nfs4_fattr4_free(fattr4 *);

extern int	nfs4lookup_setup(char *, lookup4_param_t *, int);
extern void	nfs4_getattr_otw_norecovery(vnode_t *,
			nfs4_ga_res_t *, nfs4_error_t *, cred_t *, int);
extern int	nfs4_getattr_otw(vnode_t *, nfs4_ga_res_t *, cred_t *, int);
extern int	nfs4cmpfh(const nfs_fh4 *, const nfs_fh4 *);
extern int	nfs4cmpfhandle(nfs4_fhandle_t *, nfs4_fhandle_t *);
extern int	nfs4getattr(vnode_t *, struct vattr *, cred_t *);
extern int	nfs4_waitfor_purge_complete(vnode_t *);
extern int	nfs4_validate_caches(vnode_t *, cred_t *);
extern int	nfs4init(int, char *);
extern void	nfs4fini(void);
extern int	nfs4_vfsinit(void);
extern void	nfs4_vfsfini(void);

extern void	nfs4_vnops_init(void);
extern void	nfs4_vnops_fini(void);
extern void	nfs_idmap_init(void);
extern void	nfs_idmap_flush(int);
extern void	nfs_idmap_fini(void);
extern int	nfs4_rnode_init(void);
extern int	nfs4_rnode_fini(void);
extern int	nfs4_shadow_init(void);
extern int	nfs4_shadow_fini(void);
extern int	nfs4_acache_init(void);
extern int	nfs4_acache_fini(void);
extern int	nfs4_subr_init(void);
extern int	nfs4_subr_fini(void);
extern void	nfs4_acl_init(void);
extern void	nfs4_acl_free_cache(vsecattr_t *);

extern int	geterrno4(nfsstat4);
extern nfsstat4	puterrno4(int);
extern int	nfs4_need_to_bump_seqid(COMPOUND4res_clnt *);
extern int	nfs4tsize(void);
extern int	checkauth4(struct compound_state *, struct svc_req *);
extern nfsstat4 call_checkauth4(struct compound_state *, struct svc_req *);
extern int	is_exported_sec(int, struct exportinfo *);
extern void	nfs4_vmask_to_nmask(uint_t, bitmap4 *);
extern void	nfs4_vmask_to_nmask_set(uint_t, bitmap4 *);
extern int	nfs_idmap_str_uid(utf8string *u8s, uid_t *, bool_t);
extern int	nfs_idmap_str_gid(utf8string *u8s, gid_t *, bool_t);
extern int	nfs_idmap_uid_str(uid_t, utf8string *u8s, bool_t);
extern int	nfs_idmap_gid_str(gid_t gid, utf8string *u8s, bool_t);
extern int	nfs4_time_ntov(nfstime4 *, timestruc_t *);
extern int	nfs4_time_vton(timestruc_t *, nfstime4 *);
extern char	*utf8_to_str(utf8string *, uint_t *, char *);
extern char	*utf8_to_fn(utf8string *, uint_t *, char *);
extern utf8string *str_to_utf8(char *, utf8string *);
extern utf8string *utf8_copy(utf8string *, utf8string *);
extern int	utf8_compare(const utf8string *, const utf8string *);
extern nfsstat4	utf8_dir_verify(utf8string *);
extern char	*utf8_strchr(utf8string *, const char);
extern int	ln_ace4_cmp(nfsace4 *, nfsace4 *, int);
extern int	vs_aent_to_ace4(vsecattr_t *, vsecattr_t *, int, int);
extern int	vs_ace4_to_aent(vsecattr_t *, vsecattr_t *, uid_t, gid_t,
    int, int);
extern int	vs_ace4_to_acet(vsecattr_t *, vsecattr_t *, uid_t, gid_t,
    int);
extern int	vs_acet_to_ace4(vsecattr_t *, vsecattr_t *, int);
extern void	vs_acet_destroy(vsecattr_t *);
extern void	vs_ace4_destroy(vsecattr_t *);
extern void	vs_aent_destroy(vsecattr_t *);

extern int	vn_find_nfs_record(vnode_t *, nvlist_t **, char **, char **);
extern int	vn_is_nfs_reparse(vnode_t *, cred_t *);
extern fs_locations4 *fetch_referral(vnode_t *, cred_t *);
extern char	*build_symlink(vnode_t *, cred_t *, size_t *);

extern int	stateid4_cmp(stateid4 *, stateid4 *);

extern vtype_t	nf4_to_vt[];

extern struct nfs4_ntov_map nfs4_ntov_map[];
extern uint_t nfs4_ntov_map_size;

extern kstat_named_t	*rfsproccnt_v4_ptr;
extern kstat_t		**rfsprocio_v4_ptr;
extern struct vfsops	*nfs4_vfsops;
extern struct vnodeops	*nfs4_vnodeops;
extern const struct	fs_operation_def nfs4_vnodeops_template[];
extern vnodeops_t	*nfs4_trigger_vnodeops;
extern const struct	fs_operation_def nfs4_trigger_vnodeops_template[];

extern uint_t nfs4_tsize(struct knetconfig *);
extern uint_t rfs4_tsize(struct svc_req *);

extern bool_t	xdr_inline_decode_nfs_fh4(uint32_t *, nfs_fh4_fmt_t *,
			uint32_t);
extern bool_t	xdr_inline_encode_nfs_fh4(uint32_t **, uint32_t *,
			nfs_fh4_fmt_t *);

#ifdef DEBUG
extern int		rfs4_do_pre_op_attr;
extern int		rfs4_do_post_op_attr;
#endif

extern stateid4 clnt_special0;
extern stateid4 clnt_special1;
#define	CLNT_ISSPECIAL(id) (stateid4_cmp(id, &clnt_special0) || \
				stateid4_cmp(id, &clnt_special1))

/*
 * The NFS Version 4 service procedures.
 */

extern void	rfs4_compound(COMPOUND4args *, COMPOUND4res *,
			struct exportinfo *, struct svc_req *, cred_t *, int *);
extern void	rfs4_compound_free(COMPOUND4res *);
extern void	rfs4_compound_flagproc(COMPOUND4args *, int *);
extern void	rfs4_compound_kstat_args(COMPOUND4args *);
extern void	rfs4_compound_kstat_res(COMPOUND4res *);

extern int	rfs4_srvrinit(void);
extern void	rfs4_srvrfini(void);
extern void	rfs4_state_init(void);
extern void	rfs4_state_fini(void);

#endif
#ifdef	__cplusplus
}
#endif

#endif /* _NFS4_H */
