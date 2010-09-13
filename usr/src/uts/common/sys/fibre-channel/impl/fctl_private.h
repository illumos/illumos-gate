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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FCTL_PRIVATE_H
#define	_FCTL_PRIVATE_H


#include <sys/note.h>

#include <sys/fibre-channel/impl/fc_ulpif.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Stuff strictly internal to fctl that
 * isn't exposed to any other modules.
 */
#define	PWWN_HASH_TABLE_SIZE	(32)		/* 2^n */
#define	D_ID_HASH_TABLE_SIZE	(32)		/* 2^n */
#define	NWWN_HASH_TABLE_SIZE	(32)		/* 2^n */
#define	HASH_FUNC(key, size)	((key) & (size - 1))
#define	WWN_HASH_KEY(x)		((x)[0] + (x)[1] + (x)[2] +\
				    (x)[3] + (x)[4] + (x)[5] +\
				    (x)[6] + (x)[7])
#define	D_ID_HASH_FUNC(x, size)	((x) & (size - 1))
#define	FC4_TYPE_WORD_POS(x)	((uchar_t)(x) >> 5)
#define	FC4_TYPE_BIT_POS(x)	((uchar_t)(x) & 0x1F)
#define	FC_ACTION_INVALID	-1
#define	FC_REASON_INVALID	-1
#define	FC_EXPLN_INVALID	-1

/*
 * Internally translated and used state change values to ULPs
 */
#define	FC_ULP_STATEC_DONT_CARE		0
#define	FC_ULP_STATEC_ONLINE		1
#define	FC_ULP_STATEC_OFFLINE		2
#define	FC_ULP_STATEC_OFFLINE_TIMEOUT	3

#define	FC_ULP_ADD_RETRY_COUNT		90
#define	FC_MAX_TRACE_BUF_LEN		512


#define	FC_NPIV_MAX_PORT		255

/*
 * port_dstate values
 */
#define	ULP_PORT_ATTACH			0x01
#define	ULP_PORT_SUSPEND		0x02
#define	ULP_PORT_POWER_DOWN		0x04
#define	ULP_PORT_BUSY			0x08
#define	FCTL_DISALLOW_CALLBACKS(x)	(!((x) & ULP_PORT_ATTACH) ||\
					((x) & ULP_PORT_BUSY))

typedef struct ulp_ports {
	struct ulp_ports	*port_next;
	int			port_dstate;
	uint32_t		port_statec;
	kmutex_t		port_mutex;
	struct fc_local_port	*port_handle;
} fc_ulp_ports_t;


typedef struct ulp_module {
	struct ulp_module	*mod_next;
	fc_ulp_modinfo_t	*mod_info;
	fc_ulp_ports_t		*mod_ports;
} fc_ulp_module_t;


typedef struct ulp_list {
	fc_ulp_modinfo_t	*ulp_info;
	struct ulp_list		*ulp_next;
} fc_ulp_list_t;


typedef struct fca_port {
	struct fca_port		*port_next;
	struct fc_local_port	*port_handle;
} fc_fca_port_t;

typedef struct timed_counter {
	struct timed_counter	*sig;
	uint32_t		counter;
	uint32_t		max_value;
	boolean_t		maxed_out;
	kmutex_t		mutex;
	boolean_t		active;
	clock_t			timer;
	timeout_id_t		tid;
} timed_counter_t;

/*
 * Struct describing a remote node. A remote node is associated with one
 * or more remote ports (fc_remote_port_t structs) that are all accessible
 * through one local port (fc_local_port_t struct).
 *
 * Each fc_remote_node_t struct is also referenced by nwwn in the global
 * nwwn_hash_table[] list.
 */
typedef struct fc_remote_node {
	/*
	 * Mutex lock to protect access to all members of this struct.
	 * Current implementation dictates acquisition of fd_mutex before
	 * pd_mutex can be acquired (when both locks must be acquired).
	 */
	kmutex_t		fd_mutex;

	/* Node WWN for the remote node */
	la_wwn_t		fd_node_name;

	/*
	 * This is the number of (active) fc_remote_port_t structs that
	 * are associated with this remote node.
	 */
	int			fd_numports;

	/*
	 * Tracks whether this struct is "valid" or "invalid", using the
	 * FC_REMOTE_NODE_* values given above.
	 */
	int			fd_flags;

	/* Linked list of remote ports associated with this remote node. */
	struct fc_remote_port	*fd_portlistp;

	uchar_t			fd_ipa[8];	/* Initial proc assoc */
	uchar_t			fd_vv[16];	/* Vendor Version */
	uchar_t			fd_snn_len;	/* node symbolic name len */
	uchar_t			fd_snn[255];	/* node symbolic name */
} fc_remote_node_t;

/*
 * Stack depth for troubleshooting (only used in debug code)
 */
#define	FC_STACK_DEPTH			14

/*
 * The fc_remote_port_t struct represents a remote FC port that is
 * accessible via the local FC port (fc_local_port_t). Each remote
 * FC port is associated with one FC local port (fc_local_port_t,
 * above) and one remote FC node (fc_remote_node_t, see below).
 * fc_remote_port_t structs are created and destroyed as needed to
 * correspond with changing conditions out on the link.
 */
typedef struct fc_remote_port {
	/*
	 * Ah, the infamous 'pd_mutex' that has given developers so much
	 * joy over the years....
	 * (Gotta love the original, extremely helpful comment.)
	 */
	kmutex_t		pd_mutex;	/* mutex */

	fc_portid_t		pd_port_id;	/* Port Identifier */
	la_wwn_t		pd_port_name;	/* the port WWN */

	/*
	 * Reference count of the # of logins initiated by a ULP
	 * (i.e., this is the # of ULPs accessing the struct). See
	 * fp_plogi_group() for more info.
	 */
	int			pd_login_count;

	/*
	 * This appears to track the login state of the remote FC port.
	 * Used with the PORT_DEVICE_* macros in fc_appif.h.
	 */
	uint32_t		pd_state;

	/*
	 * Link pointers for the port wwn and D_ID hash lists. These point
	 * to the next remote port in the current hash chain.
	 */
	struct fc_remote_port	*pd_wwn_hnext;
	struct fc_remote_port	*pd_did_hnext;

	/*
	 * Link pointer for list of *all* fc_remote_port_t structs
	 * associated with the same fc_local_port_t struct.
	 */
	struct fc_remote_port	*pd_port_next;

	/*
	 * Pointer to the fc_remote_node_t struct for the remote node
	 * associated with the remote port.
	 */
	struct fc_remote_node	*pd_remote_nodep;

	/* port type for the remote port */
	fc_porttype_t		pd_porttype;

	fc_hardaddr_t		pd_hard_addr;	/* Hard Address */

	/*
	 * Back pointer to the fc_local_port_t struct for the local port
	 * associated with this remote port.
	 */
	struct fc_local_port	*pd_port;

	/*
	 * (Sigh) this actually doesn't have anything to do with the "type"
	 * of the remote port per se.  It's really more an indicator of the
	 * most recently known state/status of the remote port. It's intended
	 * to help figure out if/how the remote port has either gone away or
	 * changed somehow after an event has occurred on the link.
	 * There also seems to be some connection to the "changed map".
	 *
	 * The legal values for this are the PORT_DEVICE_* definitions
	 * earlier in this file.
	 */
	uchar_t			pd_type;	/* new or old */

	/*
	 * This tracks the current state/status of a login attempt at the
	 * remote port.	 Legal values are given above.
	 * See also the pd_state field.
	 */
	uchar_t			pd_flags;	/* login in progress */

	uchar_t			pd_login_class;	/* Logi Class */

	/* Legal values are given above (beware of the mipselling) */
	uchar_t			pd_recepient;	/* who did PLOGI? */

	uchar_t			pd_ip_addr[8];	/* IP address */
	uint32_t		pd_fc4types[8];	/* FC-4 types */
	uint32_t		pd_cos;		/* class of service */
	struct common_service	pd_csp;		/* common service */
	struct service_param	pd_clsp1;	/* Class 1 */
	struct service_param	pd_clsp2;	/* Class 2 */
	struct service_param	pd_clsp3;	/* Class 3 */

	/* This is _SO_ private that even we don't use it */
	caddr_t			pd_private;	/* private data */

	/*
	 * This is a count of the number of references to (or holds on)
	 * this remote port.
	 */
	int			pd_ref_count;	/* number of references */

	/*
	 * Re-login disable for FCP-2 error recovery.  This is intended to
	 * help with tape devices when an RSCN or Link Reset occurs during
	 * a long write operations (like backup). fp's default action is
	 * to try to log in again, but that forces a rewind on the LUN
	 * and corrupts its state.
	 *
	 * The legal bit values are given below. Some specific definitions
	 * are as follows:
	 *
	 *   PD_IN_DID_QUEUE: The fc_remote_port_t is present in the d_id
	 *		    hash list of the associated fc_local_port_t.  (This
	 *		    is apparently meant to cover some races).
	 *   PD_LOGGED_OUT: This is a directive to ignore the NORELOGIN if
	 *		    an actual logout occurred
	 */
	uchar_t			pd_aux_flags;	/* relogin disable */

	uchar_t			pd_spn_len;	/* length of sym name */
	char			pd_spn[255];	/* symbolic port name */

	/*
	 * Count of the # of unsolicited LOGOs received. See the definition
	 * of FC_LOGO_TOLERANCE_LIMIT in fp.c.
	 */
	timed_counter_t		pd_logo_tc;

#ifdef	DEBUG
	int			pd_w_depth;	/* for WWN hash table */
	pc_t			pd_w_stack[FC_STACK_DEPTH];
	int			pd_d_depth;	/* for D_ID hash table */
	pc_t			pd_d_stack[FC_STACK_DEPTH];
#endif
} fc_remote_port_t;


/*
 * Structs for the global nwwn_hash_table[] entries.
 *
 * At _init() time, fctl allocates an array of fctl_nwwn_list_t structs that
 * has nwwn_table_size entries.	 The hash_head member anchors a linked
 * list of fctl_nwwn_elem_t structs that are linked via the fne_next pointer.
 * Each fctl_nwwn_elem_t also contains a pointer to one fc_remote_node_t struct.
 */
typedef struct fctl_nwwn_elem fctl_nwwn_elem_t;

struct fctl_nwwn_elem {
	fctl_nwwn_elem_t	*fne_nextp;
	fc_remote_node_t	*fne_nodep;
};

typedef struct fctl_nwwn_list {
	fctl_nwwn_elem_t	*fnl_headp;
} fctl_nwwn_list_t;



typedef struct fc_errmap {
	int	fc_errno;
	char	*fc_errname;
} fc_errmap_t;


typedef struct fc_pkt_reason {
	int	reason_val;
	char	*reason_msg;
} fc_pkt_reason_t;


typedef struct fc_pkt_action {
	int	action_val;
	char	*action_msg;
} fc_pkt_action_t;


typedef struct fc_pkt_expln {
	int	expln_val;
	char	*expln_msg;
} fc_pkt_expln_t;


typedef struct fc_pkt_error {
	int			pkt_state;
	char			*pkt_msg;
	fc_pkt_reason_t		*pkt_reason;
	fc_pkt_action_t		*pkt_action;
	fc_pkt_expln_t		*pkt_expln;
} fc_pkt_error_t;


/*
 * Values for the fd_flags field in the fc_remote_node_t struct.
 * Note, the code seems to rely on the struct initialization using
 * kmem_zalloc() to set all the bits to zero, since FC_REMOTE_NODE_INVALID
 * is never explicitly set anywhere.
 */
#define	FC_REMOTE_NODE_INVALID	0
#define	FC_REMOTE_NODE_VALID	1


/*
 * Values for the pd_flags field in the fc_remote_port_t struct.  These
 * are used in a _lot_ of places. NOTE: these are values, not bit flags.
 */
#define	PD_IDLE			0x00
#define	PD_ELS_IN_PROGRESS	0x01
#define	PD_ELS_MARK		0x02


/*
 * Bit values for the pd_aux_flags field in the fc_remote_port_t struct.
 */
#define	PD_IN_DID_QUEUE		0x01	/* The fc_remote_port_t is present */
					/* in the D_ID hash list of the */
					/* associated fc_local_port_t. (This */
					/* is apparently meant to narrow */
					/* some race windows). */
#define	PD_DISABLE_RELOGIN	0x02
#define	PD_NEEDS_REMOVAL	0x04
#define	PD_LOGGED_OUT		0x08	/* This is a directive to ignore */
					/* the NORELOGIN if an actual logout */
					/* occurred */
#define	PD_GIVEN_TO_ULPS	0x10	/* A reference to this pd has been */
					/* given to one or more ULPs. */

/*
 * Values for the pd_recepient field in the fc_remote_port_t struct.
 * Tries to describe where a PLOGI attempt originated.
 */
#define	PD_PLOGI_INITIATOR		0
#define	PD_PLOGI_RECEPIENT		1


/*
 * The fc_local_port_t struct represents a local FC port. It is the softstate
 * struct for each fp instance, so it comes into existence at DDI_ATTACH
 * and is deleted during DDI_DETACH.
 */
typedef struct fc_local_port {
	/*
	 * Mutex to protect certain data fields in this struct.
	 */
	kmutex_t		fp_mutex;

	/*
	 * fp_state sort of tracks the state of the link at the local port.
	 * The actual 'state' is kept in the lower byte, and the port speed
	 * is kept in the next most significant byte.  The code makes
	 * extensive use of the FC_PORT_SPEED_MASK() and FC_PORT_STATE_MASK()
	 * macros to separate these two items.	The current link topology
	 * is actually kept separately in the fp_topology field.
	 * The legal values for fp_state are given above.
	 */
	volatile uint32_t	fp_state;

	/*
	 * The S_ID for the local port. See fc_types.h for the fc_portid_t
	 * definition.
	 */
	fc_portid_t		fp_port_id;

	/*
	 * Opaque reference handle for the local port device. This value
	 * is supplied by the FCA driver and is passed unaltered to
	 * various FCA driver entry point functions.
	 */
	opaque_t		fp_fca_handle;

	/* Entry point vectors for the FCA driver at this FC port */
	struct fca_tran		*fp_fca_tran;

	/*
	 * fp's homegrown "job" threading mechanism (not a Solaris DDI taskq).
	 *
	 * Head/tail pointers for a linked list of requests to be executed
	 * in a driver-private thread.	One thread per fc_local_port_t struct.
	 * The thread is created during DDI_ATTACH for the instance.
	 */
	struct job_request	*fp_job_head;
	struct job_request	*fp_job_tail;

	struct fp_cmd		*fp_wait_head;		/* waitQ head */
	struct fp_cmd		*fp_wait_tail;		/* waitQ tail */

	/*
	 * Current port topology. Uses the FC_TOP_* values defined in
	 * fc_appif.h.	This is used with the FC_IS_TOP_SWITCH() macro and
	 * is also used with the FC_TOP_EXTERNAL() macro in the ULPs.
	 */
	uint32_t		fp_topology;		/* topology */

	/*
	 * The fp_task and fp_last_task fields are used mainly in the
	 * fp_job_handler() function.  These are used to indicate when a job
	 * is executing.  They also allow a second job to be issued while
	 * the current job is still in progress, but only one level of nesting
	 * is permitted.
	 *
	 * The legal values for these fields are given in fp.h
	 *
	 * This should not be confused with the Solaris DDI taskq mechanism,
	 * altho also fp makes use of that in some places (just to keep life
	 * interesting).
	 */
	int			fp_task;		/* current task */
	int			fp_last_task;		/* last task */

	/*
	 * fp_soft_state actually tracks the progression of the fp driver
	 * in various code paths, particularly in attach, detach, suspend,
	 * resume, and state change callbacks.
	 *
	 * The values for this are defined in fc_portif.h.
	 *
	 * This is sometimes used in conjunction with the fp_statec_busy
	 * field (see below), but there is no direct, 1-to-1 correlation
	 * in how these are used together.
	 */
	volatile uint16_t	fp_soft_state;


	/*
	 * Software restoration bit fields for (PM)SUSPEND/(PM)RESUME (??)
	 * Legal values are FP_RESTORE_* in fp.h
	 */
	uint16_t		fp_restore;

	/*
	 * Open/Close bit flags. Used in fp_open(), fp_close(), fp_ioctl()
	 * and fp_fciocmd(). See fp.h for legal values.
	 */
	uchar_t			fp_flag;		/* open/close flag */

	uchar_t			fp_verbose;
	uchar_t			fp_ns_login_class;	/* NS Logi Class */
	uchar_t			fp_sym_port_namelen;	/* Symb port name len */
	uint32_t		fp_cos;			/* class of service */

	/*
	 * Base pointer for hash table of fc_remote_port_t structs (remote
	 * ports) accessible thru the local port. The table is hashed by
	 * the D_ID of the remote port.
	 */
	struct d_id_hash	*fp_did_table;

	/*
	 * Base pointer for hash table of fc_remote_port_t structs (remote
	 * ports) accessible thru the local port. The table is hashed by
	 * the port WWN of the remote port.
	 */
	struct pwwn_hash	*fp_pwwn_table;

	struct kmem_cache	*fp_pkt_cache;
	int			fp_out_fpcmds;	/* outstanding fp_cmd # */

	/*
	 * fp_statec_busy tracks the progression of state change
	 * callbacks within the fp driver. It follows unsolicited callbacks
	 * and things like the port startup which happens during the attach.
	 * The value increments when a state change is active and decrements
	 * when it completes.
	 *
	 * The benefit of this is that we should be processing only the
	 * latest state change and drop the existing one.  Coalescing of
	 * multiple outstanding state changes is NOT performed.
	 *
	 * This is accessed in many places in the code, and also is buried
	 * in some macros (see fp_soft_state above).
	 *
	 * IMPORTANT: The code currently permits nested state changes,
	 * and there is no limitation on the allowed level of nesting.
	 */
	int			fp_statec_busy;

	int			fp_port_num;		/* port number */
	struct fp_cmd		*fp_els_resp_pkt;	/* ready response pkt */
	int			fp_instance;		/* instance number */

	/*
	 * Flag to indicate whether or not the ULP attach is in progress. Used
	 * to synchronize execution of various functions. Seems intended to
	 * have a value of either zero or one.
	 */
	int			fp_ulp_attach;		/* ULP attach done ? */

	int			fp_dev_count;		/* number of devices */
	int			fp_ptpt_master;		/* my WWN is greater */
	int			fp_ulp_nload;		/* count of ULPs */
	int			fp_total_devices;	/* total count */

	/*
	 * Another "busy/not busy" flag. Value is either 0 or 1.
	 */
	int			fp_els_resp_pkt_busy;

	/*
	 * This is the "state" of the link on the local port, as reported
	 * by the underlying FCA driver at bind time. This uses the same
	 * values as fp_state above, including FC_STATE_OFFLINE, FC_STATE_LOOP,
	 * and FC_PORT_STATE_MASK(port->fp_bind_state).
	 */
	uint32_t		fp_bind_state;		/* at bind time */

	/*
	 * Bit field of various parameterized behaviors for the local port.
	 * CAUTION: there is also an fp global variable called "fp_options"
	 * that is used to initialize this field during DDI_ATTACH.
	 */
	uint32_t		fp_options;

	/*
	 * Apparently intended to facilitate reporting the FC_HBA type
	 * for the local port.	Legal values are in fcgs2.h. The
	 * fc_porttype_t typedef is in fc_types.h
	 */
	fc_porttype_t		fp_port_type;

	uint32_t		fp_ub_count;		/* Number of UBs */
	int			fp_active_ubs;		/* outstanding UBs */
	uint64_t		*fp_ub_tokens;		/* UB tokens */

	/*
	 * CV to inform fp "job" thread that there is work to do.
	 * See fp_job_handler() function.
	 */
	kcondvar_t		fp_cv;

	/*
	 * Apparently intended to prevent race conditions by holding off any
	 * DDI_DETACHes for the local port while a ULP attach is in progress.
	 */
	kcondvar_t		fp_attach_cv;		/* ULP attach cv */

	/*
	 * Save up the devinfo pointers from Solaris, for performing
	 * pm_raise_power(), pm_busy_component(), and other DDI friends.
	 */
	dev_info_t		*fp_port_dip;		/* port dip */
	dev_info_t		*fp_fca_dip;		/* FCA dip */

	/* This is a real Solaris DDI taskq (not the fp "job" queue) */
	taskq_t			*fp_taskq;		/* callback queue */

	timeout_id_t		fp_wait_tid;		/* retry timer */
	timeout_id_t		fp_offline_tid;		/* Offline timeout ID */
	fc_lilpmap_t		fp_lilp_map;		/* LILP map */
	la_els_logi_t		fp_service_params;	/* service parameters */
	fc_fcp_dma_t		fp_fcp_dma;		/* FCP DVMA space */
	fc_reset_action_t	fp_reset_action;	/* FCA reset behavior */
	fc_dma_behavior_t	fp_dma_behavior;	/* FCA DMA behavior */
	uchar_t			fp_sym_node_namelen;	/* Sym node name len */
	uchar_t			fp_ipa[8];		/* initial proc assoc */
	uchar_t			fp_ip_addr[16];		/* IP address */
	uint32_t		fp_fc4_types[8];	/* fc4 types */
	struct fc_orphan	*fp_orphan_list;	/* orphan list */
	int			fp_orphan_count;	/* number of orphans */

	/*
	 * Current PM power level of the local port device. Values
	 * are given in fc_portif.h
	 */
	int			fp_pm_level;		/* power level */

	/* Increment/decrement in fctl_busy_port() and fctl_idle_port() */
	int			fp_pm_busy;		/* port busy */

	int			fp_pm_busy_nocomp;	/* busy (no comp) */
	fc_hardaddr_t		fp_hard_addr;		/* Hard Address */
	char			fp_sym_port_name[255];	/* Symb port name */
	char			fp_sym_node_name[255];	/* Symb node name */

	/*
	 * Opaque data for CALLB_CPR_* macros used by the per-local-port
	 * job thread.	Required for safe thread shutdown during PM operations.
	 */
	callb_cpr_t		fp_cpr_info;		/* CPR info */

	char			fp_jindex;		/* Not used */
	char			fp_jbuf[15];		/* Not used */

	char			fp_ibuf[15];		/* instance buf	 */
	char			fp_rnid_init;		/* init done */
	fc_rnid_t		fp_rnid_params;		/* node id data */

	/* T11 FC-HBA data */
	fca_port_attrs_t	fp_hba_port_attrs;
	fc_hba_state_change_t	fp_last_change;
	uint8_t			fp_port_supported_fc4_types[32];
	uint8_t			fp_port_active_fc4_types[32];
	uint32_t		fp_port_speed;
	la_wwn_t		fp_fabric_name;
	uint32_t		fp_rscn_count;
	int			fp_npiv_portnum;
#define	FC_NPIV_DISABLE	0
#define	FC_NPIV_ENABLE	1
	int			fp_npiv_flag;
#define	FC_NPIV_DELETING 1
	int			fp_npiv_state;
#define	FC_PHY_PORT	0
#define	FC_NPIV_PORT	1
	int			fp_npiv_type;
	int			fp_npiv_portindex[FC_NPIV_MAX_PORT];
	struct	fc_local_port	*fp_port_next;
	struct	fc_local_port	*fp_port_prev;
} fc_local_port_t;


/*
 * Struct for the d_id hash table in the fc_local_port_t struct.  The code
 * allocates memory for an array of D_ID_HASH_TABLE_SIZE elements at
 * attach time.	 The array pointer is saved at the fp_did_table member
 * in the fc_local_port_t struct.
 *  Each hash chain is a singly-linked list of fc_remote_port_t
 * structs, using the pd_did_hnext pointer in the fc_remote_port_t struct.
 */
struct d_id_hash {
	struct fc_remote_port	*d_id_head;	/* Head of linked list */
	int			d_id_count;	/* Count of list entries */
};


/*
 * Struct for the pwwn hash table in the fc_local_port_t struct.  The code
 * allocates memory for an array of PWWN_HASH_TABLE_SIZE elements at
 * attach time.	 The array pointer is saved at the fp_pwwn_table member
 * in the fc_local_port_t struct.
 * Each hash chain is a singly-linked list of fc_remote_port_t
 * structs, using the pd_wwn_hnext pointer in the fc_remote_port_t struct.
 */
struct pwwn_hash {
	struct fc_remote_port	*pwwn_head;	/* Head of linked list */
	int			pwwn_count;	/* Count of list entries */
};


/* Function prototypes */
static dev_info_t *
fctl_findchild(dev_info_t *pdip, char *cname, char *caddr);
int fctl_fca_create_npivport(dev_info_t *parent,
    dev_info_t *phydip, char *nwwn, char *pwwn, uint32_t *vindex);
static int fctl_fca_bus_ctl(dev_info_t *fca_dip, dev_info_t *rip,
    ddi_ctl_enum_t op, void *arg, void *result);
static int fctl_initchild(dev_info_t *fca_dip, dev_info_t *port_dip);
static int fctl_uninitchild(dev_info_t *fca_dip, dev_info_t *port_dip);
static int fctl_cache_constructor(void *buf, void *cdarg, int size);
static void fctl_cache_destructor(void *buf, void *cdarg);
static int fctl_pre_attach(fc_ulp_ports_t *ulp_port, fc_attach_cmd_t cmd);
static void fctl_post_attach(fc_ulp_module_t *mod, fc_ulp_ports_t *ulp_port,
    fc_attach_cmd_t cmd, int rval);
static int fctl_pre_detach(fc_ulp_ports_t *ulp_port, fc_detach_cmd_t cmd);
static void fctl_post_detach(fc_ulp_module_t *mod, fc_ulp_ports_t *ulp_port,
    fc_detach_cmd_t cmd, int rval);
static fc_ulp_ports_t *fctl_add_ulp_port(fc_ulp_module_t *ulp_module,
    fc_local_port_t *port_handle, int sleep);
static fc_ulp_ports_t *fctl_alloc_ulp_port(int sleep);
static int fctl_remove_ulp_port(struct ulp_module *ulp_module,
    fc_local_port_t *port_handle);
static void fctl_dealloc_ulp_port(fc_ulp_ports_t *next);
static fc_ulp_ports_t *fctl_get_ulp_port(struct ulp_module *ulp_module,
    fc_local_port_t *port_handle);
static int fctl_update_host_ns_values(fc_local_port_t *port,
    fc_ns_cmd_t *ns_req);
static int fctl_retrieve_host_ns_values(fc_local_port_t *port,
    fc_ns_cmd_t *ns_req);
static void fctl_print_if_not_orphan(fc_local_port_t *port,
    fc_remote_port_t *pd);
static void fctl_link_reset_done(opaque_t port_handle, uchar_t result);
static int fctl_error(int fc_errno, char **errmsg);
static int fctl_pkt_error(fc_packet_t *pkt, char **state, char **reason,
    char **action, char **expln);
static void fctl_check_alpa_list(fc_local_port_t *port, fc_remote_port_t *pd);
static int fctl_is_alpa_present(fc_local_port_t *port, uchar_t alpa);
static void fc_trace_freemsg(fc_trace_logq_t *logq);
static void fctl_init_dma_attr(fc_local_port_t *port, fc_ulp_module_t *mod,
    fc_ulp_port_info_t	*info);
fc_local_port_t *fc_get_npiv_port(fc_local_port_t *phyport, la_wwn_t *pwwn);
fc_local_port_t *fc_delete_npiv_port(fc_local_port_t *phyport, la_wwn_t *pwwn);


#ifdef	__cplusplus
}
#endif

#endif	/* _FCTL_PRIVATE_H */
