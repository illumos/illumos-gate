#ifndef ECORE_SP_VERBS
#define ECORE_SP_VERBS

#ifndef ECORE_ERASE
#define ETH_ALEN 6

#include "lm_defs.h"
#include "listq.h"
#include "eth_constants.h"
#include "bcm_utils.h"
#include "mm.h"

#ifdef __LINUX
#include <linux/time.h>
#include <linux/mutex.h>
#define ECORE_ALIGN(x, a) ALIGN(x, a)
#else
#define ECORE_ALIGN(x, a) ((((x) + (a) - 1) / (a)) * (a))

typedef volatile unsigned long atomic_t;
#endif

/* FIXME (MichalS): move to bcmtypes.h 26-Sep-10 */
typedef int BOOL;

/* None-atomic macros */
#define ECORE_SET_BIT_NA(bit, var) SET_BIT(*(var), bit)
#define ECORE_CLEAR_BIT_NA(bit, var) RESET_BIT(*(var), bit)

#ifdef __LINUX
typedef struct mutex ECORE_MUTEX;

/* Bits tweaking */
#define ECORE_SET_BIT(bit, var)   mm_atomic_or(var, (1<<bit))
#define ECORE_CLEAR_BIT(bit, var) mm_atomic_and(var, ~(1<<bit))

#elif defined(USER_LINUX)
typedef int ECORE_MUTEX;

/* Bits tweaking */
#define ECORE_SET_BIT(bit, var)   set_bit(bit, var)
#define ECORE_CLEAR_BIT(bit, var) clear_bit(bit, var)
#else /* VBD */

typedef int ECORE_MUTEX;

/* Bits tweaking */
#define ECORE_SET_BIT(bit, var)   mm_atomic_long_or(var, (1<<bit))
#define ECORE_CLEAR_BIT(bit, var) mm_atomic_long_and(var, ~(1<<bit))
#endif

/************************ Types used in ecore *********************************/

enum _ecore_status_t {
	ECORE_EXISTS  = -6,
	ECORE_IO      = -5,
	ECORE_TIMEOUT = -4,
	ECORE_INVAL   = -3,
	ECORE_BUSY    = -2,
	ECORE_NOMEM   = -1,
	ECORE_SUCCESS = 0,
	/* PENDING is not an error and should be positive */
	ECORE_PENDING = 1,
};

#endif

struct _lm_device_t;
struct eth_context;

/* Bits representing general command's configuration */
enum {
	RAMROD_TX,
	RAMROD_RX,
	/* Wait until all pending commands complete */
	RAMROD_COMP_WAIT,
	/* Don't send a ramrod, only update a registry */
	RAMROD_DRV_CLR_ONLY,
	/* Configure HW according to the current object state */
	RAMROD_RESTORE,
	 /* Execute the next command now */
	RAMROD_EXEC,
	/* Don't add a new command and continue execution of posponed
	 * commands. If not set a new command will be added to the
	 * pending commands list.
	 */
	RAMROD_CONT,
	/* If there is another pending ramrod, wait until it finishes and
	 * re-try to submit this one. This flag can be set only in sleepable
	 * context, and should not be set from the context that completes the
	 * ramrods as deadlock will occur.
	 */
	RAMROD_RETRY,
};

typedef enum {
	ECORE_OBJ_TYPE_RX,
	ECORE_OBJ_TYPE_TX,
	ECORE_OBJ_TYPE_RX_TX,
} ecore_obj_type;

/* Public slow path states */
enum {
	ECORE_FILTER_MAC_PENDING,
	ECORE_FILTER_VLAN_PENDING,
	ECORE_FILTER_VLAN_MAC_PENDING,
	ECORE_FILTER_RX_MODE_PENDING,
	ECORE_FILTER_RX_MODE_SCHED,
	ECORE_FILTER_ISCSI_ETH_START_SCHED,
	ECORE_FILTER_ISCSI_ETH_STOP_SCHED,
	ECORE_FILTER_FCOE_ETH_START_SCHED,
	ECORE_FILTER_FCOE_ETH_STOP_SCHED,
#ifdef ECORE_CHAR_DEV /* ! ECORE_UPSTREAM */
	ECORE_FILTER_BYPASS_RX_MODE_PENDING,
	ECORE_FILTER_BYPASS_MAC_PENDING,
	ECORE_FILTER_BYPASS_RSS_CONF_PENDING,
#endif
	ECORE_FILTER_MCAST_PENDING,
	ECORE_FILTER_MCAST_SCHED,
	ECORE_FILTER_RSS_CONF_PENDING,
	ECORE_AFEX_FCOE_Q_UPDATE_PENDING,
	ECORE_AFEX_PENDING_VIFSET_MCP_ACK
};

struct ecore_raw_obj {
	u8		func_id;

	/* Queue params */
	u8		cl_id;
	u32		cid;

	/* Ramrod data buffer params */
	void		*rdata;
	lm_address_t	rdata_mapping;

	/* Ramrod state params */
	int		state;   /* "ramrod is pending" state bit */
	unsigned long	*pstate; /* pointer to state buffer */

	ecore_obj_type	obj_type;

	int (*wait_comp)(struct _lm_device_t *pdev,
			 struct ecore_raw_obj *o);

	BOOL (*check_pending)(struct ecore_raw_obj *o);
	void (*clear_pending)(struct ecore_raw_obj *o);
	void (*set_pending)(struct ecore_raw_obj *o);
};

/************************* VLAN-MAC commands related parameters ***************/
struct ecore_mac_ramrod_data {
	u8 mac[ETH_ALEN];
	u8 is_inner_mac;
};

struct ecore_vlan_ramrod_data {
	u16 vlan;
};

struct ecore_vlan_mac_ramrod_data {
	u8 mac[ETH_ALEN];
	u8 is_inner_mac;
	u16 vlan;
};

union ecore_classification_ramrod_data {
	struct ecore_mac_ramrod_data mac;
	struct ecore_vlan_ramrod_data vlan;
	struct ecore_vlan_mac_ramrod_data vlan_mac;
};

/* VLAN_MAC commands */
enum ecore_vlan_mac_cmd {
	ECORE_VLAN_MAC_ADD,
	ECORE_VLAN_MAC_DEL,
	ECORE_VLAN_MAC_MOVE,
};

struct ecore_vlan_mac_data {
	/* Requested command: ECORE_VLAN_MAC_XX */
	enum ecore_vlan_mac_cmd cmd;
	/* used to contain the data related vlan_mac_flags bits from
	 * ramrod parameters.
	 */
	unsigned long vlan_mac_flags;

	/* Needed for MOVE command */
	struct ecore_vlan_mac_obj *target_obj;

	union ecore_classification_ramrod_data u;
};

/*************************** Exe Queue obj ************************************/
union ecore_exe_queue_cmd_data {
	struct ecore_vlan_mac_data vlan_mac;

	struct {
		/* TODO */
#ifndef ECORE_ERASE
		int TODO;
#endif
	} mcast;
};

struct ecore_exeq_elem {
	d_list_entry_t		link;

	/* Length of this element in the exe_chunk. */
	int				cmd_len;

	union ecore_exe_queue_cmd_data	cmd_data;
};

union ecore_qable_obj;

union ecore_exeq_comp_elem {
	union event_ring_elem *elem;
};

struct ecore_exe_queue_obj;

typedef int (*exe_q_validate)(struct _lm_device_t *pdev,
			      union ecore_qable_obj *o,
			      struct ecore_exeq_elem *elem);

typedef int (*exe_q_remove)(struct _lm_device_t *pdev,
			    union ecore_qable_obj *o,
			    struct ecore_exeq_elem *elem);

/* Return positive if entry was optimized, 0 - if not, negative
 * in case of an error.
 */
typedef int (*exe_q_optimize)(struct _lm_device_t *pdev,
			      union ecore_qable_obj *o,
			      struct ecore_exeq_elem *elem);
typedef int (*exe_q_execute)(struct _lm_device_t *pdev,
			     union ecore_qable_obj *o,
			     d_list_t *exe_chunk,
			     unsigned long *ramrod_flags);
typedef struct ecore_exeq_elem *
			(*exe_q_get)(struct ecore_exe_queue_obj *o,
				     struct ecore_exeq_elem *elem);

struct ecore_exe_queue_obj {
	/* Commands pending for an execution. */
	d_list_t	exe_queue;

	/* Commands pending for an completion. */
	d_list_t	pending_comp;

	mm_spin_lock_t		lock;

	/* Maximum length of commands' list for one execution */
	int			exe_chunk_len;

	union ecore_qable_obj	*owner;

	/****** Virtual functions ******/
	/**
	 * Called before commands execution for commands that are really
	 * going to be executed (after 'optimize').
	 *
	 * Must run under exe_queue->lock
	 */
	exe_q_validate		validate;

	/**
	 * Called before removing pending commands, cleaning allocated
	 * resources (e.g., credits from validate)
	 */
	 exe_q_remove		remove;

	/**
	 * This will try to cancel the current pending commands list
	 * considering the new command.
	 *
	 * Returns the number of optimized commands or a negative error code
	 *
	 * Must run under exe_queue->lock
	 */
	exe_q_optimize		optimize;

	/**
	 * Run the next commands chunk (owner specific).
	 */
	exe_q_execute		execute;

	/**
	 * Return the exe_queue element containing the specific command
	 * if any. Otherwise return NULL.
	 */
	exe_q_get		get;
};
/***************** Classification verbs: Set/Del MAC/VLAN/VLAN-MAC ************/
/*
 * Element in the VLAN_MAC registry list having all current configured
 * rules.
 */
struct ecore_vlan_mac_registry_elem {
	d_list_entry_t	link;

	/* Used to store the cam offset used for the mac/vlan/vlan-mac.
	 * Relevant for 57710 and 57711 only. VLANs and MACs share the
	 * same CAM for these chips.
	 */
	int			cam_offset;

	/* Needed for DEL and RESTORE flows */
	unsigned long		vlan_mac_flags;

	union ecore_classification_ramrod_data u;
};

/* Bits representing VLAN_MAC commands specific flags */
enum {
	ECORE_UC_LIST_MAC,
	ECORE_ETH_MAC,
	ECORE_ISCSI_ETH_MAC,
	ECORE_NETQ_ETH_MAC,
	ECORE_DONT_CONSUME_CAM_CREDIT,
	ECORE_DONT_CONSUME_CAM_CREDIT_DEST,
};
/* When looking for matching filters, some flags are not interesting */
#define ECORE_VLAN_MAC_CMP_MASK	(1 << ECORE_UC_LIST_MAC | \
				 1 << ECORE_ETH_MAC | \
				 1 << ECORE_ISCSI_ETH_MAC | \
				 1 << ECORE_NETQ_ETH_MAC)
#define ECORE_VLAN_MAC_CMP_FLAGS(flags) \
	((flags) & ECORE_VLAN_MAC_CMP_MASK)

struct ecore_vlan_mac_ramrod_params {
	/* Object to run the command from */
	struct ecore_vlan_mac_obj *vlan_mac_obj;

	/* General command flags: COMP_WAIT, etc. */
	unsigned long ramrod_flags;

	/* Command specific configuration request */
	struct ecore_vlan_mac_data user_req;
};

struct ecore_vlan_mac_obj {
	struct ecore_raw_obj raw;

	/* Bookkeeping list: will prevent the addition of already existing
	 * entries.
	 */
	d_list_t		head;
	/* Implement a simple reader/writer lock on the head list.
	 * all these fields should only be accessed under the exe_queue lock
	 */
	u8		head_reader; /* Num. of readers accessing head list */
	BOOL		head_exe_request; /* Pending execution request. */
	unsigned long	saved_ramrod_flags; /* Ramrods of pending execution */

	/* Execution queue interface instance */
	struct ecore_exe_queue_obj	exe_queue;

	/* MACs credit pool */
	struct ecore_credit_pool_obj	*macs_pool;

	/* VLANs credit pool */
	struct ecore_credit_pool_obj	*vlans_pool;

	/* RAMROD command to be used */
	int				ramrod_cmd;

	/* copy first n elements onto preallocated buffer
	 *
	 * @param n number of elements to get
	 * @param buf buffer preallocated by caller into which elements
	 *            will be copied. Note elements are 4-byte aligned
	 *            so buffer size must be able to accommodate the
	 *            aligned elements.
	 *
	 * @return number of copied bytes
	 */

	int (*get_n_elements)(struct _lm_device_t *pdev,
			      struct ecore_vlan_mac_obj *o, int n, u8 *base,
			      u8 stride, u8 size);

	/**
	 * Checks if ADD-ramrod with the given params may be performed.
	 *
	 * @return zero if the element may be added
	 */

	int (*check_add)(struct _lm_device_t *pdev,
			 struct ecore_vlan_mac_obj *o,
			 union ecore_classification_ramrod_data *data);

	/**
	 * Checks if DEL-ramrod with the given params may be performed.
	 *
	 * @return TRUE if the element may be deleted
	 */
	struct ecore_vlan_mac_registry_elem *
		(*check_del)(struct _lm_device_t *pdev,
			     struct ecore_vlan_mac_obj *o,
			     union ecore_classification_ramrod_data *data);

	/**
	 * Checks if DEL-ramrod with the given params may be performed.
	 *
	 * @return TRUE if the element may be deleted
	 */
	BOOL (*check_move)(struct _lm_device_t *pdev,
			   struct ecore_vlan_mac_obj *src_o,
			   struct ecore_vlan_mac_obj *dst_o,
			   union ecore_classification_ramrod_data *data);

	/**
	 *  Update the relevant credit object(s) (consume/return
	 *  correspondingly).
	 */
	BOOL (*get_credit)(struct ecore_vlan_mac_obj *o);
	BOOL (*put_credit)(struct ecore_vlan_mac_obj *o);
	BOOL (*get_cam_offset)(struct ecore_vlan_mac_obj *o, int *offset);
	BOOL (*put_cam_offset)(struct ecore_vlan_mac_obj *o, int offset);

	/**
	 * Configures one rule in the ramrod data buffer.
	 */
	void (*set_one_rule)(struct _lm_device_t *pdev,
			     struct ecore_vlan_mac_obj *o,
			     struct ecore_exeq_elem *elem, int rule_idx,
			     int cam_offset);

	/**
	*  Delete all configured elements having the given
	*  vlan_mac_flags specification. Assumes no pending for
	*  execution commands. Will schedule all all currently
	*  configured MACs/VLANs/VLAN-MACs matching the vlan_mac_flags
	*  specification for deletion and will use the given
	*  ramrod_flags for the last DEL operation.
	 *
	 * @param pdev
	 * @param o
	 * @param ramrod_flags RAMROD_XX flags
	 *
	 * @return 0 if the last operation has completed successfully
	 *         and there are no more elements left, positive value
	 *         if there are pending for completion commands,
	 *         negative value in case of failure.
	 */
	int (*delete_all)(struct _lm_device_t *pdev,
			  struct ecore_vlan_mac_obj *o,
			  unsigned long *vlan_mac_flags,
			  unsigned long *ramrod_flags);

	/**
	 * Reconfigures the next MAC/VLAN/VLAN-MAC element from the previously
	 * configured elements list.
	 *
	 * @param pdev
	 * @param p Command parameters (RAMROD_COMP_WAIT bit in
	 *          ramrod_flags is only taken into an account)
	 * @param ppos a pointer to the cookie that should be given back in the
	 *        next call to make function handle the next element. If
	 *        *ppos is set to NULL it will restart the iterator.
	 *        If returned *ppos == NULL this means that the last
	 *        element has been handled.
	 *
	 * @return int
	 */
	int (*restore)(struct _lm_device_t *pdev,
		       struct ecore_vlan_mac_ramrod_params *p,
		       struct ecore_vlan_mac_registry_elem **ppos);

	/**
	 * Should be called on a completion arrival.
	 *
	 * @param pdev
	 * @param o
	 * @param cqe Completion element we are handling
	 * @param ramrod_flags if RAMROD_CONT is set the next bulk of
	 *		       pending commands will be executed.
	 *		       RAMROD_DRV_CLR_ONLY and RAMROD_RESTORE
	 *		       may also be set if needed.
	 *
	 * @return 0 if there are neither pending nor waiting for
	 *         completion commands. Positive value if there are
	 *         pending for execution or for completion commands.
	 *         Negative value in case of an error (including an
	 *         error in the cqe).
	 */
	int (*complete)(struct _lm_device_t *pdev, struct ecore_vlan_mac_obj *o,
			union event_ring_elem *cqe,
			unsigned long *ramrod_flags);

	/**
	 * Wait for completion of all commands. Don't schedule new ones,
	 * just wait. It assumes that the completion code will schedule
	 * for new commands.
	 */
	int (*wait)(struct _lm_device_t *pdev, struct ecore_vlan_mac_obj *o);
};

enum {
	ECORE_LLH_CAM_ISCSI_ETH_LINE = 0,
	ECORE_LLH_CAM_ETH_LINE,
	ECORE_LLH_CAM_MAX_PF_LINE = NIG_REG_LLH1_FUNC_MEM_SIZE / 2
};

void ecore_set_mac_in_nig(struct _lm_device_t *pdev,
			  BOOL add, unsigned char *dev_addr, int index);

/** RX_MODE verbs:DROP_ALL/ACCEPT_ALL/ACCEPT_ALL_MULTI/ACCEPT_ALL_VLAN/NORMAL */

/* RX_MODE ramrod special flags: set in rx_mode_flags field in
 * a ecore_rx_mode_ramrod_params.
 */
enum {
	ECORE_RX_MODE_FCOE_ETH,
	ECORE_RX_MODE_ISCSI_ETH,
};

enum {
	ECORE_ACCEPT_UNICAST,
	ECORE_ACCEPT_MULTICAST,
	ECORE_ACCEPT_ALL_UNICAST,
	ECORE_ACCEPT_ALL_MULTICAST,
	ECORE_ACCEPT_BROADCAST,
	ECORE_ACCEPT_UNMATCHED,
	ECORE_ACCEPT_ANY_VLAN
};

struct ecore_rx_mode_ramrod_params {
	struct ecore_rx_mode_obj *rx_mode_obj;
	unsigned long *pstate;
	int state;
	u8 cl_id;
	u32 cid;
	u8 func_id;
	unsigned long ramrod_flags;
	unsigned long rx_mode_flags;

	/* rdata is either a pointer to eth_filter_rules_ramrod_data(e2) or to
	 * a tstorm_eth_mac_filter_config (e1x).
	 */
	void *rdata;
	lm_address_t rdata_mapping;

	/* Rx mode settings */
	unsigned long rx_accept_flags;

	/* internal switching settings */
	unsigned long tx_accept_flags;
};

struct ecore_rx_mode_obj {
	int (*config_rx_mode)(struct _lm_device_t *pdev,
			      struct ecore_rx_mode_ramrod_params *p);

	int (*wait_comp)(struct _lm_device_t *pdev,
			 struct ecore_rx_mode_ramrod_params *p);
};

/********************** Set multicast group ***********************************/

struct ecore_mcast_list_elem {
	d_list_entry_t link;
	u8 *mac;
};

union ecore_mcast_config_data {
	u8 *mac;
	u8 bin; /* used in a RESTORE flow */
};

struct ecore_mcast_ramrod_params {
	struct ecore_mcast_obj *mcast_obj;

	/* Relevant options are RAMROD_COMP_WAIT and RAMROD_DRV_CLR_ONLY */
	unsigned long ramrod_flags;

	d_list_t mcast_list; /* list of struct ecore_mcast_list_elem */
	/** TODO:
	 *      - rename it to macs_num.
	 *      - Add a new command type for handling pending commands
	 *        (remove "zero semantics").
	 *
	 *  Length of mcast_list. If zero and ADD_CONT command - post
	 *  pending commands.
	 */
	int mcast_list_len;
};

enum ecore_mcast_cmd {
	ECORE_MCAST_CMD_ADD,
	ECORE_MCAST_CMD_CONT,
	ECORE_MCAST_CMD_DEL,
	ECORE_MCAST_CMD_RESTORE,
};

struct ecore_mcast_obj {
	struct ecore_raw_obj raw;

	union {
		struct {
		#define ECORE_MCAST_BINS_NUM	256
		#define ECORE_MCAST_VEC_SZ	(ECORE_MCAST_BINS_NUM / 64)
			u64 vec[ECORE_MCAST_VEC_SZ];

			/** Number of BINs to clear. Should be updated
			 *  immediately when a command arrives in order to
			 *  properly create DEL commands.
			 */
			int num_bins_set;
		} aprox_match;

		struct {
			d_list_t macs;
			int num_macs_set;
		} exact_match;
	} registry;

	/* Pending commands */
	d_list_t pending_cmds_head;

	/* A state that is set in raw.pstate, when there are pending commands */
	int sched_state;

	/* Maximal number of mcast MACs configured in one command */
	int max_cmd_len;

	/* Total number of currently pending MACs to configure: both
	 * in the pending commands list and in the current command.
	 */
	int total_pending_num;

	u8 engine_id;

	/**
	 * @param cmd command to execute (ECORE_MCAST_CMD_X, see above)
	 */
	int (*config_mcast)(struct _lm_device_t *pdev,
			    struct ecore_mcast_ramrod_params *p,
			    enum ecore_mcast_cmd cmd);

	/**
	 * Fills the ramrod data during the RESTORE flow.
	 *
	 * @param pdev
	 * @param o
	 * @param start_idx Registry index to start from
	 * @param rdata_idx Index in the ramrod data to start from
	 *
	 * @return -1 if we handled the whole registry or index of the last
	 *         handled registry element.
	 */
	int (*hdl_restore)(struct _lm_device_t *pdev, struct ecore_mcast_obj *o,
			   int start_bin, int *rdata_idx);

	int (*enqueue_cmd)(struct _lm_device_t *pdev, struct ecore_mcast_obj *o,
			   struct ecore_mcast_ramrod_params *p,
			   enum ecore_mcast_cmd cmd);

	void (*set_one_rule)(struct _lm_device_t *pdev,
			     struct ecore_mcast_obj *o, int idx,
			     union ecore_mcast_config_data *cfg_data,
			     enum ecore_mcast_cmd cmd);

	/** Checks if there are more mcast MACs to be set or a previous
	 *  command is still pending.
	 */
	BOOL (*check_pending)(struct ecore_mcast_obj *o);

	/**
	 * Set/Clear/Check SCHEDULED state of the object
	 */
	void (*set_sched)(struct ecore_mcast_obj *o);
	void (*clear_sched)(struct ecore_mcast_obj *o);
	BOOL (*check_sched)(struct ecore_mcast_obj *o);

	/* Wait until all pending commands complete */
	int (*wait_comp)(struct _lm_device_t *pdev, struct ecore_mcast_obj *o);

	/**
	 * Handle the internal object counters needed for proper
	 * commands handling. Checks that the provided parameters are
	 * feasible.
	 */
	int (*validate)(struct _lm_device_t *pdev,
			struct ecore_mcast_ramrod_params *p,
			enum ecore_mcast_cmd cmd);

	/**
	 * Restore the values of internal counters in case of a failure.
	 */
	void (*revert)(struct _lm_device_t *pdev,
		       struct ecore_mcast_ramrod_params *p,
		       int old_num_bins);

	int (*get_registry_size)(struct ecore_mcast_obj *o);
	void (*set_registry_size)(struct ecore_mcast_obj *o, int n);
};

/*************************** Credit handling **********************************/
struct ecore_credit_pool_obj {

	/* Current amount of credit in the pool */
	atomic_t	credit;

	/* Maximum allowed credit. put() will check against it. */
	int		pool_sz;

	/* Allocate a pool table statically.
	 *
	 * Currently the maximum allowed size is MAX_MAC_CREDIT_E2(272)
	 *
	 * The set bit in the table will mean that the entry is available.
	 */
#define ECORE_POOL_VEC_SIZE	(MAX_MAC_CREDIT_E2 / 64)
	u64		pool_mirror[ECORE_POOL_VEC_SIZE];

	/* Base pool offset (initialized differently */
	int		base_pool_offset;

	/**
	 * Get the next free pool entry.
	 *
	 * @return TRUE if there was a free entry in the pool
	 */
	BOOL (*get_entry)(struct ecore_credit_pool_obj *o, int *entry);

	/**
	 * Return the entry back to the pool.
	 *
	 * @return TRUE if entry is legal and has been successfully
	 *         returned to the pool.
	 */
	BOOL (*put_entry)(struct ecore_credit_pool_obj *o, int entry);

	/**
	 * Get the requested amount of credit from the pool.
	 *
	 * @param cnt Amount of requested credit
	 * @return TRUE if the operation is successful
	 */
	BOOL (*get)(struct ecore_credit_pool_obj *o, int cnt);

	/**
	 * Returns the credit to the pool.
	 *
	 * @param cnt Amount of credit to return
	 * @return TRUE if the operation is successful
	 */
	BOOL (*put)(struct ecore_credit_pool_obj *o, int cnt);

	/**
	 * Reads the current amount of credit.
	 */
	int (*check)(struct ecore_credit_pool_obj *o);
};

/*************************** RSS configuration ********************************/
enum {
	/* RSS_MODE bits are mutually exclusive */
	ECORE_RSS_MODE_DISABLED,
	ECORE_RSS_MODE_REGULAR,

	ECORE_RSS_SET_SRCH, /* Setup searcher, E1x specific flag */

	ECORE_RSS_IPV4,
	ECORE_RSS_IPV4_TCP,
	ECORE_RSS_IPV4_UDP,
	ECORE_RSS_IPV6,
	ECORE_RSS_IPV6_TCP,
	ECORE_RSS_IPV6_UDP,

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION < 55000) /* ! BNX2X_UPSTREAM */
	ECORE_RSS_MODE_ESX51,
#endif
	ECORE_RSS_IPV4_VXLAN,
	ECORE_RSS_IPV6_VXLAN,
	ECORE_RSS_NVGRE_KEY_ENTROPY,
	ECORE_RSS_GRE_INNER_HDRS,
};

struct ecore_config_rss_params {
	struct ecore_rss_config_obj *rss_obj;

	/* may have RAMROD_COMP_WAIT set only */
	unsigned long	ramrod_flags;

	/* ECORE_RSS_X bits */
	unsigned long	rss_flags;

	/* Number hash bits to take into an account */
	u8		rss_result_mask;

	/* Indirection table */
	u8		ind_table[T_ETH_INDIRECTION_TABLE_SIZE];

	/* RSS hash values */
	u32		rss_key[10];

	/* valid only iff ECORE_RSS_UPDATE_TOE is set */
	u16		toe_rss_bitmap;
};

struct ecore_rss_config_obj {
	struct ecore_raw_obj	raw;

	/* RSS engine to use */
	u8			engine_id;

	/* Last configured indirection table */
	u8			ind_table[T_ETH_INDIRECTION_TABLE_SIZE];

	/* flags for enabling 4-tupple hash on UDP */
	u8			udp_rss_v4;
	u8			udp_rss_v6;

	int (*config_rss)(struct _lm_device_t *pdev,
			  struct ecore_config_rss_params *p);
};

/*********************** Queue state update ***********************************/

/* UPDATE command options */
enum {
	ECORE_Q_UPDATE_IN_VLAN_REM,
	ECORE_Q_UPDATE_IN_VLAN_REM_CHNG,
	ECORE_Q_UPDATE_OUT_VLAN_REM,
	ECORE_Q_UPDATE_OUT_VLAN_REM_CHNG,
	ECORE_Q_UPDATE_ANTI_SPOOF,
	ECORE_Q_UPDATE_ANTI_SPOOF_CHNG,
	ECORE_Q_UPDATE_ACTIVATE,
	ECORE_Q_UPDATE_ACTIVATE_CHNG,
	ECORE_Q_UPDATE_DEF_VLAN_EN,
	ECORE_Q_UPDATE_DEF_VLAN_EN_CHNG,
	ECORE_Q_UPDATE_SILENT_VLAN_REM_CHNG,
	ECORE_Q_UPDATE_SILENT_VLAN_REM,
	ECORE_Q_UPDATE_TX_SWITCHING_CHNG,
	ECORE_Q_UPDATE_TX_SWITCHING,
	ECORE_Q_UPDATE_PTP_PKTS_CHNG,
	ECORE_Q_UPDATE_PTP_PKTS,
};

/* Allowed Queue states */
enum ecore_q_state {
	ECORE_Q_STATE_RESET,
	ECORE_Q_STATE_INITIALIZED,
	ECORE_Q_STATE_ACTIVE,
	ECORE_Q_STATE_MULTI_COS,
	ECORE_Q_STATE_MCOS_TERMINATED,
	ECORE_Q_STATE_INACTIVE,
	ECORE_Q_STATE_STOPPED,
	ECORE_Q_STATE_TERMINATED,
	ECORE_Q_STATE_FLRED,
	ECORE_Q_STATE_MAX,
};

/* Allowed Queue states */
enum ecore_q_logical_state {
	ECORE_Q_LOGICAL_STATE_ACTIVE,
	ECORE_Q_LOGICAL_STATE_STOPPED,
};

/* Allowed commands */
enum ecore_queue_cmd {
	ECORE_Q_CMD_INIT,
	ECORE_Q_CMD_SETUP,
	ECORE_Q_CMD_SETUP_TX_ONLY,
	ECORE_Q_CMD_DEACTIVATE,
	ECORE_Q_CMD_ACTIVATE,
	ECORE_Q_CMD_UPDATE,
	ECORE_Q_CMD_UPDATE_TPA,
	ECORE_Q_CMD_HALT,
	ECORE_Q_CMD_CFC_DEL,
	ECORE_Q_CMD_TERMINATE,
	ECORE_Q_CMD_EMPTY,
	ECORE_Q_CMD_MAX,
};

/* queue SETUP + INIT flags */
enum {
	ECORE_Q_FLG_TPA,
	ECORE_Q_FLG_TPA_IPV6,
	ECORE_Q_FLG_TPA_GRO,
	ECORE_Q_FLG_STATS,
#ifndef ECORE_UPSTREAM /* ! ECORE_UPSTREAM */
	ECORE_Q_FLG_VMQUEUE_MODE,
#endif
	ECORE_Q_FLG_ZERO_STATS,
	ECORE_Q_FLG_ACTIVE,
	ECORE_Q_FLG_OV,
	ECORE_Q_FLG_VLAN,
	ECORE_Q_FLG_COS,
	ECORE_Q_FLG_HC,
	ECORE_Q_FLG_HC_EN,
	ECORE_Q_FLG_DHC,
#ifdef ECORE_OOO /* ! ECORE_UPSTREAM */
	ECORE_Q_FLG_OOO,
#endif
	ECORE_Q_FLG_FCOE,
	ECORE_Q_FLG_LEADING_RSS,
	ECORE_Q_FLG_MCAST,
	ECORE_Q_FLG_DEF_VLAN,
	ECORE_Q_FLG_TX_SWITCH,
	ECORE_Q_FLG_TX_SEC,
	ECORE_Q_FLG_ANTI_SPOOF,
	ECORE_Q_FLG_SILENT_VLAN_REM,
	ECORE_Q_FLG_FORCE_DEFAULT_PRI,
	ECORE_Q_FLG_REFUSE_OUTBAND_VLAN,
	ECORE_Q_FLG_PCSUM_ON_PKT,
	ECORE_Q_FLG_TUN_INC_INNER_IP_ID
};

/* Queue type options: queue type may be a combination of below. */
enum ecore_q_type {
#ifdef ECORE_OOO /* ! ECORE_UPSTREAM */
	ECORE_Q_TYPE_FWD,
#endif
	/** TODO: Consider moving both these flags into the init()
	 *        ramrod params.
	 */
	ECORE_Q_TYPE_HAS_RX,
	ECORE_Q_TYPE_HAS_TX,
};

#define ECORE_PRIMARY_CID_INDEX			0
#define ECORE_MULTI_TX_COS_E1X			3 /* QM only */
#define ECORE_MULTI_TX_COS_E2_E3A0		2
#define ECORE_MULTI_TX_COS_E3B0			3
#define ECORE_MULTI_TX_COS			3 /* Maximum possible */
#define MAC_PAD (ECORE_ALIGN(ETH_ALEN, sizeof(u32)) - ETH_ALEN)
/* DMAE channel to be used by FW for timesync workaroun. A driver that sends
 * timesync-related ramrods must not use this DMAE command ID.
 */
#define FW_DMAE_CMD_ID 6

struct ecore_queue_init_params {
	struct {
		unsigned long	flags;
		u16		hc_rate;
		u8		fw_sb_id;
		u8		sb_cq_index;
	} tx;

	struct {
		unsigned long	flags;
		u16		hc_rate;
		u8		fw_sb_id;
		u8		sb_cq_index;
	} rx;

	/* CID context in the host memory */
	struct eth_context *cxts[ECORE_MULTI_TX_COS];

	/* maximum number of cos supported by hardware */
	u8 max_cos;
};

struct ecore_queue_terminate_params {
	/* index within the tx_only cids of this queue object */
	u8 cid_index;
};

struct ecore_queue_cfc_del_params {
	/* index within the tx_only cids of this queue object */
	u8 cid_index;
};

struct ecore_queue_update_params {
	unsigned long	update_flags; /* ECORE_Q_UPDATE_XX bits */
	u16		def_vlan;
	u16		silent_removal_value;
	u16		silent_removal_mask;
/* index within the tx_only cids of this queue object */
	u8		cid_index;
};

struct ecore_queue_update_tpa_params {
	lm_address_t sge_map;
	u8 update_ipv4;
	u8 update_ipv6;
	u8 max_tpa_queues;
	u8 max_sges_pkt;
	u8 complete_on_both_clients;
	u8 dont_verify_thr;
	u8 tpa_mode;
	u8 _pad;

	u16 sge_buff_sz;
	u16 max_agg_sz;

	u16 sge_pause_thr_low;
	u16 sge_pause_thr_high;
};

struct rxq_pause_params {
	u16		bd_th_lo;
	u16		bd_th_hi;
	u16		rcq_th_lo;
	u16		rcq_th_hi;
	u16		sge_th_lo; /* valid iff ECORE_Q_FLG_TPA */
	u16		sge_th_hi; /* valid iff ECORE_Q_FLG_TPA */
	u16		pri_map;
};

/* general */
struct ecore_general_setup_params {
	/* valid iff ECORE_Q_FLG_STATS */
	u8		stat_id;

	u8		spcl_id;
	u16		mtu;
	u8		cos;
};

struct ecore_rxq_setup_params {
	/* dma */
	lm_address_t	dscr_map;
	lm_address_t	sge_map;
	lm_address_t	rcq_map;
	lm_address_t	rcq_np_map;

	u16		drop_flags;
	u16		buf_sz;
	u8		fw_sb_id;
	u8		cl_qzone_id;

	/* valid iff ECORE_Q_FLG_TPA */
	u16		tpa_agg_sz;
	u16		sge_buf_sz;
	u8		max_sges_pkt;
	u8		max_tpa_queues;
	u8		rss_engine_id;

	/* valid iff ECORE_Q_FLG_MCAST */
	u8		mcast_engine_id;

	u8		cache_line_log;

	u8		sb_cq_index;

	/* valid iff BXN2X_Q_FLG_SILENT_VLAN_REM */
	u16 silent_removal_value;
	u16 silent_removal_mask;
};

struct ecore_txq_setup_params {
	/* dma */
	lm_address_t	dscr_map;

	u8		fw_sb_id;
	u8		sb_cq_index;
	u8		cos;		/* valid iff ECORE_Q_FLG_COS */
	u16		traffic_type;
	/* equals to the leading rss client id, used for TX classification*/
	u8		tss_leading_cl_id;

	/* valid iff ECORE_Q_FLG_DEF_VLAN */
	u16		default_vlan;
};

struct ecore_queue_setup_params {
	struct ecore_general_setup_params gen_params;
	struct ecore_txq_setup_params txq_params;
	struct ecore_rxq_setup_params rxq_params;
	struct rxq_pause_params pause_params;
	unsigned long flags;
};

struct ecore_queue_setup_tx_only_params {
	struct ecore_general_setup_params	gen_params;
	struct ecore_txq_setup_params		txq_params;
	unsigned long				flags;
	/* index within the tx_only cids of this queue object */
	u8					cid_index;
};

struct ecore_queue_state_params {
	struct ecore_queue_sp_obj *q_obj;

	/* Current command */
	enum ecore_queue_cmd cmd;

	/* may have RAMROD_COMP_WAIT set only */
	unsigned long ramrod_flags;

	/* Params according to the current command */
	union {
		struct ecore_queue_update_params	update;
		struct ecore_queue_update_tpa_params    update_tpa;
		struct ecore_queue_setup_params		setup;
		struct ecore_queue_init_params		init;
		struct ecore_queue_setup_tx_only_params	tx_only;
		struct ecore_queue_terminate_params	terminate;
		struct ecore_queue_cfc_del_params	cfc_del;
	} params;
};

struct ecore_viflist_params {
	u8 echo_res;
	u8 func_bit_map_res;
};

struct ecore_queue_sp_obj {
	u32		cids[ECORE_MULTI_TX_COS];
	u8		cl_id;
	u8		func_id;

	/* number of traffic classes supported by queue.
	 * The primary connection of the queue supports the first traffic
	 * class. Any further traffic class is supported by a tx-only
	 * connection.
	 *
	 * Therefore max_cos is also a number of valid entries in the cids
	 * array.
	 */
	u8 max_cos;
	u8 num_tx_only, next_tx_only;

	enum ecore_q_state state, next_state;

	/* bits from enum ecore_q_type */
	unsigned long	type;

	/* ECORE_Q_CMD_XX bits. This object implements "one
	 * pending" paradigm but for debug and tracing purposes it's
	 * more convenient to have different bits for different
	 * commands.
	 */
	unsigned long	pending;

	/* Buffer to use as a ramrod data and its mapping */
	void		*rdata;
	lm_address_t	rdata_mapping;

	/**
	 * Performs one state change according to the given parameters.
	 *
	 * @return 0 in case of success and negative value otherwise.
	 */
	int (*send_cmd)(struct _lm_device_t *pdev,
			struct ecore_queue_state_params *params);

	/**
	 * Sets the pending bit according to the requested transition.
	 */
	int (*set_pending)(struct ecore_queue_sp_obj *o,
			   struct ecore_queue_state_params *params);

	/**
	 * Checks that the requested state transition is legal.
	 */
	int (*check_transition)(struct _lm_device_t *pdev,
				struct ecore_queue_sp_obj *o,
				struct ecore_queue_state_params *params);

	/**
	 * Completes the pending command.
	 */
	int (*complete_cmd)(struct _lm_device_t *pdev,
			    struct ecore_queue_sp_obj *o,
			    enum ecore_queue_cmd);

	int (*wait_comp)(struct _lm_device_t *pdev,
			 struct ecore_queue_sp_obj *o,
			 enum ecore_queue_cmd cmd);
};

/********************** Function state update *********************************/

/* UPDATE command options */
enum {
	ECORE_F_UPDATE_TX_SWITCH_SUSPEND_CHNG,
	ECORE_F_UPDATE_TX_SWITCH_SUSPEND,
	ECORE_F_UPDATE_SD_VLAN_TAG_CHNG,
	ECORE_F_UPDATE_SD_VLAN_ETH_TYPE_CHNG,
	ECORE_F_UPDATE_VLAN_FORCE_PRIO_CHNG,
	ECORE_F_UPDATE_VLAN_FORCE_PRIO_FLAG,
	ECORE_F_UPDATE_TUNNEL_CFG_CHNG,
	ECORE_F_UPDATE_TUNNEL_CLSS_EN,
	ECORE_F_UPDATE_TUNNEL_INNER_GRE_RSS_EN,
};

/* Allowed Function states */
enum ecore_func_state {
	ECORE_F_STATE_RESET,
	ECORE_F_STATE_INITIALIZED,
	ECORE_F_STATE_STARTED,
	ECORE_F_STATE_TX_STOPPED,
	ECORE_F_STATE_MAX,
};

/* Allowed Function commands */
enum ecore_func_cmd {
	ECORE_F_CMD_HW_INIT,
	ECORE_F_CMD_START,
	ECORE_F_CMD_STOP,
	ECORE_F_CMD_HW_RESET,
	ECORE_F_CMD_AFEX_UPDATE,
	ECORE_F_CMD_AFEX_VIFLISTS,
	ECORE_F_CMD_TX_STOP,
	ECORE_F_CMD_TX_START,
	ECORE_F_CMD_SWITCH_UPDATE,
	ECORE_F_CMD_SET_TIMESYNC,
	ECORE_F_CMD_MAX,
};

struct ecore_func_hw_init_params {
	/* A load phase returned by MCP.
	 *
	 * May be:
	 *		FW_MSG_CODE_DRV_LOAD_COMMON_CHIP
	 *		FW_MSG_CODE_DRV_LOAD_COMMON
	 *		FW_MSG_CODE_DRV_LOAD_PORT
	 *		FW_MSG_CODE_DRV_LOAD_FUNCTION
	 */
	u32 load_phase;
};

struct ecore_func_hw_reset_params {
	/* A load phase returned by MCP.
	 *
	 * May be:
	 *		FW_MSG_CODE_DRV_LOAD_COMMON_CHIP
	 *		FW_MSG_CODE_DRV_LOAD_COMMON
	 *		FW_MSG_CODE_DRV_LOAD_PORT
	 *		FW_MSG_CODE_DRV_LOAD_FUNCTION
	 */
	u32 reset_phase;
};

struct ecore_func_start_params {
	/* Multi Function mode:
	 *	- Single Function
	 *	- Switch Dependent
	 *	- Switch Independent
	 */
	u16 mf_mode;

	/* Switch Dependent mode outer VLAN tag */
	u16 sd_vlan_tag;

	/* Function cos mode */
	u8 network_cos_mode;

	/* TUNN_MODE_NONE/TUNN_MODE_VXLAN/TUNN_MODE_GRE */
	u8 tunnel_mode;

	/* tunneling classification enablement */
	u8 tunn_clss_en;

	/* NVGRE_TUNNEL/L2GRE_TUNNEL/IPGRE_TUNNEL */
	u8 gre_tunnel_type;

	/* Enables Inner GRE RSS on the function, depends on the client RSS
	 * capailities
	 */
	u8 inner_gre_rss_en;

	/* UDP dest port for VXLAN */
	u16 vxlan_dst_port;

	/** Allows accepting of packets failing MF classification, possibly
	 * only matching a given ethertype
	 */
	u8 class_fail;
	u16 class_fail_ethtype;

	/* Override priority of output packets */
	u8 sd_vlan_force_pri;
	u8 sd_vlan_force_pri_val;

	/* Replace vlan's ethertype */
	u16 sd_vlan_eth_type;

	/* Prevent inner vlans from being added by FW */
	u8 no_added_tags;
};

struct ecore_func_switch_update_params {
	unsigned long changes; /* ECORE_F_UPDATE_XX bits */
	u16 vlan;
	u16 vlan_eth_type;
	u8 vlan_force_prio;
	u8 tunnel_mode;
	u8 gre_tunnel_type;
	u16 vxlan_dst_port;

};

struct ecore_func_afex_update_params {
	u16 vif_id;
	u16 afex_default_vlan;
	u8 allowed_priorities;
};

struct ecore_func_afex_viflists_params {
	u16 vif_list_index;
	u8 func_bit_map;
	u8 afex_vif_list_command;
	u8 func_to_clear;
};

struct ecore_func_tx_start_params {
	struct priority_cos traffic_type_to_priority_cos[MAX_TRAFFIC_TYPES];
	u8 dcb_enabled;
	u8 dcb_version;
	u8 dont_add_pri_0_en;
};

struct ecore_func_set_timesync_params {
	/* Reset, set or keep the current drift value */
	u8 drift_adjust_cmd;
	/* Dec, inc or keep the current offset */
	u8 offset_cmd;
	/* Drift value direction */
	u8 add_sub_drift_adjust_value;
	/* Drift, period and offset values to be used according to the commands
	 * above.
	 */
	u8 drift_adjust_value;
	u32 drift_adjust_period;
	u64 offset_delta;
};

struct ecore_func_state_params {
	struct ecore_func_sp_obj *f_obj;

	/* Current command */
	enum ecore_func_cmd cmd;

	/* may have RAMROD_COMP_WAIT set only */
	unsigned long	ramrod_flags;

	/* Params according to the current command */
	union {
		struct ecore_func_hw_init_params hw_init;
		struct ecore_func_hw_reset_params hw_reset;
		struct ecore_func_start_params start;
		struct ecore_func_switch_update_params switch_update;
		struct ecore_func_afex_update_params afex_update;
		struct ecore_func_afex_viflists_params afex_viflists;
		struct ecore_func_tx_start_params tx_start;
		struct ecore_func_set_timesync_params set_timesync;
	} params;
};

struct ecore_func_sp_drv_ops {
	/* Init tool + runtime initialization:
	 *      - Common Chip
	 *      - Common (per Path)
	 *      - Port
	 *      - Function phases
	 */
	int (*init_hw_cmn_chip)(struct _lm_device_t *pdev);
	int (*init_hw_cmn)(struct _lm_device_t *pdev);
	int (*init_hw_port)(struct _lm_device_t *pdev);
	int (*init_hw_func)(struct _lm_device_t *pdev);

	/* Reset Function HW: Common, Port, Function phases. */
	void (*reset_hw_cmn)(struct _lm_device_t *pdev);
	void (*reset_hw_port)(struct _lm_device_t *pdev);
	void (*reset_hw_func)(struct _lm_device_t *pdev);

	/* Init/Free GUNZIP resources */
	int (*gunzip_init)(struct _lm_device_t *pdev);
	void (*gunzip_end)(struct _lm_device_t *pdev);

	/* Prepare/Release FW resources */
	int (*init_fw)(struct _lm_device_t *pdev);
	void (*release_fw)(struct _lm_device_t *pdev);
};

struct ecore_func_sp_obj {
	enum ecore_func_state	state, next_state;

	/* ECORE_FUNC_CMD_XX bits. This object implements "one
	 * pending" paradigm but for debug and tracing purposes it's
	 * more convenient to have different bits for different
	 * commands.
	 */
	unsigned long		pending;

	/* Buffer to use as a ramrod data and its mapping */
	void			*rdata;
	lm_address_t		rdata_mapping;

	/* Buffer to use as a afex ramrod data and its mapping.
	 * This can't be same rdata as above because afex ramrod requests
	 * can arrive to the object in parallel to other ramrod requests.
	 */
	void			*afex_rdata;
	lm_address_t		afex_rdata_mapping;

	/* this mutex validates that when pending flag is taken, the next
	 * ramrod to be sent will be the one set the pending bit
	 */
	ECORE_MUTEX		one_pending_mutex;

	/* Driver interface */
	struct ecore_func_sp_drv_ops	*drv;

	/**
	 * Performs one state change according to the given parameters.
	 *
	 * @return 0 in case of success and negative value otherwise.
	 */
	int (*send_cmd)(struct _lm_device_t *pdev,
			struct ecore_func_state_params *params);

	/**
	 * Checks that the requested state transition is legal.
	 */
	int (*check_transition)(struct _lm_device_t *pdev,
				struct ecore_func_sp_obj *o,
				struct ecore_func_state_params *params);

	/**
	 * Completes the pending command.
	 */
	int (*complete_cmd)(struct _lm_device_t *pdev,
			    struct ecore_func_sp_obj *o,
			    enum ecore_func_cmd cmd);

	int (*wait_comp)(struct _lm_device_t *pdev, struct ecore_func_sp_obj *o,
			 enum ecore_func_cmd cmd);
};

/********************** Interfaces ********************************************/
/* Queueable objects set */
union ecore_qable_obj {
	struct ecore_vlan_mac_obj vlan_mac;
};
/************** Function state update *********/
void ecore_init_func_obj(struct _lm_device_t *pdev,
			 struct ecore_func_sp_obj *obj,
			 void *rdata, lm_address_t rdata_mapping,
			 void *afex_rdata, lm_address_t afex_rdata_mapping,
			 struct ecore_func_sp_drv_ops *drv_iface);

int ecore_func_state_change(struct _lm_device_t *pdev,
			    struct ecore_func_state_params *params);

enum ecore_func_state ecore_func_get_state(struct _lm_device_t *pdev,
					   struct ecore_func_sp_obj *o);
/******************* Queue State **************/
void ecore_init_queue_obj(struct _lm_device_t *pdev,
			  struct ecore_queue_sp_obj *obj, u8 cl_id, u32 *cids,
			  u8 cid_cnt, u8 func_id, void *rdata,
			  lm_address_t rdata_mapping, unsigned long type);

int ecore_queue_state_change(struct _lm_device_t *pdev,
			     struct ecore_queue_state_params *params);

int ecore_get_q_logical_state(struct _lm_device_t *pdev,
			       struct ecore_queue_sp_obj *obj);

/********************* VLAN-MAC ****************/
void ecore_init_mac_obj(struct _lm_device_t *pdev,
			struct ecore_vlan_mac_obj *mac_obj,
			u8 cl_id, u32 cid, u8 func_id, void *rdata,
			lm_address_t rdata_mapping, int state,
			unsigned long *pstate, ecore_obj_type type,
			struct ecore_credit_pool_obj *macs_pool);

void ecore_init_vlan_obj(struct _lm_device_t *pdev,
			 struct ecore_vlan_mac_obj *vlan_obj,
			 u8 cl_id, u32 cid, u8 func_id, void *rdata,
			 lm_address_t rdata_mapping, int state,
			 unsigned long *pstate, ecore_obj_type type,
			 struct ecore_credit_pool_obj *vlans_pool);

void ecore_init_vlan_mac_obj(struct _lm_device_t *pdev,
			     struct ecore_vlan_mac_obj *vlan_mac_obj,
			     u8 cl_id, u32 cid, u8 func_id, void *rdata,
			     lm_address_t rdata_mapping, int state,
			     unsigned long *pstate, ecore_obj_type type,
			     struct ecore_credit_pool_obj *macs_pool,
			     struct ecore_credit_pool_obj *vlans_pool);

int ecore_vlan_mac_h_read_lock(struct _lm_device_t *pdev,
					struct ecore_vlan_mac_obj *o);
void ecore_vlan_mac_h_read_unlock(struct _lm_device_t *pdev,
				  struct ecore_vlan_mac_obj *o);
int ecore_vlan_mac_h_write_lock(struct _lm_device_t *pdev,
				struct ecore_vlan_mac_obj *o);
void ecore_vlan_mac_h_write_unlock(struct _lm_device_t *pdev,
					  struct ecore_vlan_mac_obj *o);
int ecore_config_vlan_mac(struct _lm_device_t *pdev,
			   struct ecore_vlan_mac_ramrod_params *p);

int ecore_vlan_mac_move(struct _lm_device_t *pdev,
			struct ecore_vlan_mac_ramrod_params *p,
			struct ecore_vlan_mac_obj *dest_o);

/********************* RX MODE ****************/

void ecore_init_rx_mode_obj(struct _lm_device_t *pdev,
			    struct ecore_rx_mode_obj *o);

/**
 * bnx2x_config_rx_mode - Send and RX_MODE ramrod according to the provided parameters.
 *
 * @p: Command parameters
 *
 * Return: 0 - if operation was successful and there is no pending completions,
 *         positive number - if there are pending completions,
 *         negative - if there were errors
 */
int ecore_config_rx_mode(struct _lm_device_t *pdev,
			 struct ecore_rx_mode_ramrod_params *p);

/****************** MULTICASTS ****************/

void ecore_init_mcast_obj(struct _lm_device_t *pdev,
			  struct ecore_mcast_obj *mcast_obj,
			  u8 mcast_cl_id, u32 mcast_cid, u8 func_id,
			  u8 engine_id, void *rdata, lm_address_t rdata_mapping,
			  int state, unsigned long *pstate,
			  ecore_obj_type type);

/**
 * bnx2x_config_mcast - Configure multicast MACs list.
 *
 * @cmd: command to execute: BNX2X_MCAST_CMD_X
 *
 * May configure a new list
 * provided in p->mcast_list (ECORE_MCAST_CMD_ADD), clean up
 * (ECORE_MCAST_CMD_DEL) or restore (ECORE_MCAST_CMD_RESTORE) a current
 * configuration, continue to execute the pending commands
 * (ECORE_MCAST_CMD_CONT).
 *
 * If previous command is still pending or if number of MACs to
 * configure is more that maximum number of MACs in one command,
 * the current command will be enqueued to the tail of the
 * pending commands list.
 *
 * Return: 0 is operation was successfull and there are no pending completions,
 *         negative if there were errors, positive if there are pending
 *         completions.
 */
int ecore_config_mcast(struct _lm_device_t *pdev,
		       struct ecore_mcast_ramrod_params *p,
		       enum ecore_mcast_cmd cmd);

/****************** CREDIT POOL ****************/
void ecore_init_mac_credit_pool(struct _lm_device_t *pdev,
				struct ecore_credit_pool_obj *p, u8 func_id,
				u8 func_num);
void ecore_init_vlan_credit_pool(struct _lm_device_t *pdev,
				 struct ecore_credit_pool_obj *p, u8 func_id,
				 u8 func_num);

/****************** RSS CONFIGURATION ****************/
void ecore_init_rss_config_obj(struct _lm_device_t *pdev,
			       struct ecore_rss_config_obj *rss_obj,
			       u8 cl_id, u32 cid, u8 func_id, u8 engine_id,
			       void *rdata, lm_address_t rdata_mapping,
			       int state, unsigned long *pstate,
			       ecore_obj_type type);

/**
 * bnx2x_config_rss - Updates RSS configuration according to provided parameters
 *
 * Return: 0 in case of success
 */
int ecore_config_rss(struct _lm_device_t *pdev,
		     struct ecore_config_rss_params *p);

/**
 * bnx2x_get_rss_ind_table - Return the current ind_table configuration.
 *
 * @ind_table: buffer to fill with the current indirection
 *                  table content. Should be at least
 *                  T_ETH_INDIRECTION_TABLE_SIZE bytes long.
 */
void ecore_get_rss_ind_table(struct ecore_rss_config_obj *rss_obj,
			     u8 *ind_table);

#endif /* ECORE_SP_VERBS */
