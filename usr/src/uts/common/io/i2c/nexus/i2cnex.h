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
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _I2CNEX_H
#define	_I2CNEX_H

/*
 * Internal definitions for the i2c nexus driver.
 */

#include <sys/id_space.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/i2c/controller.h>
#include <sys/i2c/client.h>
#include <sys/i2c/mux.h>
#include <sys/i2c/ioctl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This is the maximum number of ports we'll support on a controller or switch
 * today.
 */
#define	I2C_MAX_PORTS	16

/*
 * We split our minor range in two. There is a range that is used for devices
 * and a range that is used for users. The range for devices is in the range [1,
 * MAXMIN32], where as users start at MAXMIN32+1 and are given up to a million
 * entries.
 */
#define	I2C_DEV_MINOR_MIN	1
#define	I2C_DEV_MINOR_MAX	MAXMIN32
#define	I2C_USER_MINOR_MIN	(MAXMIN32 + 1)
#define	I2C_USER_MINOR_MAX	(MAXMIN32 + (2 << 19))

/*
 * Global data that tracks minor mapping and related.
 */
typedef struct i2cnex_minors {
	kmutex_t im_mutex;
	id_space_t *im_ids;
	id_space_t *im_user_ids;
	avl_tree_t im_nexi;
	avl_tree_t im_users;
	list_t im_roots;
} i2cnex_minors_t;

/*
 * Forward decls for various things.
 */
typedef struct i2c_root i2c_root_t;
typedef struct i2c_ctrl i2c_ctrl_t;
typedef struct i2c_port i2c_port_t;
typedef struct i2c_dev i2c_dev_t;
typedef struct i2c_mux i2c_mux_t;
typedef struct i2c_nexus i2c_nexus_t;

/*
 * Address tracking structures. See i2cnex_addr.c theory statement for more
 * information.
 */
typedef struct i2c_addr_track {
	bool at_downstream[1 << 10];
	uint8_t at_refcnt[1 << 10];
	major_t at_major[1 << 10];
} i2c_addr_track_t;

/*
 * This represents a port on a mux or a controller. Device IDs are unique
 * downstream of a port.
 */
struct i2c_port {
	uint32_t ip_portno;
	/*
	 * This is used to indicate the number of device's that exist on a port
	 * below this one. The number of devices that are on this port is just
	 * an avl_numnodes() call on ip_devices.
	 */
	uint32_t ip_ndevs_ds;
	i2c_nexus_t *ip_nex;
	i2c_addr_track_t ip_track_7b;
	avl_tree_t ip_devices;
	list_node_t ip_ctrl_link;
};

/*
 * This represents a single device on the i2c bus.
 */
struct i2c_dev {
	avl_node_t id_link;
	i2c_addr_t id_addr;
	char **id_ucompat;
	uint_t id_nucompat;
	i2c_nexus_t *id_nex;
	i2c_mux_t *id_mux;
	list_t id_clients;
};

/*
 * This represents information about a single mux. This is used when a device
 * registers with the mux framework.
 */
struct i2c_mux {
	i2c_nexus_t *im_nex;
	const i2c_mux_ops_t *im_ops;
	void *im_drv;
	uint32_t im_nports;
	/*
	 * This data is all protected by the controller lock after
	 * initialization.
	 */
	uint32_t im_curport;
	i2c_port_t im_ports[I2C_MAX_PORTS];
};

typedef enum {
	I2C_CTRL_MA_NONE,
	I2C_CTRL_MA_DESELECT,
	I2C_CTRL_MA_UPDATE
} i2c_ctrl_mux_act_t;

typedef struct i2c_ctrl_lock {
	kmutex_t cl_mutex;
	i2c_txn_t *cl_owner;
	list_t cl_waiters;
	/*
	 * The following members are used to track when a nexus operation is
	 * active. These basically allow a subsequent nexus operation in the
	 * same thread to take advantage of the lock. See the locking section
	 * in the theory statement for more information.
	 */
	uintptr_t cl_nexus_thr;
	list_t cl_stack;
	/*
	 * Misc. debugging stats.
	 */
	uint32_t cl_nlocks;
	uint32_t cl_nwait;
	uint32_t cl_nnonblock;
	uint32_t cl_nsig;
	uint32_t cl_nsig_block;
	uint32_t cl_nsig_acq;
	uint32_t cl_nstack;
	uint32_t cl_nnexus;
} i2c_ctrl_lock_t;

typedef struct i2c_ctrl_limit {
	uint32_t lim_i2c_read;
	uint32_t lim_i2c_write;
	smbus_prop_op_t lim_smbus_ops;
	uint32_t lim_smbus_block;
} i2c_ctrl_limit_t;

/*
 * This represents an instance of a controller. A controller has independent
 * controls and settings.
 */
struct i2c_ctrl {
	list_node_t ic_link;
	i2c_root_t *ic_root;
	void *ic_drv;
	const i2c_ctrl_ops_t *ic_ops;
	i2c_ctrl_type_t ic_type;
	i2c_nexus_t *ic_nexus;
	uint32_t ic_nports;
	i2c_port_t ic_ports[I2C_MAX_PORTS];
	i2c_ctrl_lock_t ic_lock;
	i2c_ctrl_limit_t ic_limit;
	union {
		smbus_req_t req_smbus;
		i2c_req_t req_i2c;
	} ic_reqs;
	/*
	 * These lists are used to manage and track the set of mux ports that
	 * are currently being used on the bus in the order that they exist in
	 * the tree. The head of the list will generally be the current port on
	 * the bus that's being used. The tail the furthest mux in the tree.
	 * When something is in here, it means that traffic will flow down the
	 * port. The plan list is used when we're switching between different
	 * muxes and want to indicate what the new order will be. See the I/O
	 * and Mux Tracking section of the theory statement for more
	 * information.
	 *
	 * The mux state is used to track what mux activity we're actively
	 * doing. This is useful because when we activate or deactivate a mux,
	 * it'll call back into the mux update logic.
	 */
	list_t ic_mux_active;
	list_t ic_mux_plan;
	i2c_ctrl_mux_act_t ic_mux_state;
	/*
	 * The ic_txn_lock protects the list of i2c_txn_t only. It is not used
	 * as part of locking more broadly.
	 */
	kmutex_t ic_txn_lock;
	list_t ic_txns;
};

typedef enum {
	I2C_NEXUS_T_CTRL,
	I2C_NEXUS_T_PORT,
	I2C_NEXUS_T_DEV,
	I2C_NEXUS_T_MUX
} i2c_nexus_type_t;

typedef enum {
	/*
	 * This indicates that the nexus is discoverable and present in the
	 * global tree.
	 */
	I2C_NEXUS_F_DISC = 1 << 0
} i2c_nexus_flags_t;

struct i2c_nexus {
	avl_node_t in_avl;
	i2c_nexus_type_t in_type;
	i2c_nexus_flags_t in_flags;
	i2c_ctrl_t *in_ctrl;
	char in_name[I2C_NAME_MAX];
	char in_addr[I2C_NAME_MAX];
	id_t in_minor;
	dev_info_t *in_dip;
	dev_info_t *in_pdip;
	i2c_nexus_t *in_pnex;
	union {
		i2c_port_t *in_port;
		i2c_dev_t *in_dev;
		i2c_mux_t *in_mux;
	} in_data;
};

/*
 * This represents the root of an i2c controller tree.
 */
struct i2c_root {
	list_node_t ir_link;
	dev_info_t *ir_dip;
	kmutex_t ir_mutex;
	list_t ir_ctrls;
};

/*
 * Various debugging tags that indicate where we were trying to create an i2c
 * transaction.
 */
typedef enum {
	I2C_LOCK_TAG_MUX_REG,
	I2C_LOCK_TAG_MUX_UNREG,
	I2C_LOCK_TAG_BUS_CONFIG,
	I2C_LOCK_TAG_BUS_UNCONFIG,
	I2C_LOCK_TAG_DIP_DETACH,
	I2C_LOCK_TAG_CLIENT_LOCK,
	I2C_LOCK_TAG_CLIENT_ALLOC,
	I2C_LOCK_TAG_CLIENT_ADDR,
	I2C_LOCK_TAG_CLIENT_DESTROY,
	I2C_LOCK_TAG_USER_IO,
	I2C_LOCK_TAG_USER_DEV_ADD,
	I2C_LOCK_TAG_USER_DEV_INFO,
	I2C_LOCK_TAG_USER_DEV_RM,
	I2C_LOCK_TAG_USER_PROP_INFO,
	I2C_LOCK_TAG_USER_PROP_SET
} i2c_txn_tag_t;

typedef enum {
	I2C_TXN_STATE_UNLOCKED	= 0,
	I2C_TXN_STATE_BLOCKED,
	I2C_TXN_STATE_ACQUIRED
} i2c_txn_state_t;

/*
 * This data structure represents an i2c transaction structure which is used to
 * wait on and acquire exclusive access to a controller.
 */
typedef struct i2c_txn {
	list_node_t txn_link;
	list_node_t txn_wait_link;
	list_node_t txn_stack_link;
	i2c_ctrl_t *txn_ctrl;
	kcondvar_t txn_cv;
	i2c_txn_state_t txn_state;
	i2c_errno_t txn_err;
	/*
	 * Misc. debugging information. None of this may be relied upon for
	 * correct operation of lock information.  The kthread_t and pid that
	 * acquired this may not be the same as the one that is actually later
	 * performing I/O and using it. Note, that txn_last_change is used for
	 * some correctness assertions.
	 */
	i2c_txn_tag_t txn_tag;
	const void *txn_debug;
	hrtime_t txn_last_change;
	uintptr_t txn_alloc_kthread;
	uintptr_t txn_acq_kthread;
	pid_t txn_acq_pid;
} i2c_txn_t;

typedef enum {
	/*
	 * This flag indicates that this minor currently holds its controller
	 * through a persistent ioctl (which isn't quite present). When this is
	 * the case, individual I/O operations don't need to acquire and release
	 * the bus.
	 */
	I2C_USER_F_CTRL_LOCK	= 1 << 0,
	/*
	 * This flag indicates that this minor is actively trying to perform
	 * I/O, manipulate the set of devices on the bus, etc. A thread may only
	 * hold this for the duration of a single ioctl. The thread that has set
	 * this will be noted in the iu_thread member.
	 */
	I2C_USER_F_ACTIVE	= 1 << 1,
	/*
	 * This flag indicates that we took the controller lock as part of this
	 * operation and therefore need to make sure that we release it. This
	 * can only be set if the I2C_USER_F_ACTIVE flag is set.
	 */
	I2C_USER_F_LOCK		= 1 << 2
} i2c_user_flags_t;

/*
 * This tracks information about an individual minor data that a user may have
 * open. The user-specific information is protected by the corresponding
 * controller's lock. A given user structure is always tied to some controller
 * per the i2c_nexus_t pointer.
 */
typedef struct i2c_user {
	/*
	 * This links the minor open instance in the global im_users. It is only
	 * manipulated while the minors im_muex is held.
	 */
	avl_node_t iu_avl;
	/*
	 * These values are set at initial creation time and contain information
	 * about what device this is actually bound to.
	 */
	id_t iu_minor;
	i2c_nexus_t *iu_nexus;
	/*
	 * Dynamic data that is protected by the following mutex.
	 */
	kmutex_t iu_mutex;
	i2c_txn_t *iu_txn;
	i2c_user_flags_t iu_flags;
	uintptr_t iu_thread;
} i2c_user_t;

typedef enum {

	/*
	 * Indicates that this client has a claimed and/or shared address that
	 * should be released when it is freed and that the address doesn't
	 * belong to the device directly.
	 */
	I2C_CLIENT_F_CLAIM_ADDR		= 1 << 0,
	I2C_CLIENT_F_SHARED_ADDR	= 1 << 1,
	/*
	 * Indicates that the current I/O operation created the transaction for
	 * us.
	 */
	I2C_CLIENT_F_ALLOC_TXN		= 1 << 2
} i2c_client_flags_t;

/*
 * Structure used for kernel device driver consumers.
 */
typedef struct i2c_client {
	list_node_t icli_dev_link;
	dev_info_t *icli_dip;
	i2c_addr_t icli_addr;
	i2c_dev_t *icli_dev;
	i2c_ctrl_t *icli_ctrl;
	i2c_port_t *icli_io_port;
	/*
	 * The icli_mutex is used to protect the fields below.
	 */
	kmutex_t icli_mutex;
	i2c_client_flags_t icli_flags;
	list_t icli_regs;
	i2c_txn_t *icli_txn;
	uintptr_t icli_curthread;
	union {
		smbus_req_t req_smbus;
		i2c_req_t req_i2c;
	} icli_reqs;
} i2c_client_t;

struct i2c_reg_hdl {
	list_node_t reg_link;
	i2c_client_t *reg_client;
	i2c_reg_acc_attr_t reg_attr;
	uint32_t reg_max_nread;
	uint32_t reg_max_nwrite;
};

/*
 * Access to our global data and minor mapping.
 */
extern i2cnex_minors_t i2cnex_minors;

/*
 * Shared bus_ops.
 */
extern struct bus_ops i2c_nex_bus_ops;

/*
 * Misc. internal functions.
 */
extern i2c_root_t *i2c_dip_to_root(dev_info_t *);
extern i2c_root_t *i2c_root_init(dev_info_t *);
extern void i2c_root_fini(i2c_root_t *);

extern i2c_nexus_t *i2cnex_nex_alloc(i2c_nexus_type_t, dev_info_t *,
    i2c_nexus_t *, const char *, const char *, i2c_ctrl_t *);
extern void i2cnex_nex_free(i2c_nexus_t *);
extern i2c_nexus_t *i2c_nex_find_by_minor(minor_t);

typedef struct {
	bool inbc_matched;
	ddi_bus_config_op_t inbc_op;
	const void *inbc_arg;
	int inbc_ret;
	char *inbc_dup;
	size_t inbc_duplen;
	const char *inbc_name;
	const char *inbc_addr;
} i2c_nex_bus_config_t;

extern int i2c_nex_bus_ctl(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
    void *);
extern bool i2c_nex_bus_config_init(i2c_nex_bus_config_t *, ddi_bus_config_op_t,
    const void *);
extern void i2c_nex_bus_config_fini(i2c_nex_bus_config_t *);
extern void i2c_nex_bus_config_one(i2c_nexus_t *, i2c_nex_bus_config_t *);
extern void i2c_nex_bus_unconfig_one(i2c_nexus_t *, i2c_nex_bus_config_t *);
extern void i2c_nex_dev_cleanup(i2c_nexus_t *);

/*
 * User Character Device Operations
 */
extern int i2c_nex_open(dev_t *, int, int, cred_t *);
extern int i2c_nex_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
extern int i2c_nex_close(dev_t, int, int, cred_t *);

/*
 * Error signaling back to clients.
 */
extern bool i2c_error(i2c_error_t *, i2c_errno_t, i2c_ctrl_error_t);
extern void i2c_success(i2c_error_t *);

/*
 * Locking operations.
 */
extern i2c_txn_t *i2c_txn_alloc(i2c_ctrl_t *, i2c_txn_tag_t, const void *);
extern i2c_errno_t i2c_txn_ctrl_lock(i2c_txn_t *, bool);
extern bool i2c_txn_held(i2c_txn_t *);
extern void i2c_txn_nexus_op_begin(i2c_txn_t *);
extern void i2c_txn_nexus_op_end(i2c_txn_t *);
extern void i2c_txn_ctrl_unlock(i2c_txn_t *);
extern void i2c_txn_free(i2c_txn_t *);

/*
 * I/O operations. These require the controller lock.
 */
extern bool i2c_ctrl_io_smbus(i2c_txn_t *, i2c_ctrl_t *, i2c_port_t *,
    smbus_req_t *);
extern bool i2c_ctrl_io_i2c(i2c_txn_t *, i2c_ctrl_t *, i2c_port_t *,
    i2c_req_t *);

/*
 * Mux related functions.
 */
extern bool i2c_mux_update(i2c_txn_t *, i2c_ctrl_t *, i2c_port_t *,
    i2c_error_t *);
extern void i2c_mux_remove_port(i2c_txn_t *, i2c_ctrl_t *, i2c_port_t *);

/*
 * Address allocations.
 */
extern bool i2c_addr_alloc(i2c_port_t *, const i2c_addr_t *,
    i2c_error_t *);
extern void i2c_addr_free(i2c_port_t *, const i2c_addr_t *);
extern bool i2c_addr_alloc_shared(i2c_port_t *, const i2c_addr_t *,
    major_t, i2c_error_t *);
extern void i2c_addr_free_shared(i2c_port_t *, const i2c_addr_t *,
    major_t);
extern void i2c_addr_info_7b(const i2c_port_t *, ui2c_port_info_t *);

/*
 * Device related functions.
 */
extern i2c_dev_t *i2c_device_find_by_addr(i2c_txn_t *, i2c_port_t *,
    const i2c_addr_t *);
extern i2c_dev_t *i2c_device_init(i2c_txn_t *, i2c_port_t *, const i2c_addr_t *,
    const char *, char *const *, uint_t, i2c_error_t *);
extern bool i2c_device_config(i2c_port_t *, i2c_dev_t *);
extern bool i2c_device_unconfig(i2c_port_t *, i2c_dev_t *);
extern void i2c_device_fini(i2c_txn_t *, i2c_port_t *, i2c_dev_t *);

/*
 * Misc. client related functions that are shared.
 */
extern bool i2c_dip_is_dev(dev_info_t *);
extern i2c_nexus_t *i2c_dev_to_nexus(dev_info_t *);

/*
 * Validation functions shared across user / client requests.
 */
extern bool i2c_addr_validate(const i2c_addr_t *, i2c_error_t *);

/*
 * Iterate over all parent ports that are above this entry. Note, there may be
 * none and therefore the function may not be called. The callback will not be
 * called for the starting port.
 */
typedef bool (*i2c_port_f)(i2c_port_t *, void *);
extern void i2c_port_parent_iter(i2c_port_t *, i2c_port_f, void *);
extern void i2c_port_iter(i2c_port_t *, i2c_port_f, void *);

/*
 * Property Interfaces.
 */
extern uint16_t i2c_prop_nstd();
extern const char *i2c_prop_name(i2c_prop_t);
extern bool i2c_prop_info(i2c_ctrl_t *, ui2c_prop_info_t *);
extern bool i2c_prop_get(i2c_ctrl_t *, i2c_prop_t, void *, uint32_t *,
    i2c_error_t *);
extern bool i2c_prop_set(i2c_txn_t *, i2c_ctrl_t *, i2c_prop_t, const void *,
    uint32_t, i2c_error_t *);

#ifdef __cplusplus
}
#endif

#endif /* _I2CNEX_H */
