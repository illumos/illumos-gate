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

#ifndef	_SYS_MDI_IMPLDEFS_H
#define	_SYS_MDI_IMPLDEFS_H


#include <sys/note.h>
#include <sys/types.h>
#include <sys/sunmdi.h>
#include <sys/modhash.h>
#include <sys/callb.h>
#include <sys/devctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Multipath Driver Interfaces
 *
 * The multipathing framework is provided in two modules.  The 'mpxio' misc.
 * module provides the core multipath framework and the 'scsi_vhci' nexus
 * driver provides the SCSI-III command set driver functionality for
 * managing Fibre-Channel storage devices.
 *
 * As in any multipathing solution there are three major problems to solve:
 *
 * 1) Identification and enumeration of multipath client devices.
 * 2) Optimal path selection when routing I/O requests.
 * 3) Observability interfaces to snapshot the multipath configuration,
 *    and infrastructure to provide performance and error statistics.
 *
 * The mpxio framework consists of several major components:
 *
 * 1) The MDI is the Multiplexed Device Interface; this is the core glue which
 *    holds the following components together.
 * 2) vHCI (Virtual Host Controller Interconnect) drivers provide multipathing
 *    services for a given bus technology (example: 'scsi_vhci' provides
 *    multipathing support for SCSI-III fibre-channel devices).
 * 3) pHCI (Physical Host Controller Interconnect) drivers provide transport
 *    services for a given host controller (example: 'fcp' provides transport
 *    for fibre-channel devices).
 * 4) Client Devices are standard Solaris target (or leaf) drivers
 *    (example: 'ssd' is the standard disk driver for fibre-channel arrays).
 * 5) Multipath information nodes ('pathinfo' nodes) connect client device
 *    nodes and pHCI device nodes in the device tree.
 *
 * With the scsi_vhci, a QLC card, and mpxio enabled, the device tree might
 * look like this:
 *
 *              /\
 *             /  ............
 *     <vHCI>:/               \
 *      +-----------+   +-----------+
 *      | scsi_vhci |   |  pci@1f,0 |
 *      +-----------+   +-----------+
 *            /   \               \
 * <Client>: /     \ :<Client>     \ :parent(pHCI)
 *  +----------+ +-----------+    +-------------+
 *  | ssd 1    | | ssd 2     |    | qlc@0,0     |
 *  +----------+ +-----------+    +-------------+
 *   |            |                /        \
 *   |            |       <pHCI>: /          \ :<pHCI>
 *   |            |      +-------------+   +-------------+
 *   |            |      | pHCI 1 (fp) |   | pHCI 2 (fp) |
 *   |            |      +-------------+   +-------------+
 *   |            |          /        |      /          |
 *   |            |    +------+       |    +------+     |
 *   |            |    | ssd 3|       |    | ssd  |     |
 *   |            |    |!mpxio|       |    | (OBP)|     |
 *   |            |    +------+       |    +------+     |
 *   |            |                   |                 |
 *   |            |       <pathinfo>: |                 |
 *   |            |               +-------+         +--------+
 *   |            +-------------->| path  |-------->| path   |
 *   |                            | info  |         | info   |
 *   |                            | node 1|         | node 3 |
 *   |                            +-------+         +--------+
 *   |                                |               |
 *   |                                |            +~~~~~~~~+
 *   |                            +-------+        :+--------+
 *   +--------------------------->| path  |-------->| path   |
 *                                | info  |        :| info   |
 *                                | node 2|        +| node 4 |
 *                                +-------+         +--------+
 *
 * The multipath information nodes (mdi_pathinfo nodes) establish the
 * relationship between the pseudo client driver instance nodes (children
 * of the vHCI) and the physical host controller interconnect (pHCI
 * drivers) forming a matrix structure.
 *
 * The mpxio module implements locking at multiple granularity levels to
 * support the needs of various consumers.  The multipath matrix can be
 * column locked, or row locked depending on the consumer. The intention
 * is to balance simplicity and performance.
 *
 * Locking:
 *
 * The devinfo locking still applies:
 *
 *   1) An ndi_devi_enter of a parent protects linkage/state of children.
 *   2) state >= DS_INITIALIZED adds devi_ref of parent
 *   3) devi_ref at state >= DS_ATTACHED prevents detach(9E).
 *
 * The ordering of 1) is (vHCI, pHCI). For a DEBUG kernel this ordering
 * is asserted by the ndi_devi_enter() implementation.  There is also an
 * ndi_devi_enter(Client), which is atypical since the client is a leaf.
 * This is done to synchronize pathinfo nodes during devinfo snapshot (see
 * di_register_pip) by pretending that the pathinfo nodes are children
 * of the client.
 *
 * In addition to devinfo locking the current implementation utilizes
 * the following locks:
 *
 *   mdi_mutex: protects the global list of vHCIs.
 *
 *   vh_phci_mutex: per-vHCI (mutex) lock: protects list of pHCIs registered
 *   with vHCI.
 *
 *   vh_client_mutex: per-vHCI (mutex) lock: protects list/hash of Clients
 *   associated with vHCI.
 *
 *   ph_mutex: per-pHCI (mutex) lock: protects the column (pHCI-mdi_pathinfo
 *   node list) and per-pHCI structure fields.  mdi_pathinfo node creation,
 *   deletion and child mdi_pathinfo node state changes are serialized on per
 *   pHCI basis (Protection against DR).
 *
 *   ct_mutex: per-client (mutex) lock: protects the row (client-mdi_pathinfo
 *   node list) and per-client structure fields.  The client-mdi_pathinfo node
 *   list is typically walked to select an optimal path when routing I/O
 *   requests.
 *
 *   pi_mutex: per-mdi_pathinfo (mutex) lock: protects the mdi_pathinfo node
 *   structure fields.
 *
 * Note that per-Client structure and per-pHCI fields are freely readable when
 * corresponding mdi_pathinfo locks are held, since holding an mdi_pathinfo
 * node guarantees that its corresponding client and pHCI devices will not be
 * freed.
 */

/*
 * MDI Client global unique identifier property name string definition
 */
extern const char			*mdi_client_guid_prop;
#define	MDI_CLIENT_GUID_PROP		(char *)mdi_client_guid_prop

/*
 * MDI Client load balancing policy definitions
 *
 * Load balancing policies are determined on a per-vHCI basis and are
 * configurable via the vHCI's driver.conf file.
 */
typedef enum {
	LOAD_BALANCE_NONE,		/* Alternate pathing		*/
	LOAD_BALANCE_RR,		/* Round Robin			*/
	LOAD_BALANCE_LBA		/* Logical Block Addressing	*/
} client_lb_t;

typedef struct {
	int region_size;
}client_lb_args_t;

/*
 * MDI client load balancing property name/value string definitions
 */
extern const char			*mdi_load_balance;
extern const char			*mdi_load_balance_none;
extern const char			*mdi_load_balance_ap;
extern const char			*mdi_load_balance_rr;
extern const char			*mdi_load_balance_lba;

#define	LOAD_BALANCE_PROP		(char *)mdi_load_balance
#define	LOAD_BALANCE_PROP_NONE		(char *)mdi_load_balance_none
#define	LOAD_BALANCE_PROP_AP		(char *)mdi_load_balance_ap
#define	LOAD_BALANCE_PROP_RR		(char *)mdi_load_balance_rr
#define	LOAD_BALANCE_PROP_LBA		(char *)mdi_load_balance_lba

/* default for region size */
#define	LOAD_BALANCE_DEFAULT_REGION_SIZE	18

/*
 * vHCI drivers:
 *
 * vHCI drivers are pseudo nexus drivers which implement multipath services
 * for a specific command set or bus architecture ('class').  There is a
 * single instance of the vHCI driver for each command set which supports
 * multipath devices.
 *
 * Each vHCI driver registers the following callbacks from attach(9e).
 */
#define	MDI_VHCI_OPS_REV_1		1
#define	MDI_VHCI_OPS_REV		MDI_VHCI_OPS_REV_1

typedef struct mdi_vhci_ops {
	/* revision management */
	int	vo_revision;

	/* mdi_pathinfo node init callback */
	int	(*vo_pi_init)(dev_info_t *vdip, mdi_pathinfo_t *pip, int flags);

	/* mdi_pathinfo node uninit callback */
	int	(*vo_pi_uninit)(dev_info_t *vdip, mdi_pathinfo_t *pip,
		    int flags);

	/* mdi_pathinfo node state change callback */
	int	(*vo_pi_state_change)(dev_info_t *vdip, mdi_pathinfo_t *pip,
		    mdi_pathinfo_state_t state, uint32_t, int flags);

	/* Client path failover callback */
	int	(*vo_failover)(dev_info_t *vdip, dev_info_t *cdip, int flags);

	/* Client attached callback */
	void	(*vo_client_attached)(dev_info_t *cdip);

	/* Ask vHCI if 'cinfo' device is support as a client */
	int	(*vo_is_dev_supported)(dev_info_t *vdip, dev_info_t *pdip,
		    void *cinfo);
} mdi_vhci_ops_t;

/*
 * An mdi_vhci structure is created and bound to the devinfo node of every
 * registered vHCI class driver; this happens when a vHCI registers itself from
 * attach(9e).  This structure is unbound and freed when the vHCI unregisters
 * at detach(9e) time;
 *
 * Each vHCI driver is associated with a vHCI class name; this is the handle
 * used to register and unregister pHCI drivers for a given transport.
 *
 * Locking: Different parts of this structure are guarded by different
 * locks: global threading of multiple vHCIs and initialization is protected
 * by mdi_mutex, the list of pHCIs associated with a vHCI is protected by
 * vh_phci_mutex, and Clients are protected by vh_client_mutex.
 *
 * XXX Depending on the context, some of the fields can be freely read without
 * holding any locks (ex. holding vh_client_mutex lock also guarantees that
 * the vHCI (parent) cannot be unexpectedly freed).
 */
typedef struct mdi_vhci {
	/* protected by mdi_mutex... */
	struct mdi_vhci		*vh_next;	/* next vHCI link	*/
	struct mdi_vhci		*vh_prev;	/* prev vHCI link	*/
	char			*vh_class;	/* vHCI class name	*/
	dev_info_t		*vh_dip;	/* vHCI devi handle	*/
	int			vh_refcnt;	/* vHCI reference count	*/
	struct mdi_vhci_config	*vh_config;	/* vHCI config		*/
	client_lb_t		vh_lb;		/* vHCI load-balancing	*/
	struct mdi_vhci_ops	*vh_ops;	/* vHCI callback vectors */

	/* protected by MDI_VHCI_PHCI_LOCK vh_phci_mutex... */
	kmutex_t		vh_phci_mutex;	/* pHCI mutex		*/
	int			vh_phci_count;	/* pHCI device count	*/
	struct mdi_phci		*vh_phci_head;	/* pHCI list head	*/
	struct mdi_phci		*vh_phci_tail;	/* pHCI list tail	*/

	/* protected by MDI_VHCI_CLIENT_LOCK vh_client_mutex... */
	kmutex_t		vh_client_mutex; /* Client mutex	*/
	int			vh_client_count; /* Client count	*/
	struct client_hash	*vh_client_table; /* Client hash	*/
} mdi_vhci_t;

/*
 * per-vHCI lock macros
 */
#define	MDI_VHCI_PHCI_LOCK(vh)		mutex_enter(&(vh)->vh_phci_mutex)
#define	MDI_VHCI_PHCI_TRYLOCK(vh)	mutex_tryenter(&(vh)->vh_phci_mutex)
#define	MDI_VHCI_PHCI_UNLOCK(vh)	mutex_exit(&(vh)->vh_phci_mutex)
#ifdef	DEBUG
#define	MDI_VHCI_PCHI_LOCKED(vh)	MUTEX_HELD(&(vh)->vh_phci_mutex)
#endif	/* DEBUG */
#define	MDI_VHCI_CLIENT_LOCK(vh)	mutex_enter(&(vh)->vh_client_mutex)
#define	MDI_VHCI_CLIENT_TRYLOCK(vh)	mutex_tryenter(&(vh)->vh_client_mutex)
#define	MDI_VHCI_CLIENT_UNLOCK(vh)	mutex_exit(&(vh)->vh_client_mutex)
#ifdef	DEBUG
#define	MDI_VHCI_CLIENT_LOCKED(vh)	MUTEX_HELD(&(vh)->vh_client_mutex)
#endif	/* DEBUG */


/*
 * GUID Hash definitions
 *
 * Since all the mpxio managed devices for a given class are enumerated under
 * the single vHCI instance for that class, sequentially walking through the
 * client device link to find a client would be prohibitively slow.
 */

#define	CLIENT_HASH_TABLE_SIZE	(32)	/* GUID hash */

/*
 * Client hash table structure
 */
struct client_hash {
	struct mdi_client	*ct_hash_head;	/* Client hash head	*/
	int			ct_hash_count;	/* Client hash count	*/
};


/*
 * pHCI Drivers:
 *
 * Physical HBA drivers provide transport services for mpxio-managed devices.
 * As each pHCI instance is attached, it must register itself with the mpxio
 * framework using mdi_phci_register().  When the pHCI is detached it must
 * similarly call mdi_phci_unregister().
 *
 * The framework maintains a list of registered pHCI device instances for each
 * vHCI.  This list involves (vh_phci_count, vh_phci_head, vh_phci_tail) and
 * (ph_next, ph_prev, ph_vhci) and is protected by vh_phci_mutex.
 *
 * Locking order:
 *
 * _NOTE(LOCK_ORDER(mdi_mutex, mdi_phci::ph_mutex))		XXX
 * _NOTE(LOCK_ORDER(mdi_phci::ph_mutex devinfo_tree_lock))		XXX
 */
typedef struct mdi_phci {
	/* protected by MDI_VHCI_PHCI_LOCK vh_phci_mutex... */
	struct mdi_phci		*ph_next;	/* next pHCI link	*/
	struct mdi_phci		*ph_prev;	/* prev pHCI link	*/
	dev_info_t		*ph_dip;	/* pHCI devi handle	*/
	struct mdi_vhci		*ph_vhci;	/* pHCI back ref. to vHCI */

	/* protected by MDI_PHCI_LOCK ph_mutex... */
	kmutex_t		ph_mutex;	/* per-pHCI mutex	*/
	int			ph_path_count;	/* pi count		*/
	mdi_pathinfo_t		*ph_path_head;	/* pi list head		*/
	mdi_pathinfo_t		*ph_path_tail;	/* pi list tail		*/
	int			ph_flags;	/* pHCI operation flags	*/
	int			ph_unstable;	/* Paths in transient state */
	kcondvar_t		ph_unstable_cv;	/* Paths in transient state */

	/* protected by mdi_phci_[gs]et_vhci_private caller... */
	void			*ph_vprivate;	/* vHCI driver private	*/
} mdi_phci_t;

/*
 * A pHCI device is 'unstable' while one or more paths are in a transitional
 * state.  Hotplugging is prevented during this state.
 */
#define	MDI_PHCI_UNSTABLE(ph)		(ph)->ph_unstable++;
#define	MDI_PHCI_STABLE(ph) { \
	(ph)->ph_unstable--; \
	if ((ph)->ph_unstable == 0) { \
		cv_broadcast(&(ph)->ph_unstable_cv); \
	} \
}

/*
 * per-pHCI lock macros
 */
#define	MDI_PHCI_LOCK(ph)		mutex_enter(&(ph)->ph_mutex)
#define	MDI_PHCI_TRYLOCK(ph)		mutex_tryenter(&(ph)->ph_mutex)
#define	MDI_PHCI_UNLOCK(ph)		mutex_exit(&(ph)->ph_mutex)
#ifdef	DEBUG
#define	MDI_PHCI_LOCKED(vh)		MUTEX_HELD(&(ph)->ph_mutex)
#endif	/* DEBUG */

/*
 * pHCI state definitions and macros to track the pHCI driver instance state
 */
#define	MDI_PHCI_FLAGS_OFFLINE		0x1	/* pHCI is offline */
#define	MDI_PHCI_FLAGS_SUSPEND		0x2	/* pHCI is suspended */
#define	MDI_PHCI_FLAGS_POWER_DOWN	0x4	/* pHCI is power down */
#define	MDI_PHCI_FLAGS_DETACH		0x8	/* pHCI is detached */
#define	MDI_PHCI_FLAGS_USER_DISABLE	0x10	/* pHCI is disabled,user */
#define	MDI_PHCI_FLAGS_D_DISABLE	0x20	/* pHCI is disabled,driver */
#define	MDI_PHCI_FLAGS_D_DISABLE_TRANS	0x40	/* pHCI is disabled,transient */
#define	MDI_PHCI_FLAGS_POWER_TRANSITION	0x80	/* pHCI is power transition */

#define	MDI_PHCI_DISABLE_MASK						\
	    (MDI_PHCI_FLAGS_USER_DISABLE | MDI_PHCI_FLAGS_D_DISABLE |	\
	    MDI_PHCI_FLAGS_D_DISABLE_TRANS)

#define	MDI_PHCI_IS_READY(ph)						\
	    (((ph)->ph_flags & MDI_PHCI_DISABLE_MASK) == 0)

#define	MDI_PHCI_SET_OFFLINE(ph)					{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags |= MDI_PHCI_FLAGS_OFFLINE;			}
#define	MDI_PHCI_SET_ONLINE(ph)						{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags &= ~MDI_PHCI_FLAGS_OFFLINE;			}
#define	MDI_PHCI_IS_OFFLINE(ph)						\
	    ((ph)->ph_flags & MDI_PHCI_FLAGS_OFFLINE)

#define	MDI_PHCI_SET_SUSPEND(ph)					{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags |= MDI_PHCI_FLAGS_SUSPEND;			}
#define	MDI_PHCI_SET_RESUME(ph)						{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags &= ~MDI_PHCI_FLAGS_SUSPEND;			}
#define	MDI_PHCI_IS_SUSPENDED(ph)					\
	    ((ph)->ph_flags & MDI_PHCI_FLAGS_SUSPEND)

#define	MDI_PHCI_SET_DETACH(ph)						{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags |= MDI_PHCI_FLAGS_DETACH;			}
#define	MDI_PHCI_SET_ATTACH(ph)						{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags &= ~MDI_PHCI_FLAGS_DETACH;			}

#define	MDI_PHCI_SET_POWER_DOWN(ph)					{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags |= MDI_PHCI_FLAGS_POWER_DOWN;		}
#define	MDI_PHCI_SET_POWER_UP(ph)					{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags &= ~MDI_PHCI_FLAGS_POWER_DOWN;		}
#define	MDI_PHCI_IS_POWERED_DOWN(ph)					\
	    ((ph)->ph_flags & MDI_PHCI_FLAGS_POWER_DOWN)

#define	MDI_PHCI_SET_USER_ENABLE(ph)					{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags &= ~MDI_PHCI_FLAGS_USER_DISABLE;		}
#define	MDI_PHCI_SET_USER_DISABLE(ph)					{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags |= MDI_PHCI_FLAGS_USER_DISABLE;		}
#define	MDI_PHCI_IS_USER_DISABLED(ph)					\
	    ((ph)->ph_flags & MDI_PHCI_FLAGS_USER_DISABLE)

#define	MDI_PHCI_SET_DRV_ENABLE(ph)					{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags &= ~MDI_PHCI_FLAGS_D_DISABLE;		}
#define	MDI_PHCI_SET_DRV_DISABLE(ph)					{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags |= MDI_PHCI_FLAGS_D_DISABLE;			}
#define	MDI_PHCI_IS_DRV_DISABLED(ph)					\
	    ((ph)->ph_flags & MDI_PHCI_FLAGS_D_DISABLE)

#define	MDI_PHCI_SET_DRV_ENABLE_TRANSIENT(ph)				{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags &= ~MDI_PHCI_FLAGS_D_DISABLE_TRANS;		}
#define	MDI_PHCI_SET_DRV_DISABLE_TRANSIENT(ph)				{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags |= MDI_PHCI_FLAGS_D_DISABLE_TRANS;		}
#define	MDI_PHCI_IS_DRV_DISABLED_TRANSIENT(ph)				\
	    ((ph)->ph_flags & MDI_PHCI_FLAGS_D_DISABLE_TRANS)

#define	MDI_PHCI_SET_POWER_TRANSITION(ph)				{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags |= MDI_PHCI_FLAGS_POWER_TRANSITION;		}
#define	MDI_PHCI_CLEAR_POWER_TRANSITION(ph)				{\
	    ASSERT(MDI_PHCI_LOCKED(ph));				\
	    (ph)->ph_flags &= ~MDI_PHCI_FLAGS_POWER_TRANSITION;		}
#define	MDI_PHCI_IS_POWER_TRANSITION(ph)				\
	    ((ph)->ph_flags & MDI_PHCI_FLAGS_POWER_TRANSITION)

/*
 * mpxio Managed Clients:
 *
 * This framework creates a struct mdi_client for every client device created
 * by the framework as a result of self-enumeration of target devices by the
 * registered pHCI devices.  This structure is bound to client device dev_info
 * node at the time of client device allocation (ndi_devi_alloc(9e)). This
 * structure is unbound from the dev_info node when mpxio framework removes a
 * client device node from the system.
 *
 * This structure is created when a first path is enumerated and removed when
 * last path is de-enumerated from the system.
 *
 * Multipath client devices are instantiated as children of corresponding vHCI
 * driver instance. Each client device is uniquely identified by a GUID
 * provided by target device itself.  The parent vHCI device also maintains a
 * hashed list of client devices, protected by vh_client_mutex.
 *
 * Typically pHCI devices self-enumerate their child devices using taskq,
 * resulting in multiple paths to the same client device to be enumerated by
 * competing threads.
 *
 * Currently this framework supports two kinds of load-balancing policy
 * configurable through the vHCI driver configuration files.
 *
 * NONE		- Legacy AP mode
 * Round Robin	- Balance the pHCI load in a Round Robin fashion.
 *
 * This framework identifies the client device in three distinct states:
 *
 * OPTIMAL	- Client device has at least one redundant path.
 * DEGRADED	- No redundant paths (critical).  Failure in the current active
 *		  path would result in data access failures.
 * FAILED	- No paths are available to access this device.
 *
 * Locking order:
 *
 * _NOTE(LOCK_ORDER(mdi_mutex, mdi_client::ct_mutex))			XXX
 * _NOTE(LOCK_ORDER(mdi_client::ct_mutex devinfo_tree_lock))		XXX
 */
typedef struct mdi_client {
	/* protected by MDI_VHCI_CLIENT_LOCK vh_client_mutex... */
	struct mdi_client	*ct_hnext;	/* next client		*/
	struct mdi_client	*ct_hprev;	/* prev client		*/
	dev_info_t		*ct_dip;	/* client devi handle	*/
	struct mdi_vhci		*ct_vhci;	/* vHCI back ref	*/
	char			*ct_drvname;	/* client driver name	*/
	char			*ct_guid;	/* client guid		*/
	client_lb_t		ct_lb;		/* load balancing scheme */
	client_lb_args_t	*ct_lb_args;	/* load balancing args */


	/* protected by MDI_CLIENT_LOCK ct_mutex... */
	kmutex_t		ct_mutex;	/* per-client mutex	*/
	int			ct_path_count;	/* multi path count	*/
	mdi_pathinfo_t		*ct_path_head;	/* multi path list head	*/
	mdi_pathinfo_t		*ct_path_tail;	/* multi path list tail	*/
	mdi_pathinfo_t		*ct_path_last;	/* last path used for i/o */
	int			ct_state;	/* state information	*/
	int			ct_flags;	/* Driver op. flags	*/
	int			ct_failover_flags;	/* Failover args */
	int			ct_failover_status;	/* last fo status */
	kcondvar_t		ct_failover_cv;	/* Failover status cv	*/
	int			ct_unstable;	/* Paths in transient state */
	kcondvar_t		ct_unstable_cv;	/* Paths in transient state */

	int			ct_power_cnt;	/* Hold count on parent power */
	kcondvar_t		ct_powerchange_cv;
					/* Paths in power transient state */
	short			ct_powercnt_config;
					/* held in pre/post config */
	short			ct_powercnt_unconfig;
					/* held in pre/post unconfig */
	int			ct_powercnt_reset;
					/* ct_power_cnt was reset */

	void			*ct_cprivate;	/* client driver private */
	void			*ct_vprivate;	/* vHCI driver private	*/
} mdi_client_t;

/*
 * per-Client device locking definitions
 */
#define	MDI_CLIENT_LOCK(ct)		mutex_enter(&(ct)->ct_mutex)
#define	MDI_CLIENT_TRYLOCK(ct)		mutex_tryenter(&(ct)->ct_mutex)
#define	MDI_CLIENT_UNLOCK(ct)		mutex_exit(&(ct)->ct_mutex)
#ifdef	DEBUG
#define	MDI_CLIENT_LOCKED(ct)		MUTEX_HELD(&(ct)->ct_mutex)
#endif	/* DEBUG */

/*
 * A Client device is in unstable while one or more paths are in transitional
 * state.  We do not allow failover to take place while paths are in transient
 * state. Similarly we do not allow state transition while client device
 * failover is in progress.
 */
#define	MDI_CLIENT_UNSTABLE(ct)		(ct)->ct_unstable++;
#define	MDI_CLIENT_STABLE(ct) { \
	(ct)->ct_unstable--; \
	if ((ct)->ct_unstable == 0) { \
		cv_broadcast(&(ct)->ct_unstable_cv); \
	} \
}

/*
 * Client driver instance state definitions:
 */
#define	MDI_CLIENT_FLAGS_OFFLINE		0x00000001
#define	MDI_CLIENT_FLAGS_SUSPEND		0x00000002
#define	MDI_CLIENT_FLAGS_POWER_DOWN		0x00000004
#define	MDI_CLIENT_FLAGS_DETACH			0x00000008
#define	MDI_CLIENT_FLAGS_FAILOVER		0x00000010
#define	MDI_CLIENT_FLAGS_REPORT_DEV		0x00000020
#define	MDI_CLIENT_FLAGS_PATH_FREE_IN_PROGRESS	0x00000040
#define	MDI_CLIENT_FLAGS_ASYNC_FREE		0x00000080
#define	MDI_CLIENT_FLAGS_DEV_NOT_SUPPORTED	0x00000100
#define	MDI_CLIENT_FLAGS_POWER_TRANSITION	0x00000200

#define	MDI_CLIENT_SET_OFFLINE(ct)					{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags |= MDI_CLIENT_FLAGS_OFFLINE;			}
#define	MDI_CLIENT_SET_ONLINE(ct)					{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags &= ~MDI_CLIENT_FLAGS_OFFLINE;		}
#define	MDI_CLIENT_IS_OFFLINE(ct) \
	    ((ct)->ct_flags & MDI_CLIENT_FLAGS_OFFLINE)

#define	MDI_CLIENT_SET_SUSPEND(ct)					{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags |= MDI_CLIENT_FLAGS_SUSPEND;			}
#define	MDI_CLIENT_SET_RESUME(ct)					{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags &= ~MDI_CLIENT_FLAGS_SUSPEND;		}
#define	MDI_CLIENT_IS_SUSPENDED(ct) \
	    ((ct)->ct_flags & MDI_CLIENT_FLAGS_SUSPEND)

#define	MDI_CLIENT_SET_POWER_DOWN(ct)					{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags |= MDI_CLIENT_FLAGS_POWER_DOWN;		}
#define	MDI_CLIENT_SET_POWER_UP(ct)					{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags &= ~MDI_CLIENT_FLAGS_POWER_DOWN;		}
#define	MDI_CLIENT_IS_POWERED_DOWN(ct) \
	    ((ct)->ct_flags & MDI_CLIENT_FLAGS_POWER_DOWN)

#define	MDI_CLIENT_SET_POWER_TRANSITION(ct)				{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags |= MDI_CLIENT_FLAGS_POWER_TRANSITION;	}
#define	MDI_CLIENT_CLEAR_POWER_TRANSITION(ct)				{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags &= ~MDI_CLIENT_FLAGS_POWER_TRANSITION;	}
#define	MDI_CLIENT_IS_POWER_TRANSITION(ct) \
	    ((ct)->ct_flags & MDI_CLIENT_FLAGS_POWER_TRANSITION)

#define	MDI_CLIENT_SET_DETACH(ct)					{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags |= MDI_CLIENT_FLAGS_DETACH;			}
#define	MDI_CLIENT_SET_ATTACH(ct)					{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags &= ~MDI_CLIENT_FLAGS_DETACH;			}
#define	MDI_CLIENT_IS_DETACHED(ct) \
	    ((ct)->ct_flags & MDI_CLIENT_FLAGS_DETACH)

#define	MDI_CLIENT_SET_FAILOVER_IN_PROGRESS(ct)				{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags |= MDI_CLIENT_FLAGS_FAILOVER;		}
#define	MDI_CLIENT_CLEAR_FAILOVER_IN_PROGRESS(ct)			{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags &= ~MDI_CLIENT_FLAGS_FAILOVER;		}
#define	MDI_CLIENT_IS_FAILOVER_IN_PROGRESS(ct) \
	    ((ct)->ct_flags & MDI_CLIENT_FLAGS_FAILOVER)

#define	MDI_CLIENT_SET_REPORT_DEV_NEEDED(ct)				{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags |= MDI_CLIENT_FLAGS_REPORT_DEV;		}
#define	MDI_CLIENT_CLEAR_REPORT_DEV_NEEDED(ct)				{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags &= ~MDI_CLIENT_FLAGS_REPORT_DEV;		}
#define	MDI_CLIENT_IS_REPORT_DEV_NEEDED(ct) \
	    ((ct)->ct_flags & MDI_CLIENT_FLAGS_REPORT_DEV)

#define	MDI_CLIENT_SET_PATH_FREE_IN_PROGRESS(ct)			{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags |= MDI_CLIENT_FLAGS_PATH_FREE_IN_PROGRESS;	}
#define	MDI_CLIENT_CLEAR_PATH_FREE_IN_PROGRESS(ct)			{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags &= ~MDI_CLIENT_FLAGS_PATH_FREE_IN_PROGRESS;	}
#define	MDI_CLIENT_IS_PATH_FREE_IN_PROGRESS(ct) \
	    ((ct)->ct_flags & MDI_CLIENT_FLAGS_PATH_FREE_IN_PROGRESS)

#define	MDI_CLIENT_SET_DEV_NOT_SUPPORTED(ct)				{\
	    ASSERT(MDI_CLIENT_LOCKED(ct));				\
	    (ct)->ct_flags |= MDI_CLIENT_FLAGS_DEV_NOT_SUPPORTED;	}
#define	MDI_CLIENT_IS_DEV_NOT_SUPPORTED(ct) \
	    ((ct)->ct_flags & MDI_CLIENT_FLAGS_DEV_NOT_SUPPORTED)

/*
 * Client operating states.
 */
#define	MDI_CLIENT_STATE_OPTIMAL	1
#define	MDI_CLIENT_STATE_DEGRADED	2
#define	MDI_CLIENT_STATE_FAILED		3

#define	MDI_CLIENT_STATE(ct) ((ct)->ct_state)
#define	MDI_CLIENT_SET_STATE(ct, state) ((ct)->ct_state = state)

#define	MDI_CLIENT_IS_FAILED(ct) \
	    ((ct)->ct_state == MDI_CLIENT_STATE_FAILED)

/*
 * mdi_pathinfo nodes:
 *
 * From this framework's perspective, a 'path' is a tuple consisting of a
 * client or end device, a host controller which provides device
 * identification and transport services (pHCI), and bus specific unit
 * addressing information.  A path may be decorated with properties which
 * describe the capabilities of the path; such properties are analogous to
 * device node and minor node properties.
 *
 * The framework maintains link list of mdi_pathinfo nodes created by every
 * pHCI driver instance via the pi_phci_link linkage; this is used (for example)
 * to make sure that all relevant pathinfo nodes are freed before the pHCI
 * is unregistered.
 *
 * Locking order:
 *
 * _NOTE(LOCK_ORDER(mdi_phci::ph_mutex mdi_pathinfo::pi_mutex))		XXX
 * _NOTE(LOCK_ORDER(mdi_client::ct_mutex mdi_pathinfo::pi_mutex))	XXX
 * _NOTE(LOCK_ORDER(mdi_phci::ph_mutex mdi_client::ct_mutex))		XXX
 * _NOTE(LOCK_ORDER(devinfo_tree_lock mdi_pathinfo::pi_mutex))		XXX
 *
 * mdi_pathinfo node structure definition
 */
struct mdi_pathinfo {
	/* protected by MDI_PHCI_LOCK ph_mutex... */
	struct mdi_pathinfo	*pi_phci_link;	 /* next path in phci list */
	mdi_phci_t		*pi_phci;	/* pHCI dev_info node	*/

	/* protected by MDI_CLIENT_LOCK ct_mutex... */
	struct mdi_pathinfo	*pi_client_link; /* next path in client list */
	mdi_client_t		*pi_client;	/* client		*/

	/* protected by MDI_VHCI_CLIENT_LOCK vh_client_mutex... */
	char			*pi_addr;	/* path unit address	*/
	int			pi_path_instance; /* path instance */

	/* protected by MDI_PI_LOCK pi_mutex... */
	kmutex_t		pi_mutex;	/* per path mutex	*/
	mdi_pathinfo_state_t	pi_state;	/* path state		*/
	mdi_pathinfo_state_t	pi_old_state;	/* path state		*/
	kcondvar_t		pi_state_cv;	/* path state condvar	*/
	nvlist_t		*pi_prop;	/* Properties		*/
	void			*pi_cprivate;	/* client private info	*/
	void			*pi_pprivate;	/* phci private info	*/
	int			pi_ref_cnt;	/* pi reference count	*/
	kcondvar_t		pi_ref_cv;	/* condition variable	*/
	struct mdi_pi_kstats	*pi_kstats;	/* aggregate kstats */
	int			pi_pm_held;	/* phci's kidsup incremented */
	int			pi_preferred;	/* Preferred path	*/
	void			*pi_vprivate;	/* vhci private info	*/
	uint_t			pi_flags;	/* path flags */
};

/*
 * pathinfo statistics:
 *
 * The mpxio architecture allows for multiple pathinfo nodes for each
 * client-pHCI combination.  For statistics purposes, these statistics are
 * aggregated into a single client-pHCI set of kstats.
 */
struct mdi_pi_kstats {
	int	pi_kstat_ref;		/* # paths aggregated, also a ref cnt */
	kstat_t	*pi_kstat_iostats;	/* mdi:iopath statistic set */
	kstat_t *pi_kstat_errstats;	/* error statistics */
};

/*
 * pathinfo error kstat
 */
struct pi_errs {
	struct kstat_named pi_softerrs;		/* "Soft" Error */
	struct kstat_named pi_harderrs;		/* "Hard" Error */
	struct kstat_named pi_transerrs;	/* Transport Errors */
	struct kstat_named pi_icnt_busy;	/* Interconnect Busy */
	struct kstat_named pi_icnt_errors;	/* Interconnect Errors */
	struct kstat_named pi_phci_rsrc;	/* pHCI No Resources */
	struct kstat_named pi_phci_localerr;	/* pHCI Local Errors */
	struct kstat_named pi_phci_invstate;	/* pHCI Invalid State */
	struct kstat_named pi_failedfrom;	/* Failover: Failed From */
	struct kstat_named pi_failedto;		/* Failover: Failed To */
};

/*
 * increment an error counter
 */
#define	MDI_PI_ERRSTAT(pip, x) { \
	if (MDI_PI((pip))->pi_kstats != NULL) { \
		struct pi_errs *pep; \
		pep = MDI_PI(pip)->pi_kstats->pi_kstat_errstats->ks_data; \
		pep->x.value.ui32++; \
	} \
}

/*
 * error codes which can be passed to MDI_PI_ERRSTAT
 */
#define	MDI_PI_SOFTERR	pi_softerrs
#define	MDI_PI_HARDERR	pi_harderrs
#define	MDI_PI_TRANSERR	pi_transerrs
#define	MDI_PI_ICNTBUSY	pi_icnt_busy
#define	MDI_PI_ICNTERR	pi_icnt_errors
#define	MDI_PI_PHCIRSRC	pi_phci_rsrc
#define	MDI_PI_PHCILOCL	pi_phci_localerr
#define	MDI_PI_PHCIINVS	pi_phci_invstate
#define	MDI_PI_FAILFROM	pi_failedfrom
#define	MDI_PI_FAILTO	pi_failedto

#define	MDI_PI(type)			((struct mdi_pathinfo *)(type))

#define	MDI_PI_LOCK(pip)		mutex_enter(&MDI_PI(pip)->pi_mutex)
#define	MDI_PI_TRYLOCK(pip)		mutex_tryenter(&MDI_PI(pip)->pi_mutex)
#define	MDI_PI_UNLOCK(pip)		mutex_exit(&MDI_PI(pip)->pi_mutex)
#ifdef	DEBUG
#define	MDI_PI_LOCKED(pip)		MUTEX_HELD(&MDI_PI(pip)->pi_mutex)
#endif	/* DEBUG */

#define	MDI_PI_HOLD(pip)		(++MDI_PI(pip)->pi_ref_cnt)
#define	MDI_PI_RELE(pip)		(--MDI_PI(pip)->pi_ref_cnt)

#define	MDI_EXT_STATE_CHANGE		0x10000000


#define	MDI_DISABLE_OP			0x1
#define	MDI_ENABLE_OP			0x2
#define	MDI_BEFORE_STATE_CHANGE		0x4
#define	MDI_AFTER_STATE_CHANGE		0x8
#define	MDI_SYNC_FLAG			0x10

#define	MDI_PI_STATE(pip)						\
	(MDI_PI((pip))->pi_state & MDI_PATHINFO_STATE_MASK)
#define	MDI_PI_OLD_STATE(pip)						\
	(MDI_PI((pip))->pi_old_state & MDI_PATHINFO_STATE_MASK)

#define	MDI_PI_EXT_STATE(pip)						\
	(MDI_PI((pip))->pi_state & MDI_PATHINFO_EXT_STATE_MASK)
#define	MDI_PI_OLD_EXT_STATE(pip)					\
	(MDI_PI((pip))->pi_old_state & MDI_PATHINFO_EXT_STATE_MASK)

#define	MDI_PI_SET_TRANSIENT(pip)					{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_state |= MDI_PATHINFO_STATE_TRANSIENT;		}
#define	MDI_PI_CLEAR_TRANSIENT(pip)					{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_state &= ~MDI_PATHINFO_STATE_TRANSIENT;		}
#define	MDI_PI_IS_TRANSIENT(pip) \
	(MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_TRANSIENT)

#define	MDI_PI_SET_USER_DISABLE(pip)					{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_state |= MDI_PATHINFO_STATE_USER_DISABLE;	}
#define	MDI_PI_SET_DRV_DISABLE(pip)					{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_state |= MDI_PATHINFO_STATE_DRV_DISABLE;	}
#define	MDI_PI_SET_DRV_DISABLE_TRANS(pip)				{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_state |= MDI_PATHINFO_STATE_DRV_DISABLE_TRANSIENT; }

#define	MDI_PI_SET_USER_ENABLE(pip)					{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_state &= ~MDI_PATHINFO_STATE_USER_DISABLE;	}
#define	MDI_PI_SET_DRV_ENABLE(pip)					{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_state &= ~MDI_PATHINFO_STATE_DRV_DISABLE;	}
#define	MDI_PI_SET_DRV_ENABLE_TRANS(pip)				{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_state &= ~MDI_PATHINFO_STATE_DRV_DISABLE_TRANSIENT; }

#define	MDI_PI_IS_USER_DISABLE(pip)					\
	(MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_USER_DISABLE)
#define	MDI_PI_IS_DRV_DISABLE(pip)					\
	(MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_DRV_DISABLE)
#define	MDI_PI_IS_DRV_DISABLE_TRANSIENT(pip)				\
	(MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_DRV_DISABLE_TRANSIENT)

#define	MDI_PI_IS_DISABLE(pip)						\
	(MDI_PI_IS_USER_DISABLE(pip) ||					\
	MDI_PI_IS_DRV_DISABLE(pip) ||					\
	MDI_PI_IS_DRV_DISABLE_TRANSIENT(pip))

#define	MDI_PI_IS_INIT(pip)						\
	((MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_MASK) ==		\
		MDI_PATHINFO_STATE_INIT)

#define	MDI_PI_IS_INITING(pip)						\
	((MDI_PI(pip)->pi_state & ~MDI_PATHINFO_EXT_STATE_MASK) ==	\
		(MDI_PATHINFO_STATE_INIT | MDI_PATHINFO_STATE_TRANSIENT))

#define	MDI_PI_SET_INIT(pip)						{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_state = MDI_PATHINFO_STATE_INIT;		}

#define	MDI_PI_SET_ONLINING(pip)					{\
	uint32_t	ext_state;					\
	ASSERT(MDI_PI_LOCKED(pip));					\
	ext_state = MDI_PI(pip)->pi_state & MDI_PATHINFO_EXT_STATE_MASK; \
	MDI_PI(pip)->pi_old_state = MDI_PI_STATE(pip);			\
	MDI_PI(pip)->pi_state =						\
	(MDI_PATHINFO_STATE_ONLINE | MDI_PATHINFO_STATE_TRANSIENT);	\
	MDI_PI(pip)->pi_state |= ext_state;				}

#define	MDI_PI_IS_ONLINING(pip)						\
	((MDI_PI(pip)->pi_state & ~MDI_PATHINFO_EXT_STATE_MASK) ==	\
	(MDI_PATHINFO_STATE_ONLINE | MDI_PATHINFO_STATE_TRANSIENT))

#define	MDI_PI_SET_ONLINE(pip)						{\
	uint32_t	ext_state;					\
	ASSERT(MDI_PI_LOCKED(pip));					\
	ext_state = MDI_PI(pip)->pi_state & MDI_PATHINFO_EXT_STATE_MASK; \
	MDI_PI(pip)->pi_state = MDI_PATHINFO_STATE_ONLINE;		\
	MDI_PI(pip)->pi_state |= ext_state;				}

#define	MDI_PI_IS_ONLINE(pip)						\
	((MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_MASK) ==		\
	MDI_PATHINFO_STATE_ONLINE)

#define	MDI_PI_SET_OFFLINING(pip)					{\
	uint32_t	ext_state;					\
	ASSERT(MDI_PI_LOCKED(pip));					\
	ext_state = MDI_PI(pip)->pi_state & MDI_PATHINFO_EXT_STATE_MASK; \
	MDI_PI(pip)->pi_old_state = MDI_PI_STATE(pip);			\
	MDI_PI(pip)->pi_state =						\
	(MDI_PATHINFO_STATE_OFFLINE | MDI_PATHINFO_STATE_TRANSIENT);	\
	MDI_PI(pip)->pi_state |= ext_state;				}

#define	MDI_PI_IS_OFFLINING(pip)					\
	((MDI_PI(pip)->pi_state & ~MDI_PATHINFO_EXT_STATE_MASK) ==	\
	(MDI_PATHINFO_STATE_OFFLINE | MDI_PATHINFO_STATE_TRANSIENT))

#define	MDI_PI_SET_OFFLINE(pip)						{\
	uint32_t	ext_state;					\
	ASSERT(MDI_PI_LOCKED(pip));					\
	ext_state = MDI_PI(pip)->pi_state & MDI_PATHINFO_EXT_STATE_MASK; \
	MDI_PI(pip)->pi_state = MDI_PATHINFO_STATE_OFFLINE;		\
	MDI_PI(pip)->pi_state |= ext_state;				}

#define	MDI_PI_IS_OFFLINE(pip)						\
	((MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_MASK) ==		\
	MDI_PATHINFO_STATE_OFFLINE)

#define	MDI_PI_SET_STANDBYING(pip)					{\
	uint32_t	ext_state;					\
	ASSERT(MDI_PI_LOCKED(pip));					\
	ext_state = MDI_PI(pip)->pi_state & MDI_PATHINFO_EXT_STATE_MASK; \
	MDI_PI(pip)->pi_old_state = MDI_PI_STATE(pip);			\
	MDI_PI(pip)->pi_state =						\
	(MDI_PATHINFO_STATE_STANDBY | MDI_PATHINFO_STATE_TRANSIENT);	\
	MDI_PI(pip)->pi_state |= ext_state;				}

#define	MDI_PI_SET_STANDBY(pip)						{\
	uint32_t	ext_state;					\
	ASSERT(MDI_PI_LOCKED(pip));					\
	ext_state = MDI_PI(pip)->pi_state & MDI_PATHINFO_EXT_STATE_MASK; \
	MDI_PI(pip)->pi_state = MDI_PATHINFO_STATE_STANDBY;		\
	MDI_PI(pip)->pi_state |= ext_state;				}

#define	MDI_PI_IS_STANDBY(pip)						\
	((MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_MASK) ==		\
	MDI_PATHINFO_STATE_STANDBY)

#define	MDI_PI_SET_FAULTING(pip)					{\
	uint32_t	ext_state;					\
	ASSERT(MDI_PI_LOCKED(pip));					\
	ext_state = MDI_PI(pip)->pi_state & MDI_PATHINFO_EXT_STATE_MASK; \
	MDI_PI(pip)->pi_old_state = MDI_PI_STATE(pip);			\
	MDI_PI(pip)->pi_state =						\
	    (MDI_PATHINFO_STATE_FAULT | MDI_PATHINFO_STATE_TRANSIENT);	\
	MDI_PI(pip)->pi_state |= ext_state;				}

#define	MDI_PI_SET_FAULT(pip)						{\
	uint32_t	ext_state;					\
	ASSERT(MDI_PI_LOCKED(pip));					\
	ext_state = MDI_PI(pip)->pi_state & MDI_PATHINFO_EXT_STATE_MASK; \
	MDI_PI(pip)->pi_state = MDI_PATHINFO_STATE_FAULT;		\
	MDI_PI(pip)->pi_state |= ext_state;				}

#define	MDI_PI_IS_FAULT(pip)						\
	((MDI_PI(pip)->pi_state & MDI_PATHINFO_STATE_MASK) ==		\
	MDI_PATHINFO_STATE_FAULT)

#define	MDI_PI_IS_SUSPENDED(pip)					\
	((MDI_PI(pip))->pi_phci->ph_flags & MDI_PHCI_FLAGS_SUSPEND)

#define	MDI_PI_FLAGS_SET_HIDDEN(pip)					{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_flags |= MDI_PATHINFO_FLAGS_HIDDEN;		}
#define	MDI_PI_FLAGS_CLR_HIDDEN(pip)					{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_flags &= ~MDI_PATHINFO_FLAGS_HIDDEN;		}
#define	MDI_PI_FLAGS_IS_HIDDEN(pip)					\
	((MDI_PI(pip)->pi_flags & MDI_PATHINFO_FLAGS_HIDDEN) ==		\
	MDI_PATHINFO_FLAGS_HIDDEN)

#define	MDI_PI_FLAGS_SET_DEVICE_REMOVED(pip)				{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_flags |= MDI_PATHINFO_FLAGS_DEVICE_REMOVED;	}
#define	MDI_PI_FLAGS_CLR_DEVICE_REMOVED(pip)				{\
	ASSERT(MDI_PI_LOCKED(pip));					\
	MDI_PI(pip)->pi_flags &= ~MDI_PATHINFO_FLAGS_DEVICE_REMOVED;	}
#define	MDI_PI_FLAGS_IS_DEVICE_REMOVED(pip)				\
	((MDI_PI(pip)->pi_flags & MDI_PATHINFO_FLAGS_DEVICE_REMOVED) ==	\
	MDI_PATHINFO_FLAGS_DEVICE_REMOVED)

/*
 * mdi_vhcache_client, mdi_vhcache_pathinfo, and mdi_vhcache_phci structures
 * hold the vhci to phci client mappings of the on-disk vhci busconfig cache.
 */

/* phci structure of vhci cache */
typedef struct mdi_vhcache_phci {
	char			*cphci_path;	/* phci path name */
	uint32_t		cphci_id;	/* used when building nvlist */
	mdi_phci_t		*cphci_phci;	/* pointer to actual phci */
	struct mdi_vhcache_phci	*cphci_next;	/* next in vhci phci list */
} mdi_vhcache_phci_t;

/* pathinfo structure of vhci cache */
typedef struct mdi_vhcache_pathinfo {
	char			*cpi_addr;	/* path address */
	mdi_vhcache_phci_t	*cpi_cphci;	/* phci the path belongs to */
	struct mdi_pathinfo	*cpi_pip;	/* ptr to actual pathinfo */
	uint32_t		cpi_flags;	/* see below */
	struct mdi_vhcache_pathinfo *cpi_next;	/* next path for the client */
} mdi_vhcache_pathinfo_t;

/*
 * cpi_flags
 *
 * MDI_CPI_HINT_PATH_DOES_NOT_EXIST - set when configuration of the path has
 * failed.
 */
#define	MDI_CPI_HINT_PATH_DOES_NOT_EXIST	0x0001

/* client structure of vhci cache */
typedef struct mdi_vhcache_client {
	char			*cct_name_addr;	/* client address */
	mdi_vhcache_pathinfo_t	*cct_cpi_head;	/* client's path list head */
	mdi_vhcache_pathinfo_t	*cct_cpi_tail;	/* client's path list tail */
	struct mdi_vhcache_client *cct_next;	/* next in vhci client list */
} mdi_vhcache_client_t;

/* vhci cache structure - one for vhci instance */
typedef struct mdi_vhci_cache {
	mdi_vhcache_phci_t	*vhcache_phci_head;	/* phci list head */
	mdi_vhcache_phci_t	*vhcache_phci_tail;	/* phci list tail */
	mdi_vhcache_client_t	*vhcache_client_head;	/* client list head */
	mdi_vhcache_client_t	*vhcache_client_tail;	/* client list tail */
	mod_hash_t		*vhcache_client_hash;	/* client hash */
	int			vhcache_flags;		/* see below */
	int64_t			vhcache_clean_time;	/* last clean time */
	krwlock_t		vhcache_lock;		/* cache lock */
} mdi_vhci_cache_t;

/* vhcache_flags */
#define	MDI_VHCI_CACHE_SETUP_DONE	0x0001	/* cache setup completed */

/* vhci bus config structure - one for vhci instance */
typedef struct mdi_vhci_config {
	char			*vhc_vhcache_filename;	/* on-disk file name */
	mdi_vhci_cache_t	vhc_vhcache;		/* vhci cache */
	kmutex_t		vhc_lock;		/* vhci config lock */
	kcondvar_t		vhc_cv;
	int			vhc_flags;		/* see below */

	/* flush vhci cache when lbolt reaches vhc_flush_at_ticks */
	clock_t			vhc_flush_at_ticks;

	/*
	 * Head and tail of the client list whose paths are being configured
	 * asynchronously. vhc_acc_count is the number of clients on this list.
	 * vhc_acc_thrcount is the number threads running to configure
	 * the paths for these clients.
	 */
	struct mdi_async_client_config *vhc_acc_list_head;
	struct mdi_async_client_config *vhc_acc_list_tail;
	int			vhc_acc_count;
	int			vhc_acc_thrcount;

	/* callback id - for flushing the cache during system shutdown */
	callb_id_t		vhc_cbid;

	/*
	 * vhc_path_discovery_boot -	number of times path discovery will be
	 *				attempted during early boot.
	 * vhc_path_discovery_postboot	number of times path discovery will be
	 *				attempted during late boot.
	 * vhc_path_discovery_cutoff_time - time at which paths were last
	 *				discovered  + some timeout
	 */
	int			vhc_path_discovery_boot;
	int			vhc_path_discovery_postboot;
	int64_t			vhc_path_discovery_cutoff_time;
} mdi_vhci_config_t;

/* vhc_flags */
#define	MDI_VHC_SINGLE_THREADED		0x0001	/* config single threaded */
#define	MDI_VHC_EXIT			0x0002	/* exit all config activity */
#define	MDI_VHC_VHCACHE_DIRTY		0x0004	/* cache dirty */
#define	MDI_VHC_VHCACHE_FLUSH_THREAD	0x0008	/* cache flush thead running */
#define	MDI_VHC_VHCACHE_FLUSH_ERROR	0x0010	/* failed to flush cache */
#define	MDI_VHC_READONLY_FS		0x0020	/* filesys is readonly */

typedef struct mdi_phys_path {
	char			*phys_path;
	struct mdi_phys_path	*phys_path_next;
} mdi_phys_path_t;

/*
 * Lookup tokens are used to cache the result of the vhci cache client lookup
 * operations (to reduce the number of real lookup operations).
 */
typedef struct mdi_vhcache_lookup_token {
	mdi_vhcache_client_t	*lt_cct;		/* vhcache client */
	int64_t			lt_cct_lookup_time;	/* last lookup time */
} mdi_vhcache_lookup_token_t;

/* asynchronous configuration of client paths */
typedef struct mdi_async_client_config {
	char			*acc_ct_name;	/* client name */
	char			*acc_ct_addr;	/* client address */
	mdi_phys_path_t		*acc_phclient_path_list_head;	/* path head */
	mdi_vhcache_lookup_token_t acc_token;	/* lookup token */
	struct mdi_async_client_config *acc_next; /* next in vhci acc list */
} mdi_async_client_config_t;

/*
 * vHCI driver instance registration/unregistration
 *
 * mdi_vhci_register() is called by a vHCI driver to register itself as the
 * manager of devices from a particular 'class'.  This should be called from
 * attach(9e).
 *
 * mdi_vhci_unregister() is called from detach(9E) to unregister a vHCI
 * instance from the framework.
 */
int		mdi_vhci_register(char *, dev_info_t *, mdi_vhci_ops_t *, int);
int		mdi_vhci_unregister(dev_info_t *, int);

/*
 * Utility functions
 */
int		mdi_phci_get_path_count(dev_info_t *);
dev_info_t	*mdi_phci_path2devinfo(dev_info_t *, caddr_t);


/*
 * Path Selection Functions:
 *
 * mdi_select_path() is called by a vHCI driver to select to which path an
 * I/O request should be routed.  The caller passes the 'buf' structure as
 * one of the parameters.  The mpxio framework uses the buf's contents to
 * maintain per path statistics (total I/O size / count pending).  If more
 * than one online path is available, the framework automatically selects
 * a suitable one.  If a failover operation is active for this client device
 * the call fails, returning MDI_BUSY.
 *
 * By default this function returns a suitable path in the 'online' state,
 * based on the current load balancing policy.  Currently we support
 * LOAD_BALANCE_NONE (Previously selected online path will continue to be
 * used as long as the path is usable) and LOAD_BALANCE_RR (Online paths
 * will be selected in a round robin fashion).  The load balancing scheme
 * can be configured in the vHCI driver's configuration file (driver.conf).
 *
 * vHCI drivers may override this default behavior by specifying appropriate
 * flags.  If start_pip is specified (non NULL), it is used as the routine's
 * starting point; it starts walking from there to find the next appropriate
 * path.
 *
 * The following values for 'flags' are currently defined, the third argument
 * to mdi_select_path depends on the flags used.
 *
 *   <none>:				default, arg is pip
 *   MDI_SELECT_ONLINE_PATH:		select an ONLINE path preferred-first,
 *					arg is pip
 *   MDI_SELECT_STANDBY_PATH:		select a STANDBY path, arg is pip
 *   MDI_SELECT_USER_DISABLE_PATH:	select user disable for failover and
 *					auto_failback
 *   MDI_SELECT_PATH_INSTANCE:		select a specific path, arg is
 *					path instance
 *   MDI_SELECT_NO_PREFERRED:		select path without preferred-first
 *
 * The selected paths are returned in an mdi_hold_path() state (pi_ref_cnt),
 * caller should release the hold by calling mdi_rele_path() at the end of
 * operation.
 */
int		mdi_select_path(dev_info_t *, struct buf *, int,
		    void *, mdi_pathinfo_t **);
int		mdi_set_lb_policy(dev_info_t *, client_lb_t);
int		mdi_set_lb_region_size(dev_info_t *, int);
client_lb_t	mdi_get_lb_policy(dev_info_t *);

/*
 * flags for mdi_select_path() routine
 */
#define	MDI_SELECT_ONLINE_PATH		0x0001
#define	MDI_SELECT_STANDBY_PATH		0x0002
#define	MDI_SELECT_USER_DISABLE_PATH	0x0004
#define	MDI_SELECT_PATH_INSTANCE	0x0008
#define	MDI_SELECT_NO_PREFERRED		0x0010

/*
 * MDI client device utility functions
 */
int		mdi_client_get_path_count(dev_info_t *);
dev_info_t	*mdi_client_path2devinfo(dev_info_t *, caddr_t);

/*
 * Failover:
 *
 * The vHCI driver calls mdi_failover() to initiate a failover operation.
 * mdi_failover() calls back into the vHCI driver's vo_failover()
 * entry point to perform the actual failover operation.  The reason
 * for requiring the vHCI driver to initiate failover by calling
 * mdi_failover(), instead of directly executing vo_failover() itself,
 * is to ensure that the mdi framework can keep track of the client
 * state properly.  Additionally, mdi_failover() provides as a
 * convenience the option of performing the failover operation
 * synchronously or asynchronously
 *
 * Upon successful completion of the failover operation, the paths that were
 * previously ONLINE will be in the STANDBY state, and the newly activated
 * paths will be in the ONLINE state.
 *
 * The flags modifier determines whether the activation is done synchronously
 */
int mdi_failover(dev_info_t *, dev_info_t *, int);

/*
 * Client device failover mode of operation
 */
#define	MDI_FAILOVER_SYNC	1	/* Synchronous Failover		*/
#define	MDI_FAILOVER_ASYNC	2	/* Asynchronous Failover	*/

/*
 * mdi_is_dev_supported: The pHCI driver bus_config implementation calls
 * mdi_is_dev_supported to determine if a child device should is supported as
 * a vHCI child (i.e. as a client). The method used to specify the child
 * device, via the cinfo argument, is by agreement between the pHCI and the
 * vHCI.  In the case of SCSA and scsi_vhci cinfo is a pointer to the pHCI
 * probe dev_info node, which is decorated with the device idenity information
 * necessary to determine scsi_vhci support.
 */
int mdi_is_dev_supported(char *class, dev_info_t *pdip, void *cinfo);

/*
 * mdi_pathinfo node kstat functions.
 */
int mdi_pi_kstat_exists(mdi_pathinfo_t *);
int mdi_pi_kstat_create(mdi_pathinfo_t *pip, char *ks_name);
void mdi_pi_kstat_iosupdate(mdi_pathinfo_t *, struct buf *);

/*
 * mdi_pathinfo node extended state change functions.
 */
int mdi_pi_get_state2(mdi_pathinfo_t *, mdi_pathinfo_state_t *, uint32_t *);
int mdi_pi_get_preferred(mdi_pathinfo_t *);

/*
 * mdi_pathinfo node member functions
 */
void *mdi_pi_get_client_private(mdi_pathinfo_t *);
void mdi_pi_set_client_private(mdi_pathinfo_t *, void *);
void mdi_pi_set_state(mdi_pathinfo_t *, mdi_pathinfo_state_t);
void mdi_pi_set_preferred(mdi_pathinfo_t *, int);

/* get/set vhci private data */
void *mdi_client_get_vhci_private(dev_info_t *);
void mdi_client_set_vhci_private(dev_info_t *, void *);
void *mdi_phci_get_vhci_private(dev_info_t *);
void mdi_phci_set_vhci_private(dev_info_t *, void *);
void *mdi_pi_get_vhci_private(mdi_pathinfo_t *);
void mdi_pi_set_vhci_private(mdi_pathinfo_t *, void *);
int mdi_dc_return_dev_state(mdi_pathinfo_t *pip, struct devctl_iocdata *dcp);

/*
 * mdi_pathinfo Property utilities
 */
int mdi_prop_size(mdi_pathinfo_t *, size_t *);
int mdi_prop_pack(mdi_pathinfo_t *, char **, uint_t);

/* obsolete interface, to be removed */
void mdi_get_next_path(dev_info_t *, mdi_pathinfo_t *, mdi_pathinfo_t **);
int mdi_get_component_type(dev_info_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MDI_IMPLDEFS_H */
