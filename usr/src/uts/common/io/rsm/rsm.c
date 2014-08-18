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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */


/*
 * Overview of the RSM Kernel Agent:
 * ---------------------------------
 *
 * rsm.c constitutes the implementation of the RSM kernel agent. The RSM
 * kernel agent is a pseudo device driver which makes use of the RSMPI
 * interface on behalf of the RSMAPI user library.
 *
 * The kernel agent functionality can be categorized into the following
 * components:
 * 1. Driver Infrastructure
 * 2. Export/Import Segment Management
 * 3. Internal resource allocation/deallocation
 *
 * The driver infrastructure includes the basic module loading entry points
 * like _init, _info, _fini to load, unload and report information about
 * the driver module. The driver infrastructure also includes the
 * autoconfiguration entry points namely, attach, detach and getinfo for
 * the device autoconfiguration.
 *
 * The kernel agent is a pseudo character device driver and exports
 * a cb_ops structure which defines the driver entry points for character
 * device access. This includes the open and close entry points. The
 * other entry points provided include ioctl, devmap and segmap and chpoll.
 * read and write entry points are not used since the device is memory
 * mapped. Also ddi_prop_op is used for the prop_op entry point.
 *
 * The ioctl entry point supports a number of commands, which are used by
 * the RSMAPI library in order to export and import segments. These
 * commands include commands for binding and rebinding the physical pages
 * allocated to the virtual address range, publishing the export segment,
 * unpublishing and republishing an export segment, creating an
 * import segment and a virtual connection from this import segment to
 * an export segment, performing scatter-gather data transfer, barrier
 * operations.
 *
 *
 * Export and Import segments:
 * ---------------------------
 *
 * In order to create an RSM export segment a process allocates a range in its
 * virtual address space for the segment using standard Solaris interfaces.
 * The process then calls RSMAPI, which in turn makes an ioctl call to the
 * RSM kernel agent for an allocation of physical memory pages and for
 * creation of the export segment by binding these pages to the virtual
 * address range. These pages are locked in memory so that remote accesses
 * are always applied to the correct page. Then the RSM segment is published,
 * again via RSMAPI making an ioctl to the RSM kernel agent, and a segment id
 * is assigned to it.
 *
 * In order to import a published RSM segment, RSMAPI creates an import
 * segment and forms a virtual connection across the interconnect to the
 * export segment, via an ioctl into the kernel agent with the connect
 * command. The import segment setup is completed by mapping the
 * local device memory into the importers virtual address space. The
 * mapping of the import segment is handled by the segmap/devmap
 * infrastructure described as follows.
 *
 * Segmap and Devmap interfaces:
 *
 * The RSM kernel agent allows device memory to be directly accessed by user
 * threads via memory mapping. In order to do so, the RSM kernel agent
 * supports the devmap and segmap entry points.
 *
 * The segmap entry point(rsm_segmap) is responsible for setting up a memory
 * mapping as requested by mmap. The devmap entry point(rsm_devmap) is
 * responsible for exporting the device memory to the user applications.
 * rsm_segmap calls RSMPI rsm_map to allocate device memory. Then the
 * control is transfered to the devmap_setup call which calls rsm_devmap.
 *
 * rsm_devmap validates the user mapping to the device or kernel memory
 * and passes the information to the system for setting up the mapping. The
 * actual setting up of the mapping is done by devmap_devmem_setup(for
 * device memory) or devmap_umem_setup(for kernel memory). Callbacks are
 * registered for device context management via the devmap_devmem_setup
 * or devmap_umem_setup calls. The callbacks are rsmmap_map, rsmmap_unmap,
 * rsmmap_access, rsmmap_dup. The callbacks are called when a new mapping
 * is created, a mapping is freed, a mapping is accessed or an existing
 * mapping is duplicated respectively. These callbacks allow the RSM kernel
 * agent to maintain state information associated with the mappings.
 * The state information is mainly in the form of a cookie list for the import
 * segment for which mapping has been done.
 *
 * Forced disconnect of import segments:
 *
 * When an exported segment is unpublished, the exporter sends a forced
 * disconnect message to all its importers. The importer segments are
 * unloaded and disconnected. This involves unloading the original
 * mappings and remapping to a preallocated kernel trash page. This is
 * done by devmap_umem_remap. The trash/dummy page is a kernel page,
 * preallocated by the kernel agent during attach using ddi_umem_alloc with
 * the DDI_UMEM_TRASH flag set. This avoids a core dump in the application
 * due to unloading of the original mappings.
 *
 * Additionally every segment has a mapping generation number associated
 * with it. This is an entry in the barrier generation page, created
 * during attach time. This mapping generation number for the import
 * segments is incremented on a force disconnect to notify the application
 * of the force disconnect. On this notification, the application needs
 * to reconnect the segment to establish a new legitimate mapping.
 *
 *
 * Locks used in the kernel agent:
 * -------------------------------
 *
 * The kernel agent uses a variety of mutexes and condition variables for
 * mutual exclusion of the shared data structures and for synchronization
 * between the various threads. Some of the locks are described as follows.
 *
 * Each resource structure, which represents either an export/import segment
 * has a lock associated with it. The lock is the resource mutex, rsmrc_lock.
 * This is used directly by RSMRC_LOCK and RSMRC_UNLOCK macros and in the
 * rsmseglock_acquire and rsmseglock_release macros. An additional
 * lock called the rsmsi_lock is used for the shared import data structure
 * that is relevant for resources representing import segments. There is
 * also a condition variable associated with the resource called s_cv. This
 * is used to wait for events like the segment state change etc.
 *
 * The resource structures are allocated from a pool of resource structures,
 * called rsm_resource. This pool is protected via a reader-writer lock,
 * called rsmrc_lock.
 *
 * There are two separate hash tables, one for the export segments and
 * one for the import segments. The export segments are inserted into the
 * export segment hash table only after they have been published and the
 * import segments are inserted in the import segments list only after they
 * have successfully connected to an exported segment. These tables are
 * protected via reader-writer locks.
 *
 * Debug Support in the kernel agent:
 * ----------------------------------
 *
 * Debugging support in the kernel agent is provided by the following
 * macros.
 *
 * DBG_PRINTF((category, level, message)) is a macro which logs a debug
 * message to the kernel agents debug buffer, rsmka_dbg. This debug buffer
 * can be viewed in kmdb as *rsmka_dbg/s. The message is logged based
 * on the definition of the category and level. All messages that belong to
 * the specified category(rsmdbg_category) and are of an equal or greater
 * severity than the specified level(rsmdbg_level) are logged. The message
 * is a string which uses the same formatting rules as the strings used in
 * printf.
 *
 * The category defines which component of the kernel agent has logged this
 * message. There are a number of categories that have been defined such as
 * RSM_KERNEL_AGENT, RSM_OPS, RSM_IMPORT, RSM_EXPORT etc. A macro,
 * DBG_ADDCATEGORY is used to add in another category to the currently
 * specified category value so that the component using this new category
 * can also effectively log debug messages. Thus, the category of a specific
 * message is some combination of the available categories and we can define
 * sub-categories if we want a finer level of granularity.
 *
 * The level defines the severity of the message. Different level values are
 * defined, with RSM_ERR being the most severe and RSM_DEBUG_VERBOSE being
 * the least severe(debug level is 0).
 *
 * DBG_DEFINE and DBG_DEFINE_STR are macros provided to declare a debug
 * variable or a string respectively.
 *
 *
 * NOTES:
 *
 * Special Fork and Exec Handling:
 * -------------------------------
 *
 * The backing physical pages of an exported segment are always locked down.
 * Thus, there are two cases in which a process having exported segments
 * will cause a cpu to hang: (1) the process invokes exec; (2) a process
 * forks and invokes exit before the duped file descriptors for the export
 * segments are closed in the child process. The hang is caused because the
 * address space release algorithm in Solaris VM subsystem is based on a
 * non-blocking loop which does not terminate while segments are locked
 * down. In addition to this, Solaris VM subsystem lacks a callback
 * mechanism to the rsm kernel agent to allow unlocking these export
 * segment pages.
 *
 * In order to circumvent this problem, the kernel agent does the following.
 * The Solaris VM subsystem keeps memory segments in increasing order of
 * virtual addressses. Thus a special page(special_exit_offset) is allocated
 * by the kernel agent and is mmapped into the heap area of the process address
 * space(the mmap is done by the RSMAPI library). During the mmap processing
 * of this special page by the devmap infrastructure, a callback(the same
 * devmap context management callbacks discussed above) is registered for an
 * unmap.
 *
 * As discussed above, this page is processed by the Solaris address space
 * release code before any of the exported segments pages(which are allocated
 * from high memory). It is during this processing that the unmap callback gets
 * called and this callback is responsible for force destroying the exported
 * segments and thus eliminating the problem of locked pages.
 *
 * Flow-control:
 * ------------
 *
 * A credit based flow control algorithm is used for messages whose
 * processing cannot be done in the interrupt context because it might
 * involve invoking rsmpi calls, or might take a long time to complete
 * or might need to allocate resources. The algorithm operates on a per
 * path basis. To send a message the pathend needs to have a credit and
 * it consumes one for every message that is flow controlled. On the
 * receiving pathend the message is put on a msgbuf_queue and a task is
 * dispatched on the worker thread - recv_taskq where it is processed.
 * After processing the message, the receiving pathend dequeues the message,
 * and if it has processed > RSMIPC_LOTSFREE_MSGBUFS messages sends
 * credits to the sender pathend.
 *
 * RSM_DRTEST:
 * -----------
 *
 * This is used to enable the DR testing using a test driver on test
 * platforms which do not supported DR.
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/vm.h>
#include <sys/uio.h>
#include <vm/seg.h>
#include <vm/page.h>
#include <sys/stat.h>

#include <sys/time.h>
#include <sys/errno.h>

#include <sys/file.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/mman.h>
#include <sys/open.h>
#include <sys/atomic.h>
#include <sys/mem_config.h>


#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/ddidevmap.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/ddi_impldefs.h>

#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi_impldefs.h>

#include <sys/modctl.h>

#include <sys/policy.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/param.h>

#include <sys/taskq.h>

#include <sys/rsm/rsm_common.h>
#include <sys/rsm/rsmapi_common.h>
#include <sys/rsm/rsm.h>
#include <rsm_in.h>
#include <sys/rsm/rsmka_path_int.h>
#include <sys/rsm/rsmpi.h>

#include <sys/modctl.h>
#include <sys/debug.h>

#include <sys/tuneable.h>

#ifdef	RSM_DRTEST
extern int rsm_kphysm_setup_func_register(kphysm_setup_vector_t *vec,
		void *arg);
extern void rsm_kphysm_setup_func_unregister(kphysm_setup_vector_t *vec,
		void *arg);
#endif

extern void dbg_printf(int category, int level, char *fmt, ...);
extern void rsmka_pathmanager_init();
extern void rsmka_pathmanager_cleanup();
extern void rele_sendq_token(sendq_token_t *);
extern rsm_addr_t get_remote_hwaddr(adapter_t *, rsm_node_id_t);
extern rsm_node_id_t get_remote_nodeid(adapter_t *, rsm_addr_t);
extern int rsmka_topology_ioctl(caddr_t, int, int);

extern pri_t maxclsyspri;
extern work_queue_t work_queue;
extern kmutex_t ipc_info_lock;
extern kmutex_t ipc_info_cvlock;
extern kcondvar_t ipc_info_cv;
extern kmutex_t path_hold_cvlock;
extern kcondvar_t path_hold_cv;

extern kmutex_t rsmka_buf_lock;

extern path_t *rsm_find_path(char *, int, rsm_addr_t);
extern adapter_t *rsmka_lookup_adapter(char *, int);
extern sendq_token_t *rsmka_get_sendq_token(rsm_node_id_t, sendq_token_t *);
extern boolean_t rsmka_do_path_active(path_t *, int);
extern boolean_t rsmka_check_node_alive(rsm_node_id_t);
extern void rsmka_release_adapter(adapter_t *);
extern void rsmka_enqueue_msgbuf(path_t *path, void *data);
extern void rsmka_dequeue_msgbuf(path_t *path);
extern msgbuf_elem_t *rsmka_gethead_msgbuf(path_t *path);
/* lint -w2 */

static int rsm_open(dev_t *, int, int, cred_t *);
static int rsm_close(dev_t, int, int, cred_t *);
static int rsm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp);
static int rsm_devmap(dev_t, devmap_cookie_t, offset_t, size_t, size_t *,
    uint_t);
static int rsm_segmap(dev_t, off_t, struct as *, caddr_t *, off_t, uint_t,
    uint_t, uint_t, cred_t *);
static int rsm_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp);

static int rsm_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int rsm_attach(dev_info_t *, ddi_attach_cmd_t);
static int rsm_detach(dev_info_t *, ddi_detach_cmd_t);

static int rsmipc_send(rsm_node_id_t, rsmipc_request_t *, rsmipc_reply_t *);
static void rsm_force_unload(rsm_node_id_t, rsm_memseg_id_t, boolean_t);
static void rsm_send_importer_disconnects(rsm_memseg_id_t, rsm_node_id_t);
static void rsm_send_republish(rsm_memseg_id_t, rsmapi_access_entry_t *, int,
				rsm_permission_t);
static void rsm_export_force_destroy(ddi_umem_cookie_t *);
static void rsmacl_free(rsmapi_access_entry_t *, int);
static void rsmpiacl_free(rsm_access_entry_t *, int);

static int rsm_inc_pgcnt(pgcnt_t);
static void rsm_dec_pgcnt(pgcnt_t);
static void rsm_free_mapinfo(rsm_mapinfo_t *mapinfop);
static rsm_mapinfo_t *rsm_get_mapinfo(rsmseg_t *, off_t, size_t, off_t *,
					size_t *);
static void exporter_quiesce();
static void rsmseg_suspend(rsmseg_t *, int *);
static void rsmsegshare_suspend(rsmseg_t *);
static int rsmseg_resume(rsmseg_t *, void **);
static int rsmsegshare_resume(rsmseg_t *);

static struct cb_ops rsm_cb_ops = {
	rsm_open,		/* open */
	rsm_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	rsm_ioctl,		/* ioctl */
	rsm_devmap,		/* devmap */
	NULL,			/* mmap */
	rsm_segmap,		/* segmap */
	rsm_chpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW|D_MP|D_DEVMAP,	/* Driver compatibility flag */
	0,
	0,
	0
};

static struct dev_ops rsm_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	rsm_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	rsm_attach,		/* attach */
	rsm_detach,		/* detach */
	nodev,			/* reset */
	&rsm_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	0,
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"Remote Shared Memory Driver",
	&rsm_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	0,
	0,
	0
};

static void rsm_dr_callback_post_add(void *arg, pgcnt_t delta);
static int rsm_dr_callback_pre_del(void *arg, pgcnt_t delta);
static void rsm_dr_callback_post_del(void *arg, pgcnt_t delta, int cancelled);

static kphysm_setup_vector_t rsm_dr_callback_vec = {
	KPHYSM_SETUP_VECTOR_VERSION,
	rsm_dr_callback_post_add,
	rsm_dr_callback_pre_del,
	rsm_dr_callback_post_del
};

/* This flag can be changed to 0 to help with PIT testing */
int rsmka_modunloadok = 1;
int no_reply_cnt = 0;

uint64_t rsm_ctrlmsg_errcnt = 0;
uint64_t rsm_ipcsend_errcnt = 0;

#define	MAX_NODES 64

static struct rsm_driver_data rsm_drv_data;
static struct rsmresource_table rsm_resource;

static void rsmresource_insert(minor_t, rsmresource_t *, rsm_resource_type_t);
static void rsmresource_destroy(void);
static int rsmresource_alloc(minor_t *);
static rsmresource_t *rsmresource_free(minor_t rnum);
static int rsm_closeconnection(rsmseg_t *seg, void **cookie);
static int rsm_unpublish(rsmseg_t *seg, int mode);
static int rsm_unbind(rsmseg_t *seg);
static uint_t rsmhash(rsm_memseg_id_t key);
static void rsmhash_alloc(rsmhash_table_t *rhash, int size);
static void rsmhash_free(rsmhash_table_t *rhash, int size);
static void *rsmhash_getbkt(rsmhash_table_t *rhash, uint_t hashval);
static void **rsmhash_bktaddr(rsmhash_table_t *rhash, uint_t hashval);
static int rsm_send_notimporting(rsm_node_id_t dest, rsm_memseg_id_t segid,
					void *cookie);
int rsm_disconnect(rsmseg_t *seg);
void rsmseg_unload(rsmseg_t *);
void rsm_suspend_complete(rsm_node_id_t src_node, int flag);

rsm_intr_hand_ret_t rsm_srv_func(rsm_controller_object_t *chd,
    rsm_intr_q_op_t opcode, rsm_addr_t src,
    void *data, size_t size, rsm_intr_hand_arg_t arg);

static void rsm_intr_callback(void *, rsm_addr_t, rsm_intr_hand_arg_t);

rsm_node_id_t my_nodeid;

/* cookie, va, offsets and length for the barrier */
static rsm_gnum_t		*bar_va;
static ddi_umem_cookie_t	bar_cookie;
static off_t			barrier_offset;
static size_t			barrier_size;
static int			max_segs;

/* cookie for the trash memory */
static ddi_umem_cookie_t	remap_cookie;

static rsm_memseg_id_t	rsm_nextavail_segmentid;

extern taskq_t *work_taskq;
extern char *taskq_name;

static dev_info_t *rsm_dip;	/* private copy of devinfo pointer */

static rsmhash_table_t rsm_export_segs;		/* list of exported segs */
rsmhash_table_t rsm_import_segs;		/* list of imported segs */
static rsmhash_table_t rsm_event_queues;	/* list of event queues */

static	rsm_ipc_t	rsm_ipc;		/* ipc info */

/* list of nodes to which RSMIPC_MSG_SUSPEND has been sent */
static list_head_t	rsm_suspend_list;

/* list of descriptors for remote importers */
static importers_table_t importer_list;

kmutex_t rsm_suspend_cvlock;
kcondvar_t rsm_suspend_cv;

static kmutex_t rsm_lock;

adapter_t loopback_adapter;
rsm_controller_attr_t loopback_attr;

int rsmipc_send_controlmsg(path_t *path, int msgtype);

void rsmka_init_loopback();

int rsmka_null_seg_create(
    rsm_controller_handle_t,
    rsm_memseg_export_handle_t *,
    size_t,
    uint_t,
    rsm_memory_local_t *,
    rsm_resource_callback_t,
    rsm_resource_callback_arg_t);

int rsmka_null_seg_destroy(
    rsm_memseg_export_handle_t);

int rsmka_null_bind(
    rsm_memseg_export_handle_t,
    off_t,
    rsm_memory_local_t *,
    rsm_resource_callback_t,
    rsm_resource_callback_arg_t);

int rsmka_null_unbind(
    rsm_memseg_export_handle_t,
    off_t,
    size_t);

int rsmka_null_rebind(
    rsm_memseg_export_handle_t,
    off_t,
    rsm_memory_local_t *,
    rsm_resource_callback_t,
    rsm_resource_callback_arg_t);

int rsmka_null_publish(
    rsm_memseg_export_handle_t,
    rsm_access_entry_t [],
    uint_t,
    rsm_memseg_id_t,
    rsm_resource_callback_t,
    rsm_resource_callback_arg_t);


int rsmka_null_republish(
    rsm_memseg_export_handle_t,
    rsm_access_entry_t [],
    uint_t,
    rsm_resource_callback_t,
    rsm_resource_callback_arg_t);

int rsmka_null_unpublish(
    rsm_memseg_export_handle_t);

rsm_ops_t null_rsmpi_ops;

/*
 * data and locks to keep track of total amount of exported memory
 */
static	pgcnt_t		rsm_pgcnt;
static	pgcnt_t		rsm_pgcnt_max;	/* max allowed */
static	kmutex_t	rsm_pgcnt_lock;

static	int		rsm_enable_dr;

static	char		loopback_str[] = "loopback";

int		rsm_hash_size;

/*
 * The locking model is as follows:
 *
 * Local operations:
 *		find resource - grab reader lock on resouce list
 *		insert rc     - grab writer lock
 *		delete rc     - grab writer lock and resource mutex
 *		read/write    - no lock
 *
 * Remote invocations:
 *		find resource - grab read lock and resource mutex
 *
 * State:
 *		resource state - grab resource mutex
 */

int
_init(void)
{
	int e;

	e = mod_install(&modlinkage);
	if (e != 0) {
		return (e);
	}

	mutex_init(&rsm_lock, NULL, MUTEX_DRIVER, NULL);

	mutex_init(&rsmka_buf_lock, NULL, MUTEX_DEFAULT, NULL);


	rw_init(&rsm_resource.rsmrc_lock, NULL, RW_DRIVER, NULL);

	rsm_hash_size = RSM_HASHSZ;

	rw_init(&rsm_export_segs.rsmhash_rw, NULL, RW_DRIVER, NULL);

	rw_init(&rsm_import_segs.rsmhash_rw, NULL, RW_DRIVER, NULL);

	mutex_init(&importer_list.lock, NULL, MUTEX_DRIVER, NULL);

	mutex_init(&rsm_ipc.lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&rsm_ipc.cv, NULL, CV_DRIVER, 0);

	mutex_init(&rsm_suspend_cvlock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&rsm_suspend_cv, NULL, CV_DRIVER, 0);

	mutex_init(&rsm_drv_data.drv_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&rsm_drv_data.drv_cv, NULL, CV_DRIVER, 0);

	rsm_ipc.count = RSMIPC_SZ;
	rsm_ipc.wanted = 0;
	rsm_ipc.sequence = 0;

	(void) mutex_init(&rsm_pgcnt_lock, NULL, MUTEX_DRIVER, NULL);

	for (e = 0; e < RSMIPC_SZ; e++) {
		rsmipc_slot_t *slot = &rsm_ipc.slots[e];

		RSMIPC_SET(slot, RSMIPC_FREE);
		mutex_init(&slot->rsmipc_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&slot->rsmipc_cv, NULL, CV_DRIVER, 0);
	}

	/*
	 * Initialize the suspend message list
	 */
	rsm_suspend_list.list_head = NULL;
	mutex_init(&rsm_suspend_list.list_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * It is assumed here that configuration data is available
	 * during system boot since _init may be called at that time.
	 */

	rsmka_pathmanager_init();

	DBG_PRINTF((RSM_KERNEL_AGENT, RSM_DEBUG_VERBOSE,
	    "rsm: _init done\n"));

	return (DDI_SUCCESS);

}

int
_info(struct modinfo *modinfop)
{

	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int e;

	DBG_PRINTF((RSM_KERNEL_AGENT, RSM_DEBUG_VERBOSE,
	    "rsm: _fini enter\n"));

	/*
	 * The rsmka_modunloadok flag is simply used to help with
	 * the PIT testing. Make this flag 0 to disallow modunload.
	 */
	if (rsmka_modunloadok == 0)
		return (EBUSY);

	/* rsm_detach will be called as a result of mod_remove */
	e = mod_remove(&modlinkage);
	if (e) {
		DBG_PRINTF((RSM_KERNEL_AGENT, RSM_ERR,
		    "Unable to fini RSM %x\n", e));
		return (e);
	}

	rsmka_pathmanager_cleanup();

	rw_destroy(&rsm_resource.rsmrc_lock);

	rw_destroy(&rsm_export_segs.rsmhash_rw);
	rw_destroy(&rsm_import_segs.rsmhash_rw);
	rw_destroy(&rsm_event_queues.rsmhash_rw);

	mutex_destroy(&importer_list.lock);

	mutex_destroy(&rsm_ipc.lock);
	cv_destroy(&rsm_ipc.cv);

	(void) mutex_destroy(&rsm_suspend_list.list_lock);

	(void) mutex_destroy(&rsm_pgcnt_lock);

	DBG_PRINTF((RSM_KERNEL_AGENT, RSM_DEBUG_VERBOSE, "_fini done\n"));

	return (DDI_SUCCESS);

}

/*ARGSUSED1*/
static int
rsm_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	minor_t	rnum;
	int	percent;
	int	ret;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_attach enter\n"));

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
	default:
		DBG_PRINTF((category, RSM_ERR,
		    "rsm:rsm_attach - cmd not supported\n"));
		return (DDI_FAILURE);
	}

	if (rsm_dip != NULL) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm:rsm_attach - supports only "
		    "one instance\n"));
		return (DDI_FAILURE);
	}

	rsm_enable_dr = ddi_prop_get_int(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "enable-dynamic-reconfiguration", 1);

	mutex_enter(&rsm_drv_data.drv_lock);
	rsm_drv_data.drv_state = RSM_DRV_REG_PROCESSING;
	mutex_exit(&rsm_drv_data.drv_lock);

	if (rsm_enable_dr) {
#ifdef	RSM_DRTEST
		ret = rsm_kphysm_setup_func_register(&rsm_dr_callback_vec,
		    (void *)NULL);
#else
		ret = kphysm_setup_func_register(&rsm_dr_callback_vec,
		    (void *)NULL);
#endif
		if (ret != 0) {
			mutex_exit(&rsm_drv_data.drv_lock);
			cmn_err(CE_CONT, "rsm:rsm_attach - Dynamic "
			    "reconfiguration setup failed\n");
			return (DDI_FAILURE);
		}
	}

	mutex_enter(&rsm_drv_data.drv_lock);
	ASSERT(rsm_drv_data.drv_state == RSM_DRV_REG_PROCESSING);
	rsm_drv_data.drv_state = RSM_DRV_OK;
	cv_broadcast(&rsm_drv_data.drv_cv);
	mutex_exit(&rsm_drv_data.drv_lock);

	/*
	 * page_list_read_lock();
	 * xx_setup();
	 * page_list_read_unlock();
	 */

	rsm_hash_size = ddi_prop_get_int(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "segment-hashtable-size", RSM_HASHSZ);
	if (rsm_hash_size == 0) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm: segment-hashtable-size in rsm.conf "
		    "must be greater than 0, defaulting to 128\n"));
		rsm_hash_size = RSM_HASHSZ;
	}

	DBG_PRINTF((category, RSM_DEBUG, "rsm_attach rsm_hash_size: %d\n",
	    rsm_hash_size));

	rsm_pgcnt = 0;

	percent = ddi_prop_get_int(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "max-exported-memory", 0);
	if (percent < 0) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm:rsm_attach not enough memory available to "
		    "export, or max-exported-memory set incorrectly.\n"));
		return (DDI_FAILURE);
	}
	/* 0 indicates no fixed upper limit. maxmem is the max	*/
	/* available pageable physical mem			*/
	rsm_pgcnt_max = (percent*maxmem)/100;

	if (rsm_pgcnt_max > 0) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm: Available physical memory = %lu pages, "
		    "Max exportable memory = %lu pages",
		    maxmem, rsm_pgcnt_max));
	}

	/*
	 * Create minor number
	 */
	if (rsmresource_alloc(&rnum) != RSM_SUCCESS) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm: rsm_attach - Unable to get "
		    "minor number\n"));
		return (DDI_FAILURE);
	}

	ASSERT(rnum == RSM_DRIVER_MINOR);

	if (ddi_create_minor_node(devi, DRIVER_NAME, S_IFCHR,
	    rnum, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm: rsm_attach - unable to allocate "
		    "minor #\n"));
		return (DDI_FAILURE);
	}

	rsm_dip = devi;
	/*
	 * Allocate the hashtables
	 */
	rsmhash_alloc(&rsm_export_segs, rsm_hash_size);
	rsmhash_alloc(&rsm_import_segs, rsm_hash_size);

	importer_list.bucket = (importing_token_t **)
	    kmem_zalloc(rsm_hash_size * sizeof (importing_token_t *), KM_SLEEP);

	/*
	 * Allocate a resource struct
	 */
	{
		rsmresource_t *p;

		p = (rsmresource_t *)kmem_zalloc(sizeof (*p), KM_SLEEP);

		mutex_init(&p->rsmrc_lock, NULL, MUTEX_DRIVER, (void *) NULL);

		rsmresource_insert(rnum, p, RSM_RESOURCE_BAR);
	}

	/*
	 * Based on the rsm.conf property max-segments, determine the maximum
	 * number of segments that can be exported/imported. This is then used
	 * to determine the size for barrier failure pages.
	 */

	/* First get the max number of segments from the rsm.conf file */
	max_segs = ddi_prop_get_int(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "max-segments", 0);
	if (max_segs == 0) {
		/* Use default number of segments */
		max_segs = RSM_MAX_NUM_SEG;
	}

	/*
	 * Based on the max number of segments allowed, determine the barrier
	 * page size. add 1 to max_segs since the barrier page itself uses
	 * a slot
	 */
	barrier_size = roundup((max_segs + 1) * sizeof (rsm_gnum_t),
	    PAGESIZE);

	/*
	 * allocation of the barrier failure page
	 */
	bar_va = (rsm_gnum_t *)ddi_umem_alloc(barrier_size,
	    DDI_UMEM_SLEEP, &bar_cookie);

	/*
	 * Set the barrier_offset
	 */
	barrier_offset = 0;

	/*
	 * Allocate a trash memory and get a cookie for it. This will be used
	 * when remapping segments during force disconnects. Allocate the
	 * trash memory with a large size which is page aligned.
	 */
	(void) ddi_umem_alloc((size_t)TRASHSIZE,
	    DDI_UMEM_TRASH, &remap_cookie);

	/* initialize user segment id allocation variable */
	rsm_nextavail_segmentid = (rsm_memseg_id_t)RSM_USER_APP_ID_BASE;

	/*
	 * initialize the null_rsmpi_ops vector and the loopback adapter
	 */
	rsmka_init_loopback();


	ddi_report_dev(devi);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_attach done\n"));

	return (DDI_SUCCESS);
}

/*
 * The call to mod_remove in the _fine routine will cause the system
 * to call rsm_detach
 */
/*ARGSUSED*/
static int
rsm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_detach enter\n"));

	switch (cmd) {
	case DDI_DETACH:
		break;
	default:
		DBG_PRINTF((category, RSM_ERR,
		    "rsm:rsm_detach - cmd %x not supported\n",
		    cmd));
		return (DDI_FAILURE);
	}

	mutex_enter(&rsm_drv_data.drv_lock);
	while (rsm_drv_data.drv_state != RSM_DRV_OK)
		cv_wait(&rsm_drv_data.drv_cv, &rsm_drv_data.drv_lock);
	rsm_drv_data.drv_state = RSM_DRV_UNREG_PROCESSING;
	mutex_exit(&rsm_drv_data.drv_lock);

	/*
	 * Unregister the DR callback functions
	 */
	if (rsm_enable_dr) {
#ifdef	RSM_DRTEST
		rsm_kphysm_setup_func_unregister(&rsm_dr_callback_vec,
		    (void *)NULL);
#else
		kphysm_setup_func_unregister(&rsm_dr_callback_vec,
		    (void *)NULL);
#endif
	}

	mutex_enter(&rsm_drv_data.drv_lock);
	ASSERT(rsm_drv_data.drv_state == RSM_DRV_UNREG_PROCESSING);
	rsm_drv_data.drv_state = RSM_DRV_NEW;
	mutex_exit(&rsm_drv_data.drv_lock);

	ASSERT(rsm_suspend_list.list_head == NULL);

	/*
	 * Release all resources, seglist, controller, ...
	 */

	/* remove intersend queues */
	/* remove registered services */


	ddi_remove_minor_node(dip, DRIVER_NAME);
	rsm_dip = NULL;

	/*
	 * Free minor zero resource
	 */
	{
		rsmresource_t *p;

		p = rsmresource_free(RSM_DRIVER_MINOR);
		if (p) {
			mutex_destroy(&p->rsmrc_lock);
			kmem_free((void *)p, sizeof (*p));
		}
	}

	/*
	 * Free resource table
	 */

	rsmresource_destroy();

	/*
	 * Free the hash tables
	 */
	rsmhash_free(&rsm_export_segs, rsm_hash_size);
	rsmhash_free(&rsm_import_segs, rsm_hash_size);

	kmem_free((void *)importer_list.bucket,
	    rsm_hash_size * sizeof (importing_token_t *));
	importer_list.bucket = NULL;


	/* free barrier page */
	if (bar_cookie != NULL) {
		ddi_umem_free(bar_cookie);
	}
	bar_va = NULL;
	bar_cookie = NULL;

	/*
	 * Free the memory allocated for the trash
	 */
	if (remap_cookie != NULL) {
		ddi_umem_free(remap_cookie);
	}
	remap_cookie = NULL;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_detach done\n"));

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
rsm_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	register int error;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_info enter\n"));

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (rsm_dip == NULL)
			error = DDI_FAILURE;
		else {
			*result = (void *)rsm_dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_info done\n"));
	return (error);
}

adapter_t *
rsm_getadapter(rsm_ioctlmsg_t *msg, int mode)
{
	adapter_t *adapter;
	char adapter_devname[MAXNAMELEN];
	int instance;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_IMPORT | RSM_EXPORT | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_getadapter enter\n"));

	instance = msg->cnum;

	if ((msg->cname_len <= 0) || (msg->cname_len > MAXNAMELEN)) {
		return (NULL);
	}

	if (ddi_copyin(msg->cname, adapter_devname, msg->cname_len, mode))
		return (NULL);

	if (strcmp(adapter_devname, "loopback") == 0)
		return (&loopback_adapter);

	adapter = rsmka_lookup_adapter(adapter_devname, instance);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_getadapter done\n"));

	return (adapter);
}


/*
 * *********************** Resource Number Management ********************
 * All resources are stored in a simple hash table. The table is an array
 * of pointers to resource blks. Each blk contains:
 *	base	- base number of this blk
 *	used	- number of used slots in this blk.
 *	blks    - array of pointers to resource items.
 * An entry in a resource blk is empty if it's NULL.
 *
 * We start with no resource array. Each time we run out of slots, we
 * reallocate a new larger array and copy the pointer to the new array and
 * a new resource blk is allocated and added to the hash table.
 *
 * The resource control block contains:
 *      root    - array of pointer of resource blks
 *      sz      - current size of array.
 *      len     - last valid entry in array.
 *
 * A search operation based on a resource number is as follows:
 *      index = rnum / RESOURCE_BLKSZ;
 *      ASSERT(index < resource_block.len);
 *      ASSERT(index < resource_block.sz);
 *	offset = rnum % RESOURCE_BLKSZ;
 *      ASSERT(offset >= resource_block.root[index]->base);
 *	ASSERT(offset < resource_block.root[index]->base + RESOURCE_BLKSZ);
 *	return resource_block.root[index]->blks[offset];
 *
 * A resource blk is freed with its used count reachs zero.
 */
static int
rsmresource_alloc(minor_t *rnum)
{

	/* search for available resource slot */
	int i, j, empty = -1;
	rsmresource_blk_t *blk;

	DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
	    "rsmresource_alloc enter\n"));

	rw_enter(&rsm_resource.rsmrc_lock, RW_WRITER);

	/* Try to find an empty slot */
	for (i = 0; i < rsm_resource.rsmrc_len; i++) {
		blk = rsm_resource.rsmrc_root[i];
		if (blk != NULL && blk->rsmrcblk_avail > 0) {
			/* found an empty slot in this blk */
			for (j = 0; j < RSMRC_BLKSZ; j++) {
				if (blk->rsmrcblk_blks[j] == NULL) {
					*rnum = (minor_t)
					    (j + (i * RSMRC_BLKSZ));
					/*
					 * obey gen page limits
					 */
					if (*rnum >= max_segs + 1) {
						if (empty < 0) {
							rw_exit(&rsm_resource.
							    rsmrc_lock);
							DBG_PRINTF((
							    RSM_KERNEL_ALL,
							    RSM_ERR,
							    "rsmresource"
							    "_alloc failed:"
							    "not enough res"
							    "%d\n", *rnum));
					return (RSMERR_INSUFFICIENT_RESOURCES);
						} else {
							/* use empty slot */
							break;
						}

					}

					blk->rsmrcblk_blks[j] = RSMRC_RESERVED;
					blk->rsmrcblk_avail--;
					rw_exit(&rsm_resource.rsmrc_lock);
					DBG_PRINTF((RSM_KERNEL_ALL,
					    RSM_DEBUG_VERBOSE,
					    "rsmresource_alloc done\n"));
					return (RSM_SUCCESS);
				}
			}
		} else if (blk == NULL && empty < 0) {
			/* remember first empty slot */
			empty = i;
		}
	}

	/* Couldn't find anything, allocate a new blk */
	/*
	 * Do we need to reallocate the root array
	 */
	if (empty < 0) {
		if (rsm_resource.rsmrc_len == rsm_resource.rsmrc_sz) {
			/*
			 * Allocate new array and copy current stuff into it
			 */
			rsmresource_blk_t	**p;
			uint_t newsz = (uint_t)rsm_resource.rsmrc_sz +
			    RSMRC_BLKSZ;
			/*
			 * Don't allocate more that max valid rnum
			 */
			if (rsm_resource.rsmrc_len*RSMRC_BLKSZ >=
			    max_segs + 1) {
				rw_exit(&rsm_resource.rsmrc_lock);
				return (RSMERR_INSUFFICIENT_RESOURCES);
			}

			p = (rsmresource_blk_t **)kmem_zalloc(
			    newsz * sizeof (*p),
			    KM_SLEEP);

			if (rsm_resource.rsmrc_root) {
				uint_t oldsz;

				oldsz = (uint_t)(rsm_resource.rsmrc_sz *
				    (int)sizeof (*p));

				/*
				 * Copy old data into new space and
				 * free old stuff
				 */
				bcopy(rsm_resource.rsmrc_root, p, oldsz);
				kmem_free(rsm_resource.rsmrc_root, oldsz);
			}

			rsm_resource.rsmrc_root = p;
			rsm_resource.rsmrc_sz = (int)newsz;
		}

		empty = rsm_resource.rsmrc_len;
		rsm_resource.rsmrc_len++;
	}

	/*
	 * Allocate a new blk
	 */
	blk = (rsmresource_blk_t *)kmem_zalloc(sizeof (*blk), KM_SLEEP);
	ASSERT(rsm_resource.rsmrc_root[empty] == NULL);
	rsm_resource.rsmrc_root[empty] = blk;
	blk->rsmrcblk_avail = RSMRC_BLKSZ - 1;

	/*
	 * Allocate slot
	 */

	*rnum = (minor_t)(empty * RSMRC_BLKSZ);

	/*
	 * watch out not to exceed bounds of barrier page
	 */
	if (*rnum >= max_segs + 1) {
		rw_exit(&rsm_resource.rsmrc_lock);
		DBG_PRINTF((RSM_KERNEL_ALL, RSM_ERR,
		    "rsmresource_alloc failed %d\n", *rnum));

		return (RSMERR_INSUFFICIENT_RESOURCES);
	}
	blk->rsmrcblk_blks[0] = RSMRC_RESERVED;


	rw_exit(&rsm_resource.rsmrc_lock);

	DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
	    "rsmresource_alloc done\n"));

	return (RSM_SUCCESS);
}

static rsmresource_t *
rsmresource_free(minor_t rnum)
{

	/* search for available resource slot */
	int i, j;
	rsmresource_blk_t *blk;
	rsmresource_t *p;

	DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
	    "rsmresource_free enter\n"));

	i = (int)(rnum / RSMRC_BLKSZ);
	j = (int)(rnum % RSMRC_BLKSZ);

	if (i >= rsm_resource.rsmrc_len) {
		DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
		    "rsmresource_free done\n"));
		return (NULL);
	}

	rw_enter(&rsm_resource.rsmrc_lock, RW_WRITER);

	ASSERT(rsm_resource.rsmrc_root);
	ASSERT(i < rsm_resource.rsmrc_len);
	ASSERT(i < rsm_resource.rsmrc_sz);
	blk = rsm_resource.rsmrc_root[i];
	if (blk == NULL) {
		rw_exit(&rsm_resource.rsmrc_lock);
		DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
		    "rsmresource_free done\n"));
		return (NULL);
	}

	ASSERT(blk->rsmrcblk_blks[j]); /* reserved or full */

	p = blk->rsmrcblk_blks[j];
	if (p == RSMRC_RESERVED) {
		p = NULL;
	}

	blk->rsmrcblk_blks[j] = NULL;
	blk->rsmrcblk_avail++;
	if (blk->rsmrcblk_avail == RSMRC_BLKSZ) {
		/* free this blk */
		kmem_free(blk, sizeof (*blk));
		rsm_resource.rsmrc_root[i] = NULL;
	}

	rw_exit(&rsm_resource.rsmrc_lock);

	DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
	    "rsmresource_free done\n"));

	return (p);
}

static rsmresource_t *
rsmresource_lookup(minor_t rnum, int lock)
{
	int i, j;
	rsmresource_blk_t *blk;
	rsmresource_t *p;

	DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
	    "rsmresource_lookup enter\n"));

	/* Find resource and lock it in READER mode */
	/* search for available resource slot */

	i = (int)(rnum / RSMRC_BLKSZ);
	j = (int)(rnum % RSMRC_BLKSZ);

	if (i >= rsm_resource.rsmrc_len) {
		DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
		    "rsmresource_lookup done\n"));
		return (NULL);
	}

	rw_enter(&rsm_resource.rsmrc_lock, RW_READER);

	blk = rsm_resource.rsmrc_root[i];
	if (blk != NULL) {
		ASSERT(i < rsm_resource.rsmrc_len);
		ASSERT(i < rsm_resource.rsmrc_sz);

		p = blk->rsmrcblk_blks[j];
		if (lock == RSM_LOCK) {
			if (p != RSMRC_RESERVED) {
				mutex_enter(&p->rsmrc_lock);
			} else {
				p = NULL;
			}
		}
	} else {
		p = NULL;
	}
	rw_exit(&rsm_resource.rsmrc_lock);

	DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
	    "rsmresource_lookup done\n"));

	return (p);
}

static void
rsmresource_insert(minor_t rnum, rsmresource_t *p, rsm_resource_type_t type)
{
	/* Find resource and lock it in READER mode */
	/* Caller can upgrade if need be */
	/* search for available resource slot */
	int i, j;
	rsmresource_blk_t *blk;

	DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
	    "rsmresource_insert enter\n"));

	i = (int)(rnum / RSMRC_BLKSZ);
	j = (int)(rnum % RSMRC_BLKSZ);

	p->rsmrc_type = type;
	p->rsmrc_num = rnum;

	rw_enter(&rsm_resource.rsmrc_lock, RW_READER);

	ASSERT(rsm_resource.rsmrc_root);
	ASSERT(i < rsm_resource.rsmrc_len);
	ASSERT(i < rsm_resource.rsmrc_sz);

	blk = rsm_resource.rsmrc_root[i];
	ASSERT(blk);

	ASSERT(blk->rsmrcblk_blks[j] == RSMRC_RESERVED);

	blk->rsmrcblk_blks[j] = p;

	DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
	    "rsmresource_insert done\n"));

	rw_exit(&rsm_resource.rsmrc_lock);
}

static void
rsmresource_destroy()
{
	int i, j;

	DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
	    "rsmresource_destroy enter\n"));

	rw_enter(&rsm_resource.rsmrc_lock, RW_WRITER);

	for (i = 0; i < rsm_resource.rsmrc_len; i++) {
		rsmresource_blk_t	*blk;

		blk = rsm_resource.rsmrc_root[i];
		if (blk == NULL) {
			continue;
		}
		for (j = 0; j < RSMRC_BLKSZ; j++) {
			if (blk->rsmrcblk_blks[j] != NULL) {
				DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
				    "Not null slot %d, %lx\n", j,
				    (size_t)blk->rsmrcblk_blks[j]));
			}
		}
		kmem_free(blk, sizeof (*blk));
		rsm_resource.rsmrc_root[i] = NULL;
	}
	if (rsm_resource.rsmrc_root) {
		i = rsm_resource.rsmrc_sz * (int)sizeof (rsmresource_blk_t *);
		kmem_free(rsm_resource.rsmrc_root, (uint_t)i);
		rsm_resource.rsmrc_root = NULL;
		rsm_resource.rsmrc_len = 0;
		rsm_resource.rsmrc_sz = 0;
	}

	DBG_PRINTF((RSM_KERNEL_ALL, RSM_DEBUG_VERBOSE,
	    "rsmresource_destroy done\n"));

	rw_exit(&rsm_resource.rsmrc_lock);
}


/* ******************** Generic Key Hash Table Management ********* */
static rsmresource_t *
rsmhash_lookup(rsmhash_table_t *rhash, rsm_memseg_id_t key,
    rsm_resource_state_t state)
{
	rsmresource_t	*p;
	uint_t		hashval;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmhash_lookup enter\n"));

	hashval = rsmhash(key);

	DBG_PRINTF((category, RSM_DEBUG_LVL2, "rsmhash_lookup %u=%d\n",
	    key, hashval));

	rw_enter(&rhash->rsmhash_rw, RW_READER);

	p = (rsmresource_t *)rsmhash_getbkt(rhash, hashval);

	for (; p; p = p->rsmrc_next) {
		if (p->rsmrc_key == key) {
			/* acquire resource lock */
			RSMRC_LOCK(p);
			break;
		}
	}

	rw_exit(&rhash->rsmhash_rw);

	if (p != NULL && p->rsmrc_state != state) {
		/* state changed, release lock and return null */
		RSMRC_UNLOCK(p);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmhash_lookup done: state changed\n"));
		return (NULL);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmhash_lookup done\n"));

	return (p);
}

static void
rsmhash_rm(rsmhash_table_t *rhash, rsmresource_t *rcelm)
{
	rsmresource_t		*p, **back;
	uint_t			hashval;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmhash_rm enter\n"));

	hashval = rsmhash(rcelm->rsmrc_key);

	DBG_PRINTF((category, RSM_DEBUG_LVL2, "rsmhash_rm %u=%d\n",
	    rcelm->rsmrc_key, hashval));

	/*
	 * It's ok not to find the segment.
	 */
	rw_enter(&rhash->rsmhash_rw, RW_WRITER);

	back = (rsmresource_t **)rsmhash_bktaddr(rhash, hashval);

	for (; (p = *back) != NULL;  back = &p->rsmrc_next) {
		if (p == rcelm) {
			*back = rcelm->rsmrc_next;
			break;
		}
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmhash_rm done\n"));

	rw_exit(&rhash->rsmhash_rw);
}

static int
rsmhash_add(rsmhash_table_t *rhash, rsmresource_t *new, rsm_memseg_id_t key,
    int dup_check, rsm_resource_state_t state)
{
	rsmresource_t	*p = NULL, **bktp;
	uint_t		hashval;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmhash_add enter\n"));

	/* lock table */
	rw_enter(&rhash->rsmhash_rw, RW_WRITER);

	/*
	 * If the current resource state is other than the state passed in
	 * then the resource is (probably) already on the list. eg. for an
	 * import segment if the state is not RSM_STATE_NEW then it's on the
	 * list already.
	 */
	RSMRC_LOCK(new);
	if (new->rsmrc_state != state) {
		RSMRC_UNLOCK(new);
		rw_exit(&rhash->rsmhash_rw);
		return (RSMERR_BAD_SEG_HNDL);
	}

	hashval = rsmhash(key);
	DBG_PRINTF((category, RSM_DEBUG_LVL2, "rsmhash_add %d\n", hashval));

	if (dup_check) {
		/*
		 * Used for checking export segments; don't want to have
		 * the same key used for multiple segments.
		 */

		p = (rsmresource_t *)rsmhash_getbkt(rhash, hashval);

		for (; p; p = p->rsmrc_next) {
			if (p->rsmrc_key == key) {
				RSMRC_UNLOCK(new);
				break;
			}
		}
	}

	if (p == NULL) {
		/* Key doesn't exist, add it */

		bktp = (rsmresource_t **)rsmhash_bktaddr(rhash, hashval);

		new->rsmrc_key = key;
		new->rsmrc_next = *bktp;
		*bktp = new;
	}

	rw_exit(&rhash->rsmhash_rw);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmhash_add done\n"));

	return (p == NULL ? RSM_SUCCESS : RSMERR_SEGID_IN_USE);
}

/*
 * XOR each byte of the key.
 */
static uint_t
rsmhash(rsm_memseg_id_t key)
{
	uint_t	hash = key;

	hash ^=  (key >> 8);
	hash ^=  (key >> 16);
	hash ^=  (key >> 24);

	return (hash % rsm_hash_size);

}

/*
 * generic function to get a specific bucket
 */
static void *
rsmhash_getbkt(rsmhash_table_t *rhash, uint_t hashval)
{

	if (rhash->bucket == NULL)
		return (NULL);
	else
		return ((void *)rhash->bucket[hashval]);
}

/*
 * generic function to get a specific bucket's address
 */
static void **
rsmhash_bktaddr(rsmhash_table_t *rhash, uint_t hashval)
{
	if (rhash->bucket == NULL)
		return (NULL);
	else
		return ((void **)&(rhash->bucket[hashval]));
}

/*
 * generic function to alloc a hash table
 */
static void
rsmhash_alloc(rsmhash_table_t *rhash, int size)
{
	rhash->bucket = (rsmresource_t **)
	    kmem_zalloc(size * sizeof (rsmresource_t *), KM_SLEEP);
}

/*
 * generic function to free a hash table
 */
static void
rsmhash_free(rsmhash_table_t *rhash, int size)
{

	kmem_free((void *)rhash->bucket, size * sizeof (caddr_t));
	rhash->bucket = NULL;

}
/* *********************** Exported Segment Key Management ************ */

#define	rsmexport_add(new, key)		\
	rsmhash_add(&rsm_export_segs, (rsmresource_t *)new, key, 1, \
	    RSM_STATE_BIND)

#define	rsmexport_rm(arg)	\
	rsmhash_rm(&rsm_export_segs, (rsmresource_t *)(arg))

#define	rsmexport_lookup(key)	\
	(rsmseg_t *)rsmhash_lookup(&rsm_export_segs, key, RSM_STATE_EXPORT)

/* ************************** Import Segment List Management ********** */

/*
 *  Add segment to import list. This will be useful for paging and loopback
 * segment unloading.
 */
#define	rsmimport_add(arg, key)	\
	rsmhash_add(&rsm_import_segs, (rsmresource_t *)(arg), (key), 0, \
	    RSM_STATE_NEW)

#define	rsmimport_rm(arg)	\
	rsmhash_rm(&rsm_import_segs, (rsmresource_t *)(arg))

/*
 *	#define	rsmimport_lookup(key)	\
 *	(rsmseg_t *)rsmhash_lookup(&rsm_import_segs, (key), RSM_STATE_CONNECT)
 */

/*
 * increase the ref count and make the import segment point to the
 * shared data structure. Return a pointer to the share data struct
 * and the shared data struct is locked upon return
 */
static rsm_import_share_t *
rsmshare_get(rsm_memseg_id_t key, rsm_node_id_t node, adapter_t *adapter,
    rsmseg_t *segp)
{
	uint_t		hash;
	rsmresource_t		*p;
	rsm_import_share_t	*shdatap;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmshare_get enter\n"));

	hash = rsmhash(key);
	/* lock table */
	rw_enter(&rsm_import_segs.rsmhash_rw, RW_WRITER);
	DBG_PRINTF((category, RSM_DEBUG_LVL2, "rsmshare_get:key=%u, hash=%d\n",
	    key, hash));

	p = (rsmresource_t *)rsmhash_getbkt(&rsm_import_segs, hash);

	for (; p; p = p->rsmrc_next) {
		/*
		 * Look for an entry that is importing the same exporter
		 * with the share data structure allocated.
		 */
		if ((p->rsmrc_key == key) &&
		    (p->rsmrc_node == node) &&
		    (p->rsmrc_adapter == adapter) &&
		    (((rsmseg_t *)p)->s_share != NULL)) {
			shdatap = ((rsmseg_t *)p)->s_share;
			break;
		}
	}

	if (p == NULL) {
		/* we are the first importer, create the shared data struct */
		shdatap = kmem_zalloc(sizeof (rsm_import_share_t), KM_SLEEP);
		shdatap->rsmsi_state = RSMSI_STATE_NEW;
		shdatap->rsmsi_segid = key;
		shdatap->rsmsi_node = node;
		mutex_init(&shdatap->rsmsi_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&shdatap->rsmsi_cv, NULL, CV_DRIVER, 0);
	}

	rsmseglock_acquire(segp);

	/* we grab the shared lock before returning from this function */
	mutex_enter(&shdatap->rsmsi_lock);

	shdatap->rsmsi_refcnt++;
	segp->s_share = shdatap;

	rsmseglock_release(segp);

	rw_exit(&rsm_import_segs.rsmhash_rw);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmshare_get done\n"));

	return (shdatap);
}

/*
 * the shared data structure should be locked before calling
 * rsmsharecv_signal().
 * Change the state and signal any waiting segments.
 */
void
rsmsharecv_signal(rsmseg_t *seg, int oldstate, int newstate)
{
	ASSERT(rsmsharelock_held(seg));

	if (seg->s_share->rsmsi_state == oldstate) {
		seg->s_share->rsmsi_state = newstate;
		cv_broadcast(&seg->s_share->rsmsi_cv);
	}
}

/*
 * Add to the hash table
 */
static void
importer_list_add(rsm_node_id_t node, rsm_memseg_id_t key, rsm_addr_t hwaddr,
    void *cookie)
{

	importing_token_t	*head;
	importing_token_t	*new_token;
	int			index;

	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "importer_list_add enter\n"));

	new_token = kmem_zalloc(sizeof (importing_token_t), KM_SLEEP);
	new_token->importing_node = node;
	new_token->key = key;
	new_token->import_segment_cookie = cookie;
	new_token->importing_adapter_hwaddr = hwaddr;

	index = rsmhash(key);

	mutex_enter(&importer_list.lock);

	head = importer_list.bucket[index];
	importer_list.bucket[index] = new_token;
	new_token->next = head;
	mutex_exit(&importer_list.lock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "importer_list_add done\n"));
}

static void
importer_list_rm(rsm_node_id_t node,  rsm_memseg_id_t key, void *cookie)
{

	importing_token_t	*prev, *token = NULL;
	int			index;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "importer_list_rm enter\n"));

	index = rsmhash(key);

	mutex_enter(&importer_list.lock);

	token = importer_list.bucket[index];

	prev = token;
	while (token != NULL) {
		if (token->importing_node == node &&
		    token->import_segment_cookie == cookie) {
			if (prev == token)
				importer_list.bucket[index] = token->next;
			else
				prev->next = token->next;
			kmem_free((void *)token, sizeof (*token));
			break;
		} else {
			prev = token;
			token = token->next;
		}
	}

	mutex_exit(&importer_list.lock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "importer_list_rm done\n"));


}

/* **************************Segment Structure Management ************* */

/*
 * Free segment structure
 */
static void
rsmseg_free(rsmseg_t *seg)
{

	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmseg_free enter\n"));

	/* need to take seglock here to avoid race with rsmmap_unmap() */
	rsmseglock_acquire(seg);
	if (seg->s_ckl != NULL) {
		/* Segment is still busy */
		seg->s_state = RSM_STATE_END;
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmseg_free done\n"));
		return;
	}

	rsmseglock_release(seg);

	ASSERT(seg->s_state == RSM_STATE_END || seg->s_state == RSM_STATE_NEW);

	/*
	 * If it's an importer decrement the refcount
	 * and if its down to zero free the shared data structure.
	 * This is where failures during rsm_connect() are unrefcounted
	 */
	if (seg->s_share != NULL) {

		ASSERT(seg->s_type == RSM_RESOURCE_IMPORT_SEGMENT);

		rsmsharelock_acquire(seg);

		ASSERT(seg->s_share->rsmsi_refcnt > 0);

		seg->s_share->rsmsi_refcnt--;

		if (seg->s_share->rsmsi_refcnt == 0) {
			rsmsharelock_release(seg);
			mutex_destroy(&seg->s_share->rsmsi_lock);
			cv_destroy(&seg->s_share->rsmsi_cv);
			kmem_free((void *)(seg->s_share),
			    sizeof (rsm_import_share_t));
		} else {
			rsmsharelock_release(seg);
		}
		/*
		 * The following needs to be done after any
		 * rsmsharelock calls which use seg->s_share.
		 */
		seg->s_share = NULL;
	}

	cv_destroy(&seg->s_cv);
	mutex_destroy(&seg->s_lock);
	rsmacl_free(seg->s_acl, seg->s_acl_len);
	rsmpiacl_free(seg->s_acl_in, seg->s_acl_len);
	if (seg->s_adapter)
		rsmka_release_adapter(seg->s_adapter);

	kmem_free((void *)seg, sizeof (*seg));

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmseg_free done\n"));

}


static rsmseg_t *
rsmseg_alloc(minor_t num, struct cred *cred)
{
	rsmseg_t	*new;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmseg_alloc enter\n"));
	/*
	 * allocate memory for new segment. This should be a segkmem cache.
	 */
	new = (rsmseg_t *)kmem_zalloc(sizeof (*new), KM_SLEEP);

	new->s_state = RSM_STATE_NEW;
	new->s_minor	= num;
	new->s_acl_len	= 0;
	new->s_cookie = NULL;
	new->s_adapter = NULL;

	new->s_mode = 0777 & ~PTOU((ttoproc(curthread)))->u_cmask;
	/* we don't have a key yet, will set at export/connect */
	new->s_uid  = crgetuid(cred);
	new->s_gid  = crgetgid(cred);

	mutex_init(&new->s_lock, NULL, MUTEX_DRIVER, (void *)NULL);
	cv_init(&new->s_cv, NULL, CV_DRIVER, 0);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmseg_alloc done\n"));

	return (new);
}

/* ******************************** Driver Open/Close/Poll *************** */

/*ARGSUSED1*/
static int
rsm_open(dev_t *devp, int flag, int otyp, struct cred *cred)
{
	minor_t rnum;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL| RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_open enter\n"));
	/*
	 * Char only
	 */
	if (otyp != OTYP_CHR) {
		DBG_PRINTF((category, RSM_ERR, "rsm_open: bad otyp\n"));
		return (EINVAL);
	}

	/*
	 * Only zero can be opened, clones are used for resources.
	 */
	if (getminor(*devp) != RSM_DRIVER_MINOR) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_open: bad minor %d\n", getminor(*devp)));
		return (ENODEV);
	}

	if ((flag & FEXCL) != 0 && secpolicy_excl_open(cred) != 0) {
		DBG_PRINTF((category, RSM_ERR, "rsm_open: bad perm\n"));
		return (EPERM);
	}

	if (!(flag & FWRITE)) {
		/*
		 * The library function _rsm_librsm_init calls open for
		 * /dev/rsm with flag set to O_RDONLY.  We want a valid
		 * file descriptor to be returned for minor device zero.
		 */

		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_open RDONLY done\n"));
		return (DDI_SUCCESS);
	}

	/*
	 * - allocate new minor number and segment.
	 * - add segment to list of all segments.
	 * - set minordev data to segment
	 * - update devp argument to new device
	 * - update s_cred to cred; make sure you do crhold(cred);
	 */

	/* allocate a new resource number */
	if (rsmresource_alloc(&rnum) == RSM_SUCCESS) {
		/*
		 * We will bind this minor to a specific resource in first
		 * ioctl
		 */
		*devp = makedevice(getmajor(*devp), rnum);
	} else {
		return (EAGAIN);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_open done\n"));
	return (DDI_SUCCESS);
}

static void
rsmseg_close(rsmseg_t *seg, int force_flag)
{
	int e = RSM_SUCCESS;

	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL| RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmseg_close enter\n"));

	rsmseglock_acquire(seg);
	if (!force_flag && (seg->s_hdr.rsmrc_type ==
	    RSM_RESOURCE_EXPORT_SEGMENT)) {
		/*
		 * If we are processing rsm_close wait for force_destroy
		 * processing to complete since force_destroy processing
		 * needs to finish first before we can free the segment.
		 * force_destroy is only for export segments
		 */
		while (seg->s_flags & RSM_FORCE_DESTROY_WAIT) {
			cv_wait(&seg->s_cv, &seg->s_lock);
		}
	}
	rsmseglock_release(seg);

	/* It's ok to read the state without a lock */
	switch (seg->s_state) {
	case RSM_STATE_EXPORT:
	case RSM_STATE_EXPORT_QUIESCING:
	case RSM_STATE_EXPORT_QUIESCED:
		e = rsm_unpublish(seg, 1);
		/* FALLTHRU */
	case RSM_STATE_BIND_QUIESCED:
		/* FALLTHRU */
	case RSM_STATE_BIND:
		e = rsm_unbind(seg);
		if (e != RSM_SUCCESS && force_flag == 1)
			return;
		ASSERT(seg->s_hdr.rsmrc_type == RSM_RESOURCE_EXPORT_SEGMENT);
		/* FALLTHRU */
	case RSM_STATE_NEW_QUIESCED:
		rsmseglock_acquire(seg);
		seg->s_state = RSM_STATE_NEW;
		cv_broadcast(&seg->s_cv);
		rsmseglock_release(seg);
		break;
	case RSM_STATE_NEW:
		break;
	case RSM_STATE_ZOMBIE:
		/*
		 * Segments in this state have been removed off the
		 * exported segments list and have been unpublished
		 * and unbind. These segments have been removed during
		 * a callback to the rsm_export_force_destroy, which
		 * is called for the purpose of unlocking these
		 * exported memory segments when a process exits but
		 * leaves the segments locked down since rsm_close is
		 * is not called for the segments. This can happen
		 * when a process calls fork or exec and then exits.
		 * Once the segments are in the ZOMBIE state, all that
		 * remains is to destroy them when rsm_close is called.
		 * This is done here. Thus, for such segments the
		 * the state is changed to new so that later in this
		 * function rsmseg_free is called.
		 */
		rsmseglock_acquire(seg);
		seg->s_state = RSM_STATE_NEW;
		rsmseglock_release(seg);
		break;
	case RSM_STATE_MAP_QUIESCE:
	case RSM_STATE_ACTIVE:
		/* Disconnect will handle the unmap */
	case RSM_STATE_CONN_QUIESCE:
	case RSM_STATE_CONNECT:
	case RSM_STATE_DISCONNECT:
		ASSERT(seg->s_hdr.rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT);
		(void) rsm_disconnect(seg);
		break;
	case RSM_STATE_MAPPING:
		/*FALLTHRU*/
	case RSM_STATE_END:
		DBG_PRINTF((category, RSM_ERR,
		    "Invalid segment state %d in rsm_close\n", seg->s_state));
		break;
	default:
		DBG_PRINTF((category, RSM_ERR,
		    "Invalid segment state %d in rsm_close\n", seg->s_state));
		break;
	}

	/*
	 * check state.
	 * - make sure you do crfree(s_cred);
	 * release segment and minor number
	 */
	ASSERT(seg->s_state == RSM_STATE_NEW);

	/*
	 * The export_force_destroy callback is created to unlock
	 * the exported segments of a process
	 * when the process does a fork or exec and then exits calls this
	 * function with the force flag set to 1 which indicates that the
	 * segment state must be converted to ZOMBIE. This state means that the
	 * segments still exist and have been unlocked and most importantly the
	 * only operation allowed is to destroy them on an rsm_close.
	 */
	if (force_flag) {
		rsmseglock_acquire(seg);
		seg->s_state = RSM_STATE_ZOMBIE;
		rsmseglock_release(seg);
	} else {
		rsmseg_free(seg);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmseg_close done\n"));
}

static int
rsm_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	minor_t	rnum = getminor(dev);
	rsmresource_t *res;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL| RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_close enter\n"));

	flag = flag; cred = cred;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rnum = %d\n", rnum));

	/*
	 * At this point we are the last reference to the resource.
	 * Free resource number from resource table.
	 * It's ok to remove number before we free the segment.
	 * We need to lock the resource to protect against remote calls.
	 */
	if (rnum == RSM_DRIVER_MINOR ||
	    (res = rsmresource_free(rnum)) == NULL) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_close done\n"));
		return (DDI_SUCCESS);
	}

	switch (res->rsmrc_type) {
	case RSM_RESOURCE_EXPORT_SEGMENT:
	case RSM_RESOURCE_IMPORT_SEGMENT:
		rsmseg_close((rsmseg_t *)res, 0);
		break;
	case RSM_RESOURCE_BAR:
		DBG_PRINTF((category, RSM_ERR, "bad resource in rsm_close\n"));
		break;
	default:
		break;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_close done\n"));

	return (DDI_SUCCESS);
}

/*
 * rsm_inc_pgcnt
 *
 * Description: increment rsm page counter.
 *
 * Parameters:	pgcnt_t	pnum;	number of pages to be used
 *
 * Returns:	RSM_SUCCESS	if memory limit not exceeded
 *		ENOSPC		if memory limit exceeded. In this case, the
 *				page counter remains unchanged.
 *
 */
static int
rsm_inc_pgcnt(pgcnt_t pnum)
{
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);
	if (rsm_pgcnt_max == 0) { /* no upper limit has been set */
		return (RSM_SUCCESS);
	}

	mutex_enter(&rsm_pgcnt_lock);

	if (rsm_pgcnt + pnum > rsm_pgcnt_max) {
		/* ensure that limits have not been exceeded */
		mutex_exit(&rsm_pgcnt_lock);
		return (RSMERR_INSUFFICIENT_MEM);
	}

	rsm_pgcnt += pnum;
	DBG_PRINTF((category, RSM_DEBUG, "rsm_pgcnt incr to %d.\n",
	    rsm_pgcnt));
	mutex_exit(&rsm_pgcnt_lock);

	return (RSM_SUCCESS);
}

/*
 * rsm_dec_pgcnt
 *
 * Description:	decrement rsm page counter.
 *
 * Parameters:	pgcnt_t	pnum;	number of pages freed
 *
 */
static void
rsm_dec_pgcnt(pgcnt_t pnum)
{
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	if (rsm_pgcnt_max == 0) { /* no upper limit has been set */
		return;
	}

	mutex_enter(&rsm_pgcnt_lock);
	ASSERT(rsm_pgcnt >= pnum);
	rsm_pgcnt -= pnum;
	DBG_PRINTF((category, RSM_DEBUG, "rsm_pgcnt decr to %d.\n",
	    rsm_pgcnt));
	mutex_exit(&rsm_pgcnt_lock);
}

static struct umem_callback_ops rsm_as_ops = {
	UMEM_CALLBACK_VERSION, /* version number */
	rsm_export_force_destroy,
};

static int
rsm_bind_pages(ddi_umem_cookie_t *cookie, caddr_t vaddr, size_t len,
    proc_t *procp)
{
	int error = RSM_SUCCESS;
	ulong_t pnum;
	struct umem_callback_ops *callbackops = &rsm_as_ops;

	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_bind_pages enter\n"));

	/*
	 * Make sure vaddr and len are aligned on a page boundary
	 */
	if ((uintptr_t)vaddr & (PAGESIZE - 1)) {
		return (RSMERR_BAD_ADDR);
	}

	if (len & (PAGESIZE - 1)) {
		return (RSMERR_BAD_LENGTH);
	}

	/*
	 * Find number of pages
	 */
	pnum = btopr(len);
	error = rsm_inc_pgcnt(pnum);
	if (error != RSM_SUCCESS) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_bind_pages:mem limit exceeded\n"));
		return (RSMERR_INSUFFICIENT_MEM);
	}

	error = umem_lockmemory(vaddr, len,
	    DDI_UMEMLOCK_WRITE|DDI_UMEMLOCK_READ|DDI_UMEMLOCK_LONGTERM,
	    cookie,
	    callbackops, procp);

	if (error) {
		rsm_dec_pgcnt(pnum);
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_bind_pages:ddi_umem_lock failed\n"));
		/*
		 * ddi_umem_lock, in the case of failure, returns one of
		 * the following three errors. These are translated into
		 * the RSMERR namespace and returned.
		 */
		if (error == EFAULT)
			return (RSMERR_BAD_ADDR);
		else if (error == EACCES)
			return (RSMERR_PERM_DENIED);
		else
			return (RSMERR_INSUFFICIENT_MEM);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_bind_pages done\n"));

	return (error);

}

static int
rsm_unbind_pages(rsmseg_t *seg)
{
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_unbind_pages enter\n"));

	ASSERT(rsmseglock_held(seg));

	if (seg->s_cookie != NULL) {
		/* unlock address range */
		ddi_umem_unlock(seg->s_cookie);
		rsm_dec_pgcnt(btopr(seg->s_len));
		seg->s_cookie = NULL;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_unbind_pages done\n"));

	return (RSM_SUCCESS);
}


static int
rsm_bind(rsmseg_t *seg, rsm_ioctlmsg_t *msg, intptr_t dataptr, int mode)
{
	int e;
	adapter_t *adapter;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_bind enter\n"));

	adapter = rsm_getadapter(msg, mode);
	if (adapter == NULL) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_bind done:no adapter\n"));
		return (RSMERR_CTLR_NOT_PRESENT);
	}

	/* lock address range */
	if (msg->vaddr == NULL) {
		rsmka_release_adapter(adapter);
		DBG_PRINTF((category, RSM_ERR,
		    "rsm: rsm_bind done: invalid vaddr\n"));
		return (RSMERR_BAD_ADDR);
	}
	if (msg->len <= 0) {
		rsmka_release_adapter(adapter);
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_bind: invalid length\n"));
		return (RSMERR_BAD_LENGTH);
	}

	/* Lock segment */
	rsmseglock_acquire(seg);

	while (seg->s_state == RSM_STATE_NEW_QUIESCED) {
		if (cv_wait_sig(&seg->s_cv, &seg->s_lock) == 0) {
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsm_bind done: cv_wait INTERRUPTED"));
			rsmka_release_adapter(adapter);
			rsmseglock_release(seg);
			return (RSMERR_INTERRUPTED);
		}
	}

	ASSERT(seg->s_state == RSM_STATE_NEW);

	ASSERT(seg->s_cookie == NULL);

	e = rsm_bind_pages(&seg->s_cookie, msg->vaddr, msg->len, curproc);
	if (e == RSM_SUCCESS) {
		seg->s_flags |= RSM_USER_MEMORY;
		if (msg->perm & RSM_ALLOW_REBIND) {
			seg->s_flags |= RSMKA_ALLOW_UNBIND_REBIND;
		}
		if (msg->perm & RSM_CREATE_SEG_DONTWAIT) {
			seg->s_flags |= RSMKA_SET_RESOURCE_DONTWAIT;
		}
		seg->s_region.r_vaddr = msg->vaddr;
		/*
		 * Set the s_pid value in the segment structure. This is used
		 * to identify exported segments belonging to a particular
		 * process so that when the process exits, these segments can
		 * be unlocked forcefully even if rsm_close is not called on
		 * process exit since there maybe other processes referencing
		 * them (for example on a fork or exec).
		 * The s_pid value is also used to authenticate the process
		 * doing a publish or unpublish on the export segment. Only
		 * the creator of the export segment has a right to do a
		 * publish or unpublish and unbind on the segment.
		 */
		seg->s_pid = ddi_get_pid();
		seg->s_len = msg->len;
		seg->s_state = RSM_STATE_BIND;
		seg->s_adapter = adapter;
		seg->s_proc = curproc;
	} else {
		rsmka_release_adapter(adapter);
		DBG_PRINTF((category, RSM_WARNING,
		    "unable to lock down pages\n"));
	}

	msg->rnum = seg->s_minor;
	/* Unlock segment */
	rsmseglock_release(seg);

	if (e == RSM_SUCCESS) {
		/* copyout the resource number */
#ifdef _MULTI_DATAMODEL
		if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
			rsm_ioctlmsg32_t msg32;

			msg32.rnum = msg->rnum;
			if (ddi_copyout((caddr_t)&msg32.rnum,
			    (caddr_t)&((rsm_ioctlmsg32_t *)dataptr)->rnum,
			    sizeof (minor_t), mode)) {
				rsmka_release_adapter(adapter);
				e = RSMERR_BAD_ADDR;
			}
		}
#endif
		if (ddi_copyout((caddr_t)&msg->rnum,
		    (caddr_t)&((rsm_ioctlmsg_t *)dataptr)->rnum,
		    sizeof (minor_t), mode)) {
			rsmka_release_adapter(adapter);
			e = RSMERR_BAD_ADDR;
		}
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_bind done\n"));

	return (e);
}

static void
rsm_remap_local_importers(rsm_node_id_t src_nodeid,
    rsm_memseg_id_t ex_segid,
    ddi_umem_cookie_t cookie)

{
	rsmresource_t	*p = NULL;
	rsmhash_table_t *rhash = &rsm_import_segs;
	uint_t		index;

	DBG_PRINTF((RSM_KERNEL_AGENT | RSM_FUNC_ALL, RSM_DEBUG_VERBOSE,
	    "rsm_remap_local_importers enter\n"));

	index = rsmhash(ex_segid);

	rw_enter(&rhash->rsmhash_rw, RW_READER);

	p = rsmhash_getbkt(rhash, index);

	for (; p; p = p->rsmrc_next) {
		rsmseg_t *seg = (rsmseg_t *)p;
		rsmseglock_acquire(seg);
		/*
		 * Change the s_cookie value of only the local importers
		 * which have been mapped (in state RSM_STATE_ACTIVE).
		 * Note that there is no need to change the s_cookie value
		 * if the imported segment is in RSM_STATE_MAPPING since
		 * eventually the s_cookie will be updated via the mapping
		 * functionality.
		 */
		if ((seg->s_segid == ex_segid) && (seg->s_node == src_nodeid) &&
		    (seg->s_state == RSM_STATE_ACTIVE)) {
			seg->s_cookie = cookie;
		}
		rsmseglock_release(seg);
	}
	rw_exit(&rhash->rsmhash_rw);

	DBG_PRINTF((RSM_KERNEL_AGENT | RSM_FUNC_ALL, RSM_DEBUG_VERBOSE,
	    "rsm_remap_local_importers done\n"));
}

static int
rsm_rebind(rsmseg_t *seg, rsm_ioctlmsg_t *msg)
{
	int e;
	adapter_t *adapter;
	ddi_umem_cookie_t cookie;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_rebind enter\n"));

	/* Check for permissions to rebind */
	if (!(seg->s_flags & RSMKA_ALLOW_UNBIND_REBIND)) {
		return (RSMERR_REBIND_NOT_ALLOWED);
	}

	if (seg->s_pid != ddi_get_pid() &&
	    ddi_get_pid() != 0) {
		DBG_PRINTF((category, RSM_ERR, "rsm_rebind: Not owner\n"));
		return (RSMERR_NOT_CREATOR);
	}

	/*
	 * We will not be allowing partial rebind and hence length passed
	 * in must be same as segment length
	 */
	if (msg->vaddr == NULL) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_rebind done: null msg->vaddr\n"));
		return (RSMERR_BAD_ADDR);
	}
	if (msg->len != seg->s_len) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_rebind: invalid length\n"));
		return (RSMERR_BAD_LENGTH);
	}

	/* Lock segment */
	rsmseglock_acquire(seg);

	while ((seg->s_state == RSM_STATE_BIND_QUIESCED) ||
	    (seg->s_state == RSM_STATE_EXPORT_QUIESCING) ||
	    (seg->s_state == RSM_STATE_EXPORT_QUIESCED)) {
		if (cv_wait_sig(&seg->s_cv, &seg->s_lock) == 0) {
			rsmseglock_release(seg);
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsm_rebind done: cv_wait INTERRUPTED"));
			return (RSMERR_INTERRUPTED);
		}
	}

	/* verify segment state */
	if ((seg->s_state != RSM_STATE_BIND) &&
	    (seg->s_state != RSM_STATE_EXPORT)) {
		/* Unlock segment */
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_rebind done: invalid state\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	ASSERT(seg->s_cookie != NULL);

	if (msg->vaddr == seg->s_region.r_vaddr) {
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_rebind done\n"));
		return (RSM_SUCCESS);
	}

	e = rsm_bind_pages(&cookie, msg->vaddr, msg->len, curproc);
	if (e == RSM_SUCCESS) {
		struct buf *xbuf;
		dev_t sdev = 0;
		rsm_memory_local_t mem;

		xbuf = ddi_umem_iosetup(cookie, 0, msg->len, B_WRITE,
		    sdev, 0, NULL, DDI_UMEM_SLEEP);
		ASSERT(xbuf != NULL);

		mem.ms_type = RSM_MEM_BUF;
		mem.ms_bp = xbuf;

		adapter = seg->s_adapter;
		e = adapter->rsmpi_ops->rsm_rebind(
		    seg->s_handle.out, 0, &mem,
		    RSM_RESOURCE_DONTWAIT, NULL);

		if (e == RSM_SUCCESS) {
			/*
			 * unbind the older pages, and unload local importers;
			 * but don't disconnect importers
			 */
			(void) rsm_unbind_pages(seg);
			seg->s_cookie = cookie;
			seg->s_region.r_vaddr = msg->vaddr;
			rsm_remap_local_importers(my_nodeid, seg->s_segid,
			    cookie);
		} else {
			/*
			 * Unbind the pages associated with "cookie" by the
			 * rsm_bind_pages calls prior to this. This is
			 * similar to what is done in the rsm_unbind_pages
			 * routine for the seg->s_cookie.
			 */
			ddi_umem_unlock(cookie);
			rsm_dec_pgcnt(btopr(msg->len));
			DBG_PRINTF((category, RSM_ERR,
			    "rsm_rebind failed with %d\n", e));
		}
		/*
		 * At present there is no dependency on the existence of xbuf.
		 * So we can free it here. If in the future this changes, it can
		 * be freed sometime during the segment destroy.
		 */
		freerbuf(xbuf);
	}

	/* Unlock segment */
	rsmseglock_release(seg);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_rebind done\n"));

	return (e);
}

static int
rsm_unbind(rsmseg_t *seg)
{
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_unbind enter\n"));

	rsmseglock_acquire(seg);

	/* verify segment state */
	if ((seg->s_state != RSM_STATE_BIND) &&
	    (seg->s_state != RSM_STATE_BIND_QUIESCED)) {
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_unbind: invalid state\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	/* unlock current range */
	(void) rsm_unbind_pages(seg);

	if (seg->s_state == RSM_STATE_BIND) {
		seg->s_state = RSM_STATE_NEW;
	} else if (seg->s_state == RSM_STATE_BIND_QUIESCED) {
		seg->s_state = RSM_STATE_NEW_QUIESCED;
	}

	rsmseglock_release(seg);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_unbind done\n"));

	return (RSM_SUCCESS);
}

/* **************************** Exporter Access List Management ******* */
static void
rsmacl_free(rsmapi_access_entry_t *acl, int acl_len)
{
	int	acl_sz;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmacl_free enter\n"));

	/* acl could be NULL */

	if (acl != NULL && acl_len > 0) {
		acl_sz = acl_len * sizeof (rsmapi_access_entry_t);
		kmem_free((void *)acl, acl_sz);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmacl_free done\n"));
}

static void
rsmpiacl_free(rsm_access_entry_t *acl, int acl_len)
{
	int	acl_sz;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmpiacl_free enter\n"));

	if (acl != NULL && acl_len > 0) {
		acl_sz = acl_len * sizeof (rsm_access_entry_t);
		kmem_free((void *)acl, acl_sz);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmpiacl_free done\n"));

}

static int
rsmacl_build(rsm_ioctlmsg_t *msg, int mode,
    rsmapi_access_entry_t **list, int *len, int loopback)
{
	rsmapi_access_entry_t *acl;
	int	acl_len;
	int i;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmacl_build enter\n"));

	*len = 0;
	*list = NULL;

	acl_len = msg->acl_len;
	if ((loopback && acl_len > 1) || (acl_len < 0) ||
	    (acl_len > MAX_NODES)) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmacl_build done: acl invalid\n"));
		return (RSMERR_BAD_ACL);
	}

	if (acl_len > 0 && acl_len <= MAX_NODES) {
		size_t acl_size = acl_len * sizeof (rsmapi_access_entry_t);

		acl = kmem_alloc(acl_size, KM_SLEEP);

		if (ddi_copyin((caddr_t)msg->acl, (caddr_t)acl,
		    acl_size, mode)) {
			kmem_free((void *) acl, acl_size);
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsmacl_build done: BAD_ADDR\n"));
			return (RSMERR_BAD_ADDR);
		}

		/*
		 * Verify access list
		 */
		for (i = 0; i < acl_len; i++) {
			if (acl[i].ae_node > MAX_NODES ||
			    (loopback && (acl[i].ae_node != my_nodeid)) ||
			    acl[i].ae_permission > RSM_ACCESS_TRUSTED) {
				/* invalid entry */
				kmem_free((void *) acl, acl_size);
				DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
				    "rsmacl_build done: EINVAL\n"));
				return (RSMERR_BAD_ACL);
			}
		}

		*len = acl_len;
		*list = acl;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmacl_build done\n"));

	return (DDI_SUCCESS);
}

static int
rsmpiacl_create(rsmapi_access_entry_t *src, rsm_access_entry_t **dest,
    int acl_len, adapter_t *adapter)
{
	rsm_access_entry_t *acl;
	rsm_addr_t hwaddr;
	int i;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmpiacl_create enter\n"));

	if (src != NULL) {
		size_t acl_size = acl_len * sizeof (rsm_access_entry_t);
		acl = kmem_alloc(acl_size, KM_SLEEP);

		/*
		 * translate access list
		 */
		for (i = 0; i < acl_len; i++) {
			if (src[i].ae_node == my_nodeid) {
				acl[i].ae_addr = adapter->hwaddr;
			} else {
				hwaddr = get_remote_hwaddr(adapter,
				    src[i].ae_node);
				if ((int64_t)hwaddr < 0) {
					/* invalid hwaddr */
					kmem_free((void *) acl, acl_size);
					DBG_PRINTF((category,
					    RSM_DEBUG_VERBOSE,
					    "rsmpiacl_create done:"
					    "EINVAL hwaddr\n"));
					return (RSMERR_INTERNAL_ERROR);
				}
				acl[i].ae_addr = hwaddr;
			}
			/* rsmpi understands only RSM_PERM_XXXX */
			acl[i].ae_permission =
			    src[i].ae_permission & RSM_PERM_RDWR;
		}
		*dest = acl;
	} else {
		*dest = NULL;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmpiacl_create done\n"));

	return (RSM_SUCCESS);
}

static int
rsmsegacl_validate(rsmipc_request_t *req, rsm_node_id_t rnode,
    rsmipc_reply_t *reply)
{

	int		i;
	rsmseg_t	*seg;
	rsm_memseg_id_t key = req->rsmipc_key;
	rsm_permission_t perm = req->rsmipc_perm;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmsegacl_validate enter\n"));

	/*
	 * Find segment and grab its lock. The reason why we grab the segment
	 * lock in side the search is to avoid the race when the segment is
	 * being deleted and we already have a pointer to it.
	 */
	seg = rsmexport_lookup(key);
	if (!seg) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmsegacl_validate done: %u ENXIO\n", key));
		return (RSMERR_SEG_NOT_PUBLISHED);
	}

	ASSERT(rsmseglock_held(seg));
	ASSERT(seg->s_state == RSM_STATE_EXPORT);

	/*
	 * We implement a 2-level protection scheme.
	 * First, we check if local/remote host has access rights.
	 * Second, we check if the user has access rights.
	 *
	 * This routine only validates the rnode access_list
	 */
	if (seg->s_acl_len > 0) {
		/*
		 * Check host access list
		 */
		ASSERT(seg->s_acl != NULL);
		for (i = 0; i < seg->s_acl_len; i++) {
			if (seg->s_acl[i].ae_node == rnode) {
				perm &= seg->s_acl[i].ae_permission;
				goto found;
			}
		}
		/* rnode is not found in the list */
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmsegacl_validate done: EPERM\n"));
		return (RSMERR_SEG_NOT_PUBLISHED_TO_NODE);
	} else {
		/* use default owner creation umask */
		perm &= seg->s_mode;
	}

found:
	/* update perm for this node */
	reply->rsmipc_mode = perm;
	reply->rsmipc_uid = seg->s_uid;
	reply->rsmipc_gid = seg->s_gid;
	reply->rsmipc_segid = seg->s_segid;
	reply->rsmipc_seglen = seg->s_len;

	/*
	 * Perm of requesting node is valid; source will validate user
	 */
	rsmseglock_release(seg);

	/*
	 * Add the importer to the list right away, if connect fails
	 * the importer will ask the exporter to remove it.
	 */
	importer_list_add(rnode, key, req->rsmipc_adapter_hwaddr,
	    req->rsmipc_segment_cookie);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmsegacl_validate done\n"));

	return (RSM_SUCCESS);
}


/* ************************** Exporter Calls ************************* */

static int
rsm_publish(rsmseg_t *seg, rsm_ioctlmsg_t *msg, intptr_t dataptr, int mode)
{
	int			e;
	int			acl_len;
	rsmapi_access_entry_t	*acl;
	rsm_access_entry_t	*rsmpi_acl;
	rsm_memory_local_t	mem;
	struct buf		*xbuf;
	dev_t 			sdev = 0;
	adapter_t		*adapter;
	rsm_memseg_id_t		segment_id = 0;
	int			loopback_flag = 0;
	int			create_flags = 0;
	rsm_resource_callback_t	callback_flag;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_publish enter\n"));

	if (seg->s_adapter == &loopback_adapter)
		loopback_flag = 1;

	if (seg->s_pid != ddi_get_pid() &&
	    ddi_get_pid() != 0) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_publish: Not creator\n"));
		return (RSMERR_NOT_CREATOR);
	}

	/*
	 * Get per node access list
	 */
	e = rsmacl_build(msg, mode, &acl, &acl_len, loopback_flag);
	if (e != DDI_SUCCESS) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_publish done: rsmacl_build failed\n"));
		return (e);
	}

	/*
	 * The application provided msg->key is used for resolving a
	 * segment id according to the following:
	 *    key = 0   		Kernel Agent selects the segment id
	 *    key <= RSM_DLPI_ID_END	Reserved for system usage except
	 *				RSMLIB range
	 *    key < RSM_USER_APP_ID_BASE segment id = key
	 *    key >= RSM_USER_APP_ID_BASE Reserved for KA selections
	 *
	 * rsm_nextavail_segmentid is initialized to 0x80000000 and
	 * overflows to zero after 0x80000000 allocations.
	 * An algorithm is needed which allows reinitialization and provides
	 * for reallocation after overflow.  For now, ENOMEM is returned
	 * once the overflow condition has occurred.
	 */
	if (msg->key == 0) {
		mutex_enter(&rsm_lock);
		segment_id = rsm_nextavail_segmentid;
		if (segment_id != 0) {
			rsm_nextavail_segmentid++;
			mutex_exit(&rsm_lock);
		} else {
			mutex_exit(&rsm_lock);
			DBG_PRINTF((category, RSM_ERR,
			    "rsm_publish done: no more keys avlbl\n"));
			return (RSMERR_INSUFFICIENT_RESOURCES);
		}
	} else	if BETWEEN(msg->key, RSM_RSMLIB_ID_BASE, RSM_RSMLIB_ID_END)
		/* range reserved for internal use by base/ndi libraries */
		segment_id = msg->key;
	else	if (msg->key <= RSM_DLPI_ID_END)
		return (RSMERR_RESERVED_SEGID);
	else if (msg->key <= (uint_t)RSM_USER_APP_ID_BASE -1)
		segment_id = msg->key;
	else {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_publish done: invalid key %u\n", msg->key));
		return (RSMERR_RESERVED_SEGID);
	}

	/* Add key to exportlist; The segment lock is held on success */
	e = rsmexport_add(seg, segment_id);
	if (e) {
		rsmacl_free(acl, acl_len);
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_publish done: export_add failed: %d\n", e));
		return (e);
	}

	seg->s_segid = segment_id;

	if ((seg->s_state != RSM_STATE_BIND) &&
	    (seg->s_state != RSM_STATE_BIND_QUIESCED)) {
		/* state changed since then, free acl and return */
		rsmseglock_release(seg);
		rsmexport_rm(seg);
		rsmacl_free(acl, acl_len);
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_publish done: segment in wrong state: %d\n",
		    seg->s_state));
		return (RSMERR_BAD_SEG_HNDL);
	}

	/*
	 * If this is for a local memory handle and permissions are zero,
	 * then the surrogate segment is very large and we want to skip
	 * allocation of DVMA space.
	 *
	 * Careful!  If the user didn't use an ACL list, acl will be a NULL
	 * pointer.  Check that before dereferencing it.
	 */
	if (acl != (rsmapi_access_entry_t *)NULL) {
		if (acl[0].ae_node == my_nodeid && acl[0].ae_permission == 0)
			goto skipdriver;
	}

	/* create segment  */
	xbuf = ddi_umem_iosetup(seg->s_cookie, 0, seg->s_len, B_WRITE,
	    sdev, 0, NULL, DDI_UMEM_SLEEP);
	ASSERT(xbuf != NULL);

	mem.ms_type = RSM_MEM_BUF;
	mem.ms_bp = xbuf;

	/* This call includes a bind operations */

	adapter = seg->s_adapter;
	/*
	 * create a acl list with hwaddr for RSMPI publish
	 */
	e = rsmpiacl_create(acl, &rsmpi_acl, acl_len, adapter);

	if (e != RSM_SUCCESS) {
		rsmseglock_release(seg);
		rsmexport_rm(seg);
		rsmacl_free(acl, acl_len);
		freerbuf(xbuf);
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_publish done: rsmpiacl_create failed: %d\n", e));
		return (e);
	}

	if (seg->s_state == RSM_STATE_BIND) {
		/* create segment  */

		/* This call includes a bind operations */

		if (seg->s_flags & RSMKA_ALLOW_UNBIND_REBIND) {
			create_flags = RSM_ALLOW_UNBIND_REBIND;
		}

		if (seg->s_flags & RSMKA_SET_RESOURCE_DONTWAIT) {
			callback_flag  = RSM_RESOURCE_DONTWAIT;
		} else {
			callback_flag  = RSM_RESOURCE_SLEEP;
		}

		e = adapter->rsmpi_ops->rsm_seg_create(
		    adapter->rsmpi_handle,
		    &seg->s_handle.out, seg->s_len,
		    create_flags, &mem,
		    callback_flag, NULL);
		/*
		 * At present there is no dependency on the existence of xbuf.
		 * So we can free it here. If in the future this changes, it can
		 * be freed sometime during the segment destroy.
		 */
		freerbuf(xbuf);

		if (e != RSM_SUCCESS) {
			rsmseglock_release(seg);
			rsmexport_rm(seg);
			rsmacl_free(acl, acl_len);
			rsmpiacl_free(rsmpi_acl, acl_len);
			DBG_PRINTF((category, RSM_ERR,
			    "rsm_publish done: export_create failed: %d\n", e));
			/*
			 * The following assertion ensures that the two errors
			 * related to the length and its alignment do not occur
			 * since they have been checked during export_create
			 */
			ASSERT(e != RSMERR_BAD_MEM_ALIGNMENT &&
			    e != RSMERR_BAD_LENGTH);
			if (e == RSMERR_NOT_MEM)
				e = RSMERR_INSUFFICIENT_MEM;

			return (e);
		}
		/* export segment, this should create an IMMU mapping */
		e = adapter->rsmpi_ops->rsm_publish(
		    seg->s_handle.out,
		    rsmpi_acl, acl_len,
		    seg->s_segid,
		    RSM_RESOURCE_DONTWAIT, NULL);

		if (e != RSM_SUCCESS) {
			adapter->rsmpi_ops->rsm_seg_destroy(seg->s_handle.out);
			rsmseglock_release(seg);
			rsmexport_rm(seg);
			rsmacl_free(acl, acl_len);
			rsmpiacl_free(rsmpi_acl, acl_len);
			DBG_PRINTF((category, RSM_ERR,
			    "rsm_publish done: export_publish failed: %d\n",
			    e));
			return (e);
		}
	}

	seg->s_acl_in = rsmpi_acl;

skipdriver:
	/* defer s_acl/s_acl_len -> avoid crash in rsmseg_free */
	seg->s_acl_len	= acl_len;
	seg->s_acl	= acl;

	if (seg->s_state == RSM_STATE_BIND) {
		seg->s_state = RSM_STATE_EXPORT;
	} else if (seg->s_state == RSM_STATE_BIND_QUIESCED) {
		seg->s_state = RSM_STATE_EXPORT_QUIESCED;
		cv_broadcast(&seg->s_cv);
	}

	rsmseglock_release(seg);

	/*
	 * If the segment id was solicited, then return it in
	 * the original incoming message.
	 */
	if (msg->key == 0) {
		msg->key = segment_id;
#ifdef _MULTI_DATAMODEL
		if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
			rsm_ioctlmsg32_t msg32;

			msg32.key = msg->key;
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsm_publish done\n"));
			return (ddi_copyout((caddr_t)&msg32,
			    (caddr_t)dataptr, sizeof (msg32), mode));
		}
#endif
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_publish done\n"));
		return (ddi_copyout((caddr_t)msg,
		    (caddr_t)dataptr, sizeof (*msg), mode));
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_publish done\n"));
	return (DDI_SUCCESS);
}

/*
 * This function modifies the access control list of an already published
 * segment.  There is no effect on import segments which are already
 * connected.
 */
static int
rsm_republish(rsmseg_t *seg, rsm_ioctlmsg_t *msg, int mode)
{
	rsmapi_access_entry_t	*new_acl, *old_acl, *tmp_acl;
	rsm_access_entry_t	*rsmpi_new_acl, *rsmpi_old_acl;
	int			new_acl_len, old_acl_len, tmp_acl_len;
	int			e, i;
	adapter_t		*adapter;
	int			loopback_flag = 0;
	rsm_memseg_id_t		key;
	rsm_permission_t	permission;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_republish enter\n"));

	if ((seg->s_state != RSM_STATE_EXPORT) &&
	    (seg->s_state != RSM_STATE_EXPORT_QUIESCED) &&
	    (seg->s_state != RSM_STATE_EXPORT_QUIESCING))
		return (RSMERR_SEG_NOT_PUBLISHED);

	if (seg->s_pid != ddi_get_pid() &&
	    ddi_get_pid() != 0) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_republish: Not owner\n"));
		return (RSMERR_NOT_CREATOR);
	}

	if (seg->s_adapter == &loopback_adapter)
		loopback_flag = 1;

	/*
	 * Build new list first
	 */
	e = rsmacl_build(msg, mode, &new_acl, &new_acl_len, loopback_flag);
	if (e) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_republish done: rsmacl_build failed %d", e));
		return (e);
	}

	/* Lock segment */
	rsmseglock_acquire(seg);
	/*
	 * a republish is in progress - REPUBLISH message is being
	 * sent to the importers so wait for it to complete OR
	 * wait till DR completes
	 */
	while (((seg->s_state == RSM_STATE_EXPORT) &&
	    (seg->s_flags & RSM_REPUBLISH_WAIT)) ||
	    (seg->s_state == RSM_STATE_EXPORT_QUIESCED) ||
	    (seg->s_state == RSM_STATE_EXPORT_QUIESCING)) {
		if (cv_wait_sig(&seg->s_cv, &seg->s_lock) == 0) {
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsm_republish done: cv_wait  INTERRUPTED"));
			rsmseglock_release(seg);
			rsmacl_free(new_acl, new_acl_len);
			return (RSMERR_INTERRUPTED);
		}
	}

	/* recheck if state is valid */
	if (seg->s_state != RSM_STATE_EXPORT) {
		rsmseglock_release(seg);
		rsmacl_free(new_acl, new_acl_len);
		return (RSMERR_SEG_NOT_PUBLISHED);
	}

	key = seg->s_key;
	old_acl = seg->s_acl;
	old_acl_len = seg->s_acl_len;

	seg->s_acl = new_acl;
	seg->s_acl_len = new_acl_len;

	/*
	 * This call will only be meaningful if and when the interconnect
	 * layer makes use of the access list
	 */
	adapter = seg->s_adapter;
	/*
	 * create a acl list with hwaddr for RSMPI publish
	 */
	e = rsmpiacl_create(new_acl, &rsmpi_new_acl, new_acl_len, adapter);

	if (e != RSM_SUCCESS) {
		seg->s_acl = old_acl;
		seg->s_acl_len = old_acl_len;
		rsmseglock_release(seg);
		rsmacl_free(new_acl, new_acl_len);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_republish done: rsmpiacl_create failed %d", e));
		return (e);
	}
	rsmpi_old_acl = seg->s_acl_in;
	seg->s_acl_in = rsmpi_new_acl;

	e = adapter->rsmpi_ops->rsm_republish(seg->s_handle.out,
	    seg->s_acl_in, seg->s_acl_len,
	    RSM_RESOURCE_DONTWAIT, NULL);

	if (e != RSM_SUCCESS) {
		seg->s_acl = old_acl;
		seg->s_acl_in = rsmpi_old_acl;
		seg->s_acl_len = old_acl_len;
		rsmseglock_release(seg);
		rsmacl_free(new_acl, new_acl_len);
		rsmpiacl_free(rsmpi_new_acl, new_acl_len);

		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_republish done: rsmpi republish failed %d\n", e));
		return (e);
	}

	/* create a tmp copy of the new acl */
	tmp_acl_len = new_acl_len;
	if (tmp_acl_len > 0) {
		tmp_acl = kmem_zalloc(new_acl_len*sizeof (*tmp_acl), KM_SLEEP);
		for (i = 0; i < tmp_acl_len; i++) {
			tmp_acl[i].ae_node = new_acl[i].ae_node;
			tmp_acl[i].ae_permission = new_acl[i].ae_permission;
		}
		/*
		 * The default permission of a node which was in the old
		 * ACL but not in the new ACL is 0 ie no access.
		 */
		permission = 0;
	} else {
		/*
		 * NULL acl means all importers can connect and
		 * default permission will be owner creation umask
		 */
		tmp_acl = NULL;
		permission = seg->s_mode;
	}

	/* make other republishers to wait for republish to complete */
	seg->s_flags |= RSM_REPUBLISH_WAIT;

	rsmseglock_release(seg);

	/* send the new perms to the importing nodes */
	rsm_send_republish(key, tmp_acl, tmp_acl_len, permission);

	rsmseglock_acquire(seg);
	seg->s_flags &= ~RSM_REPUBLISH_WAIT;
	/* wake up any one waiting for republish to complete */
	cv_broadcast(&seg->s_cv);
	rsmseglock_release(seg);

	rsmacl_free(tmp_acl, tmp_acl_len);
	rsmacl_free(old_acl, old_acl_len);
	rsmpiacl_free(rsmpi_old_acl, old_acl_len);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_republish done\n"));
	return (DDI_SUCCESS);
}

static int
rsm_unpublish(rsmseg_t *seg, int mode)
{
	rsmapi_access_entry_t	*acl;
	rsm_access_entry_t	*rsmpi_acl;
	int			acl_len;
	int			e;
	adapter_t *adapter;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_unpublish enter\n"));

	if (seg->s_pid != ddi_get_pid() &&
	    ddi_get_pid() != 0) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_unpublish: Not creator\n"));
		return (RSMERR_NOT_CREATOR);
	}

	rsmseglock_acquire(seg);
	/*
	 * wait for QUIESCING to complete here before rsmexport_rm
	 * is called because the SUSPEND_COMPLETE mesg which changes
	 * the seg state from EXPORT_QUIESCING to EXPORT_QUIESCED and
	 * signals the cv_wait needs to find it in the hashtable.
	 */
	while ((seg->s_state == RSM_STATE_EXPORT_QUIESCING) ||
	    ((seg->s_state == RSM_STATE_EXPORT) && (seg->s_rdmacnt > 0))) {
		if (cv_wait_sig(&seg->s_cv, &seg->s_lock) == 0) {
			rsmseglock_release(seg);
			DBG_PRINTF((category, RSM_ERR,
			    "rsm_unpublish done: cv_wait INTR qscing"
			    "getv/putv in progress"));
			return (RSMERR_INTERRUPTED);
		}
	}

	/* verify segment state */
	if ((seg->s_state != RSM_STATE_EXPORT) &&
	    (seg->s_state != RSM_STATE_EXPORT_QUIESCED)) {
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_unpublish done: bad state %x\n", seg->s_state));
		return (RSMERR_SEG_NOT_PUBLISHED);
	}

	rsmseglock_release(seg);

	rsmexport_rm(seg);

	rsm_send_importer_disconnects(seg->s_segid, my_nodeid);

	rsmseglock_acquire(seg);
	/*
	 * wait for republish to complete
	 */
	while ((seg->s_state == RSM_STATE_EXPORT) &&
	    (seg->s_flags & RSM_REPUBLISH_WAIT)) {
		if (cv_wait_sig(&seg->s_cv, &seg->s_lock) == 0) {
			DBG_PRINTF((category, RSM_ERR,
			    "rsm_unpublish done: cv_wait INTR repubing"));
			rsmseglock_release(seg);
			return (RSMERR_INTERRUPTED);
		}
	}

	if ((seg->s_state != RSM_STATE_EXPORT) &&
	    (seg->s_state != RSM_STATE_EXPORT_QUIESCED)) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_unpublish done: invalid state"));
		rsmseglock_release(seg);
		return (RSMERR_SEG_NOT_PUBLISHED);
	}

	/*
	 * check for putv/get surrogate segment which was not published
	 * to the driver.
	 *
	 * Be certain to see if there is an ACL first!  If this segment was
	 * not published with an ACL, acl will be a null pointer.  Check
	 * that before dereferencing it.
	 */
	acl = seg->s_acl;
	if (acl != (rsmapi_access_entry_t *)NULL) {
		if (acl[0].ae_node == my_nodeid && acl[0].ae_permission == 0)
			goto bypass;
	}

	/* The RSMPI unpublish/destroy has been done if seg is QUIESCED */
	if (seg->s_state == RSM_STATE_EXPORT_QUIESCED)
		goto bypass;

	adapter = seg->s_adapter;
	for (;;) {
		if (seg->s_state != RSM_STATE_EXPORT) {
			rsmseglock_release(seg);
			DBG_PRINTF((category, RSM_ERR,
			    "rsm_unpublish done: bad state %x\n",
			    seg->s_state));
			return (RSMERR_SEG_NOT_PUBLISHED);
		}

		/* unpublish from adapter */
		e = adapter->rsmpi_ops->rsm_unpublish(seg->s_handle.out);

		if (e == RSM_SUCCESS) {
			break;
		}

		if (e == RSMERR_SEG_IN_USE && mode == 1) {
			/*
			 * wait for unpublish to succeed, it's busy.
			 */
			seg->s_flags |= RSM_EXPORT_WAIT;

			/* wait for a max of 1 ms - this is an empirical */
			/* value that was found by some minimal testing  */
			/* can be fine tuned when we have better numbers */
			/* A long term fix would be to send cv_signal	 */
			/* from the intr callback routine		 */
			/* currently nobody signals this wait		 */
			(void) cv_reltimedwait(&seg->s_cv, &seg->s_lock,
			    drv_usectohz(1000), TR_CLOCK_TICK);

			DBG_PRINTF((category, RSM_ERR,
			    "rsm_unpublish: SEG_IN_USE\n"));

			seg->s_flags &= ~RSM_EXPORT_WAIT;
		} else {
			if (mode == 1) {
				DBG_PRINTF((category, RSM_ERR,
				    "rsm:rsmpi unpublish err %x\n", e));
				seg->s_state = RSM_STATE_BIND;
			}
			rsmseglock_release(seg);
			return (e);
		}
	}

	/* Free segment */
	e = adapter->rsmpi_ops->rsm_seg_destroy(seg->s_handle.out);

	if (e != RSM_SUCCESS) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_unpublish: rsmpi destroy key=%x failed %x\n",
		    seg->s_key, e));
	}

bypass:
	acl = seg->s_acl;
	rsmpi_acl = seg->s_acl_in;
	acl_len = seg->s_acl_len;

	seg->s_acl = NULL;
	seg->s_acl_in = NULL;
	seg->s_acl_len = 0;

	if (seg->s_state == RSM_STATE_EXPORT) {
		seg->s_state = RSM_STATE_BIND;
	} else if (seg->s_state == RSM_STATE_EXPORT_QUIESCED) {
		seg->s_state = RSM_STATE_BIND_QUIESCED;
		cv_broadcast(&seg->s_cv);
	}

	rsmseglock_release(seg);

	rsmacl_free(acl, acl_len);
	rsmpiacl_free(rsmpi_acl, acl_len);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_unpublish done\n"));

	return (DDI_SUCCESS);
}

/*
 * Called from rsm_unpublish to force an unload and disconnection of all
 * importers of the unpublished segment.
 *
 * First build the list of segments requiring a force disconnect, then
 * send a request for each.
 */
static void
rsm_send_importer_disconnects(rsm_memseg_id_t ex_segid,
    rsm_node_id_t ex_nodeid)
{
	rsmipc_request_t 	request;
	importing_token_t	*prev_token, *token, *tmp_token, *tokp;
	importing_token_t	*force_disconnect_list = NULL;
	int			index;

	DBG_PRINTF((RSM_KERNEL_AGENT | RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_send_importer_disconnects enter\n"));

	index = rsmhash(ex_segid);

	mutex_enter(&importer_list.lock);

	prev_token = NULL;
	token = importer_list.bucket[index];

	while (token != NULL) {
		if (token->key == ex_segid) {
			/*
			 * take it off the importer list and add it
			 * to the force disconnect list.
			 */
			if (prev_token == NULL)
				importer_list.bucket[index] = token->next;
			else
				prev_token->next = token->next;
			tmp_token = token;
			token = token->next;
			if (force_disconnect_list == NULL) {
				force_disconnect_list = tmp_token;
				tmp_token->next = NULL;
			} else {
				tokp = force_disconnect_list;
				/*
				 * make sure that the tmp_token's node
				 * is not already on the force disconnect
				 * list.
				 */
				while (tokp != NULL) {
					if (tokp->importing_node ==
					    tmp_token->importing_node) {
						break;
					}
					tokp = tokp->next;
				}
				if (tokp == NULL) {
					tmp_token->next =
					    force_disconnect_list;
					force_disconnect_list = tmp_token;
				} else {
					kmem_free((void *)tmp_token,
					    sizeof (*token));
				}
			}

		} else {
			prev_token = token;
			token = token->next;
		}
	}
	mutex_exit(&importer_list.lock);

	token = force_disconnect_list;
	while (token != NULL) {
		if (token->importing_node == my_nodeid) {
			rsm_force_unload(ex_nodeid, ex_segid,
			    DISCONNECT);
		} else {
			request.rsmipc_hdr.rsmipc_type =
			    RSMIPC_MSG_DISCONNECT;
			request.rsmipc_key = token->key;
			for (;;) {
				if (rsmipc_send(token->importing_node,
				    &request,
				    RSM_NO_REPLY) == RSM_SUCCESS) {
					break;
				} else {
					delay(drv_usectohz(10000));
				}
			}
		}
		tmp_token = token;
		token = token->next;
		kmem_free((void *)tmp_token, sizeof (*token));
	}

	DBG_PRINTF((RSM_KERNEL_AGENT | RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_send_importer_disconnects done\n"));
}

/*
 * This function is used as a callback for unlocking the pages locked
 * down by a process which then does a fork or an exec.
 * It marks the export segments corresponding to umem cookie given by
 * the *arg to be in a ZOMBIE state(by calling rsmseg_close to be
 * destroyed later when an rsm_close occurs).
 */
static void
rsm_export_force_destroy(ddi_umem_cookie_t *ck)
{
	rsmresource_blk_t *blk;
	rsmresource_t *p;
	rsmseg_t *eseg = NULL;
	int i, j;
	int found = 0;

	DBG_PRINTF((RSM_KERNEL_AGENT | RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_export_force_destroy enter\n"));

	/*
	 * Walk the resource list and locate the export segment (either
	 * in the BIND or the EXPORT state) which corresponds to the
	 * ddi_umem_cookie_t being freed up, and call rsmseg_close.
	 * Change the state to ZOMBIE by calling rsmseg_close with the
	 * force_flag argument (the second argument) set to 1. Also,
	 * unpublish and unbind the segment, but don't free it. Free it
	 * only on a rsm_close call for the segment.
	 */
	rw_enter(&rsm_resource.rsmrc_lock, RW_READER);

	for (i = 0; i < rsm_resource.rsmrc_len; i++) {
		blk = rsm_resource.rsmrc_root[i];
		if (blk == NULL) {
			continue;
		}

		for (j = 0; j < RSMRC_BLKSZ; j++) {
			p = blk->rsmrcblk_blks[j];
			if ((p != NULL) && (p != RSMRC_RESERVED) &&
			    (p->rsmrc_type == RSM_RESOURCE_EXPORT_SEGMENT)) {
				eseg = (rsmseg_t *)p;
				if (eseg->s_cookie != ck)
					continue; /* continue searching */
				/*
				 * Found the segment, set flag to indicate
				 * force destroy processing is in progress
				 */
				rsmseglock_acquire(eseg);
				eseg->s_flags |= RSM_FORCE_DESTROY_WAIT;
				rsmseglock_release(eseg);
				found = 1;
				break;
			}
		}

		if (found)
			break;
	}

	rw_exit(&rsm_resource.rsmrc_lock);

	if (found) {
		ASSERT(eseg != NULL);
		/* call rsmseg_close with force flag set to 1 */
		rsmseg_close(eseg, 1);
		/*
		 * force destroy processing done, clear flag and signal any
		 * thread waiting in rsmseg_close.
		 */
		rsmseglock_acquire(eseg);
		eseg->s_flags &= ~RSM_FORCE_DESTROY_WAIT;
		cv_broadcast(&eseg->s_cv);
		rsmseglock_release(eseg);
	}

	DBG_PRINTF((RSM_KERNEL_AGENT | RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_export_force_destroy done\n"));
}

/* ******************************* Remote Calls *********************** */
static void
rsm_intr_segconnect(rsm_node_id_t src, rsmipc_request_t *req)
{
	rsmipc_reply_t reply;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_intr_segconnect enter\n"));

	reply.rsmipc_status = (short)rsmsegacl_validate(req, src, &reply);

	reply.rsmipc_hdr.rsmipc_type = RSMIPC_MSG_REPLY;
	reply.rsmipc_hdr.rsmipc_cookie = req->rsmipc_hdr.rsmipc_cookie;

	(void) rsmipc_send(src, NULL, &reply);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_intr_segconnect done\n"));
}


/*
 * When an exported segment is unpublished the exporter sends an ipc
 * message (RSMIPC_MSG_DISCONNECT) to all importers.  The recv ipc dispatcher
 * calls this function.  The import list is scanned; segments which match the
 * exported segment id are unloaded and disconnected.
 *
 * Will also be called from rsm_rebind with disconnect_flag FALSE.
 *
 */
static void
rsm_force_unload(rsm_node_id_t src_nodeid,
    rsm_memseg_id_t ex_segid,
    boolean_t disconnect_flag)

{
	rsmresource_t	*p = NULL;
	rsmhash_table_t *rhash = &rsm_import_segs;
	uint_t		index;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_force_unload enter\n"));

	index = rsmhash(ex_segid);

	rw_enter(&rhash->rsmhash_rw, RW_READER);

	p = rsmhash_getbkt(rhash, index);

	for (; p; p = p->rsmrc_next) {
		rsmseg_t *seg = (rsmseg_t *)p;
		if ((seg->s_segid == ex_segid) && (seg->s_node == src_nodeid)) {
			/*
			 * In order to make rsmseg_unload and rsm_force_unload
			 * thread safe, acquire the segment lock here.
			 * rsmseg_unload is responsible for releasing the lock.
			 * rsmseg_unload releases the lock just before a call
			 * to rsmipc_send or in case of an early exit which
			 * occurs if the segment was in the state
			 * RSM_STATE_CONNECTING or RSM_STATE_NEW.
			 */
			rsmseglock_acquire(seg);
			if (disconnect_flag)
				seg->s_flags |= RSM_FORCE_DISCONNECT;
			rsmseg_unload(seg);
		}
	}
	rw_exit(&rhash->rsmhash_rw);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_force_unload done\n"));
}

static void
rsm_intr_reply(rsmipc_msghdr_t *msg)
{
	/*
	 * Find slot for cookie in reply.
	 * Match sequence with sequence in cookie
	 * If no match; return
	 * Try to grap lock of slot, if locked return
	 * copy data into reply slot area
	 * signal waiter
	 */
	rsmipc_slot_t 	*slot;
	rsmipc_cookie_t	*cookie;
	void *data = (void *) msg;
	size_t size = sizeof (rsmipc_reply_t);
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_intr_reply enter\n"));

	cookie = &msg->rsmipc_cookie;
	if (cookie->ic.index >= RSMIPC_SZ) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm: rsm_intr_reply bad cookie %d\n", cookie->ic.index));
		return;
	}

	ASSERT(cookie->ic.index < RSMIPC_SZ);
	slot = &rsm_ipc.slots[cookie->ic.index];
	mutex_enter(&slot->rsmipc_lock);
	if (slot->rsmipc_cookie.value == cookie->value) {
		/* found a match */
		if (RSMIPC_GET(slot, RSMIPC_PENDING)) {
			bcopy(data, slot->rsmipc_data, size);
			RSMIPC_CLEAR(slot, RSMIPC_PENDING);
			cv_signal(&slot->rsmipc_cv);
		}
	} else {
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm: rsm_intr_reply mismatched reply %d\n",
		    cookie->ic.index));
	}
	mutex_exit(&slot->rsmipc_lock);
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_intr_reply done\n"));
}

/*
 * This function gets dispatched on the worker thread when we receive
 * the SQREADY message. This function sends the SQREADY_ACK message.
 */
static void
rsm_sqready_ack_deferred(void *arg)
{
	path_t	*path = (path_t *)arg;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_sqready_ack_deferred enter\n"));

	mutex_enter(&path->mutex);

	/*
	 * If path is not active no point in sending the ACK
	 * because the whole SQREADY protocol will again start
	 * when the path becomes active.
	 */
	if (path->state != RSMKA_PATH_ACTIVE) {
		/*
		 * decrement the path refcnt incremented in rsm_proc_sqready
		 */
		PATH_RELE_NOLOCK(path);
		mutex_exit(&path->mutex);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_sqready_ack_deferred done:!ACTIVE\n"));
		return;
	}

	/* send an SQREADY_ACK message */
	(void) rsmipc_send_controlmsg(path, RSMIPC_MSG_SQREADY_ACK);

	/* initialize credits to the max level */
	path->sendq_token.msgbuf_avail = RSMIPC_MAX_MESSAGES;

	/* wake up any send that is waiting for credits */
	cv_broadcast(&path->sendq_token.sendq_cv);

	/*
	 * decrement the path refcnt since we incremented it in
	 * rsm_proc_sqready
	 */
	PATH_RELE_NOLOCK(path);

	mutex_exit(&path->mutex);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_sqready_ack_deferred done\n"));
}

/*
 * Process the SQREADY message
 */
static void
rsm_proc_sqready(rsmipc_controlmsg_t *msg, rsm_addr_t src_hwaddr,
    rsm_intr_hand_arg_t arg)
{
	rsmipc_msghdr_t		*msghdr = (rsmipc_msghdr_t *)msg;
	srv_handler_arg_t	*hdlr_argp = (srv_handler_arg_t *)arg;
	path_t			*path;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_proc_sqready enter\n"));

	/* look up the path - incr the path refcnt */
	path = rsm_find_path(hdlr_argp->adapter_name,
	    hdlr_argp->adapter_instance, src_hwaddr);

	/*
	 * No path exists or path is not active - drop the message
	 */
	if (path == NULL) {
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_proc_sqready done: msg dropped no path\n"));
		return;
	}

	mutex_exit(&path->mutex);

	/* drain any tasks from the previous incarnation */
	taskq_wait(path->recv_taskq);

	mutex_enter(&path->mutex);
	/*
	 * If we'd sent an SQREADY message and were waiting for SQREADY_ACK
	 * in the meanwhile we received an SQREADY message, blindly reset
	 * the WAIT_FOR_SQACK flag because we'll just send SQREADY_ACK
	 * and forget about the SQREADY that we sent.
	 */
	path->flags &= ~RSMKA_WAIT_FOR_SQACK;

	if (path->state != RSMKA_PATH_ACTIVE) {
		/* decr refcnt and drop the mutex */
		PATH_RELE_NOLOCK(path);
		mutex_exit(&path->mutex);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_proc_sqready done: msg dropped path !ACTIVE\n"));
		return;
	}

	DBG_PRINTF((category, RSM_DEBUG, "rsm_proc_sqready:path=%lx "
	    " src=%lx:%llx\n", path, msghdr->rsmipc_src, src_hwaddr));

	/*
	 * The sender's local incarnation number is our remote incarnation
	 * number save it in the path data structure
	 */
	path->remote_incn = msg->rsmipc_local_incn;
	path->sendq_token.msgbuf_avail = 0;
	path->procmsg_cnt = 0;

	/*
	 * path is active - dispatch task to send SQREADY_ACK - remember
	 * RSMPI calls can't be done in interrupt context
	 *
	 * We can use the recv_taskq to send because the remote endpoint
	 * cannot start sending messages till it receives SQREADY_ACK hence
	 * at this point there are no tasks on recv_taskq.
	 *
	 * The path refcnt will be decremented in rsm_sqready_ack_deferred.
	 */
	(void) taskq_dispatch(path->recv_taskq,
	    rsm_sqready_ack_deferred, path, KM_NOSLEEP);

	mutex_exit(&path->mutex);


	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_proc_sqready done\n"));
}

/*
 * Process the SQREADY_ACK message
 */
static void
rsm_proc_sqready_ack(rsmipc_controlmsg_t *msg, rsm_addr_t src_hwaddr,
    rsm_intr_hand_arg_t arg)
{
	rsmipc_msghdr_t		*msghdr = (rsmipc_msghdr_t *)msg;
	srv_handler_arg_t	*hdlr_argp = (srv_handler_arg_t *)arg;
	path_t			*path;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_proc_sqready_ack enter\n"));

	/* look up the path - incr the path refcnt */
	path = rsm_find_path(hdlr_argp->adapter_name,
	    hdlr_argp->adapter_instance, src_hwaddr);

	/*
	 * drop the message if - no path exists or path is not active
	 * or if its not waiting for SQREADY_ACK message
	 */
	if (path == NULL) {
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_proc_sqready_ack done: msg dropped no path\n"));
		return;
	}

	if ((path->state != RSMKA_PATH_ACTIVE) ||
	    !(path->flags & RSMKA_WAIT_FOR_SQACK)) {
		/* decrement the refcnt */
		PATH_RELE_NOLOCK(path);
		mutex_exit(&path->mutex);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_proc_sqready_ack done: msg dropped\n"));
		return;
	}

	/*
	 * Check if this message is in response to the last RSMIPC_MSG_SQREADY
	 * sent, if not drop it.
	 */
	if (path->local_incn != msghdr->rsmipc_incn) {
		/* decrement the refcnt */
		PATH_RELE_NOLOCK(path);
		mutex_exit(&path->mutex);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_proc_sqready_ack done: msg old incn %lld\n",
		    msghdr->rsmipc_incn));
		return;
	}

	DBG_PRINTF((category, RSM_DEBUG, "rsm_proc_sqready_ack:path=%lx "
	    " src=%lx:%llx\n", path, msghdr->rsmipc_src, src_hwaddr));

	/*
	 * clear the WAIT_FOR_SQACK flag since we have recvd the ack
	 */
	path->flags &= ~RSMKA_WAIT_FOR_SQACK;

	/* save the remote sendq incn number */
	path->remote_incn = msg->rsmipc_local_incn;

	/* initialize credits to the max level */
	path->sendq_token.msgbuf_avail = RSMIPC_MAX_MESSAGES;

	/* wake up any send that is waiting for credits */
	cv_broadcast(&path->sendq_token.sendq_cv);

	/* decrement the refcnt */
	PATH_RELE_NOLOCK(path);

	mutex_exit(&path->mutex);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_proc_sqready_ack done\n"));
}

/*
 * process the RSMIPC_MSG_CREDIT message
 */
static void
rsm_add_credits(rsmipc_controlmsg_t *msg, rsm_addr_t src_hwaddr,
    rsm_intr_hand_arg_t arg)
{
	rsmipc_msghdr_t		*msghdr = (rsmipc_msghdr_t *)msg;
	srv_handler_arg_t	*hdlr_argp = (srv_handler_arg_t *)arg;
	path_t			*path;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL |
	    RSM_INTR_CALLBACK | RSM_FLOWCONTROL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_add_credits enter\n"));

	/* look up the path - incr the path refcnt */
	path = rsm_find_path(hdlr_argp->adapter_name,
	    hdlr_argp->adapter_instance, src_hwaddr);

	if (path == NULL) {
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_add_credits enter: path not found\n"));
		return;
	}

	/* the path is not active - discard credits */
	if (path->state != RSMKA_PATH_ACTIVE) {
		PATH_RELE_NOLOCK(path);
		mutex_exit(&path->mutex);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_add_credits enter:path=%lx !ACTIVE\n", path));
		return;
	}

	/*
	 * Check if these credits are for current incarnation of the path.
	 */
	if (path->local_incn != msghdr->rsmipc_incn) {
		/* decrement the refcnt */
		PATH_RELE_NOLOCK(path);
		mutex_exit(&path->mutex);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_add_credits enter: old incn %lld\n",
		    msghdr->rsmipc_incn));
		return;
	}

	DBG_PRINTF((category, RSM_DEBUG,
	    "rsm_add_credits:path=%lx new-creds=%d "
	    "curr credits=%d src=%lx:%llx\n", path, msg->rsmipc_credits,
	    path->sendq_token.msgbuf_avail, msghdr->rsmipc_src,
	    src_hwaddr));


	/* add credits to the path's sendq */
	path->sendq_token.msgbuf_avail += msg->rsmipc_credits;

	ASSERT(path->sendq_token.msgbuf_avail <= RSMIPC_MAX_MESSAGES);

	/* wake up any send that is waiting for credits */
	cv_broadcast(&path->sendq_token.sendq_cv);

	/* decrement the refcnt */
	PATH_RELE_NOLOCK(path);

	mutex_exit(&path->mutex);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_add_credits done\n"));
}

static void
rsm_intr_event(rsmipc_request_t *msg)
{
	rsmseg_t	*seg;
	rsmresource_t	*p;
	rsm_node_id_t	src_node;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_intr_event enter\n"));

	src_node = msg->rsmipc_hdr.rsmipc_src;

	if ((seg = msg->rsmipc_segment_cookie) != NULL) {
		/* This is for an import segment */
		uint_t hashval = rsmhash(msg->rsmipc_key);

		rw_enter(&rsm_import_segs.rsmhash_rw, RW_READER);

		p = (rsmresource_t *)rsmhash_getbkt(&rsm_import_segs, hashval);

		for (; p; p = p->rsmrc_next) {
			if ((p->rsmrc_key == msg->rsmipc_key) &&
			    (p->rsmrc_node == src_node)) {
				seg = (rsmseg_t *)p;
				rsmseglock_acquire(seg);

				atomic_inc_32(&seg->s_pollevent);

				if (seg->s_pollflag & RSM_SEGMENT_POLL)
					pollwakeup(&seg->s_poll, POLLRDNORM);

				rsmseglock_release(seg);
			}
		}

		rw_exit(&rsm_import_segs.rsmhash_rw);
	} else {
		/* This is for an export segment */
		seg = rsmexport_lookup(msg->rsmipc_key);
		if (!seg) {
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsm_intr_event done: exp seg not found\n"));
			return;
		}

		ASSERT(rsmseglock_held(seg));

		atomic_inc_32(&seg->s_pollevent);

		/*
		 * We must hold the segment lock here, or else the segment
		 * can be freed while pollwakeup is using it. This implies
		 * that we MUST NOT grab the segment lock during rsm_chpoll,
		 * as outlined in the chpoll(2) man page.
		 */
		if (seg->s_pollflag & RSM_SEGMENT_POLL)
			pollwakeup(&seg->s_poll, POLLRDNORM);

		rsmseglock_release(seg);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_intr_event done\n"));
}

/*
 * The exporter did a republish and changed the ACL - this change is only
 * visible to new importers.
 */
static void
importer_update(rsm_node_id_t src_node, rsm_memseg_id_t key,
    rsm_permission_t perm)
{

	rsmresource_t	*p;
	rsmseg_t	*seg;
	uint_t		hashval = rsmhash(key);
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "importer_update enter\n"));

	rw_enter(&rsm_import_segs.rsmhash_rw, RW_READER);

	p = (rsmresource_t *)rsmhash_getbkt(&rsm_import_segs, hashval);

	for (; p; p = p->rsmrc_next) {
		/*
		 * find the importer and update the permission in the shared
		 * data structure. Any new importers will use the new perms
		 */
		if ((p->rsmrc_key == key) && (p->rsmrc_node == src_node)) {
			seg = (rsmseg_t *)p;

			rsmseglock_acquire(seg);
			rsmsharelock_acquire(seg);
			seg->s_share->rsmsi_mode = perm;
			rsmsharelock_release(seg);
			rsmseglock_release(seg);

			break;
		}
	}

	rw_exit(&rsm_import_segs.rsmhash_rw);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "importer_update done\n"));
}

void
rsm_suspend_complete(rsm_node_id_t src_node, int flag)
{
	int		done = 1; /* indicate all SUSPENDS have been acked */
	list_element_t	*elem;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_suspend_complete enter\n"));

	mutex_enter(&rsm_suspend_list.list_lock);

	if (rsm_suspend_list.list_head == NULL) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_suspend_complete done: suspend_list is empty\n"));
		mutex_exit(&rsm_suspend_list.list_lock);
		return;
	}

	elem = rsm_suspend_list.list_head;
	while (elem != NULL) {
		if (elem->nodeid == src_node) {
			/* clear the pending flag for the node */
			elem->flags &= ~RSM_SUSPEND_ACKPENDING;
			elem->flags |= flag;
		}

		if (done && (elem->flags & RSM_SUSPEND_ACKPENDING))
			done = 0; /* still some nodes have not yet ACKED */

		elem = elem->next;
	}

	mutex_exit(&rsm_suspend_list.list_lock);

	if (!done) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_suspend_complete done: acks pending\n"));
		return;
	}
	/*
	 * Now that we are done with suspending all the remote importers
	 * time to quiesce the local exporters
	 */
	exporter_quiesce();

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_suspend_complete done\n"));
}

static void
exporter_quiesce()
{
	int		i, e;
	rsmresource_t	*current;
	rsmseg_t	*seg;
	adapter_t	*adapter;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "exporter_quiesce enter\n"));
	/*
	 * The importers send a SUSPEND_COMPLETE to the exporter node
	 *	Unpublish, unbind the export segment and
	 *	move the segments to the EXPORT_QUIESCED state
	 */

	rw_enter(&rsm_export_segs.rsmhash_rw, RW_READER);

	for (i = 0; i < rsm_hash_size; i++) {
		current = rsm_export_segs.bucket[i];
		while (current != NULL) {
			seg = (rsmseg_t *)current;
			rsmseglock_acquire(seg);
			if (current->rsmrc_state ==
			    RSM_STATE_EXPORT_QUIESCING) {
				adapter = seg->s_adapter;
				/*
				 * some local memory handles are not published
				 * check if it was published
				 */
				if ((seg->s_acl == NULL) ||
				    (seg->s_acl[0].ae_node != my_nodeid) ||
				    (seg->s_acl[0].ae_permission != 0)) {

					e = adapter->rsmpi_ops->rsm_unpublish(
					    seg->s_handle.out);
					DBG_PRINTF((category, RSM_DEBUG,
					    "exporter_quiesce:unpub %d\n", e));

					e = adapter->rsmpi_ops->rsm_seg_destroy(
					    seg->s_handle.out);

					DBG_PRINTF((category, RSM_DEBUG,
					    "exporter_quiesce:destroy %d\n",
					    e));
				}

				(void) rsm_unbind_pages(seg);
				seg->s_state = RSM_STATE_EXPORT_QUIESCED;
				cv_broadcast(&seg->s_cv);
			}
			rsmseglock_release(seg);
			current = current->rsmrc_next;
		}
	}
	rw_exit(&rsm_export_segs.rsmhash_rw);

	/*
	 * All the local segments we are done with the pre-del processing
	 * - time to move to PREDEL_COMPLETED.
	 */

	mutex_enter(&rsm_drv_data.drv_lock);

	ASSERT(rsm_drv_data.drv_state == RSM_DRV_PREDEL_STARTED);

	rsm_drv_data.drv_state = RSM_DRV_PREDEL_COMPLETED;

	cv_broadcast(&rsm_drv_data.drv_cv);

	mutex_exit(&rsm_drv_data.drv_lock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "exporter_quiesce done\n"));
}

static void
importer_suspend(rsm_node_id_t src_node)
{
	int		i;
	int		susp_flg; /* true means already suspended */
	int		num_importers;
	rsmresource_t	*p = NULL, *curp;
	rsmhash_table_t *rhash = &rsm_import_segs;
	rsmseg_t	*seg;
	rsmipc_request_t request;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "importer_suspend enter\n"));

	rw_enter(&rhash->rsmhash_rw, RW_READER);
	for (i = 0; i < rsm_hash_size; i++) {
		p = rhash->bucket[i];

		/*
		 * Suspend all importers with same <node, key> pair.
		 * After the last one of the shared importers has been
		 * suspended - suspend the shared mappings/connection.
		 */
		for (; p; p = p->rsmrc_next) {
			rsmseg_t *first = (rsmseg_t *)p;
			if ((first->s_node != src_node) ||
			    (first->s_state == RSM_STATE_DISCONNECT))
				continue; /* go to next entry */
			/*
			 * search the rest of the bucket for
			 * other siblings (imprtrs with the same key)
			 * of "first" and suspend them.
			 * All importers with same key fall in
			 * the same bucket.
			 */
			num_importers = 0;
			for (curp = p; curp; curp = curp->rsmrc_next) {
				seg = (rsmseg_t *)curp;

				rsmseglock_acquire(seg);

				if ((seg->s_node != first->s_node) ||
				    (seg->s_key != first->s_key) ||
				    (seg->s_state == RSM_STATE_DISCONNECT)) {
					/*
					 * either not a peer segment or its a
					 * disconnected segment - skip it
					 */
					rsmseglock_release(seg);
					continue;
				}

				rsmseg_suspend(seg, &susp_flg);

				if (susp_flg) { /* seg already suspended */
					rsmseglock_release(seg);
					break; /* the inner for loop */
				}

				num_importers++;
				rsmsharelock_acquire(seg);
				/*
				 * we've processed all importers that are
				 * siblings of "first"
				 */
				if (num_importers ==
				    seg->s_share->rsmsi_refcnt) {
					rsmsharelock_release(seg);
					rsmseglock_release(seg);
					break;
				}
				rsmsharelock_release(seg);
				rsmseglock_release(seg);
			}

			/*
			 * All the importers with the same key and
			 * nodeid as "first" have been suspended.
			 * Now suspend the shared connect/mapping.
			 * This is done only once.
			 */
			if (!susp_flg) {
				rsmsegshare_suspend(seg);
			}
		}
	}

	rw_exit(&rhash->rsmhash_rw);

	/* send an ACK for SUSPEND message */
	request.rsmipc_hdr.rsmipc_type = RSMIPC_MSG_SUSPEND_DONE;
	(void) rsmipc_send(src_node, &request, RSM_NO_REPLY);


	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "importer_suspend done\n"));

}

static void
rsmseg_suspend(rsmseg_t *seg, int *susp_flg)
{
	int		recheck_state;
	rsmcookie_t	*hdl;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmseg_suspend enter: key=%u\n", seg->s_key));

	*susp_flg = 0;

	ASSERT(rsmseglock_held(seg));
	/* wait if putv/getv is in progress */
	while (seg->s_rdmacnt > 0)
		cv_wait(&seg->s_cv, &seg->s_lock);

	do {
		recheck_state = 0;

		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmseg_suspend:segment %x state=%d\n",
		    seg->s_key, seg->s_state));

		switch (seg->s_state) {
		case RSM_STATE_NEW:
			/* not a valid state */
			break;
		case RSM_STATE_CONNECTING:
			seg->s_state = RSM_STATE_ABORT_CONNECT;
			break;
		case RSM_STATE_ABORT_CONNECT:
			break;
		case RSM_STATE_CONNECT:
			seg->s_handle.in = NULL;
			seg->s_state = RSM_STATE_CONN_QUIESCE;
			break;
		case RSM_STATE_MAPPING:
			/* wait until segment leaves the mapping state */
			while (seg->s_state == RSM_STATE_MAPPING)
				cv_wait(&seg->s_cv, &seg->s_lock);
			recheck_state = 1;
			break;
		case RSM_STATE_ACTIVE:
			/* unload the mappings */
			if (seg->s_ckl != NULL) {
				hdl = seg->s_ckl;
				for (; hdl != NULL; hdl = hdl->c_next) {
					(void) devmap_unload(hdl->c_dhp,
					    hdl->c_off, hdl->c_len);
				}
			}
			seg->s_mapinfo = NULL;
			seg->s_state = RSM_STATE_MAP_QUIESCE;
			break;
		case RSM_STATE_CONN_QUIESCE:
			/* FALLTHRU */
		case RSM_STATE_MAP_QUIESCE:
			/* rsmseg_suspend already done for seg */
			*susp_flg = 1;
			break;
		case RSM_STATE_DISCONNECT:
			break;
		default:
			ASSERT(0); /* invalid state */
		}
	} while (recheck_state);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmseg_suspend done\n"));
}

static void
rsmsegshare_suspend(rsmseg_t *seg)
{
	int			e;
	adapter_t		*adapter;
	rsm_import_share_t	*sharedp;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmsegshare_suspend enter\n"));

	rsmseglock_acquire(seg);
	rsmsharelock_acquire(seg);

	sharedp = seg->s_share;
	adapter = seg->s_adapter;
	switch (sharedp->rsmsi_state) {
	case RSMSI_STATE_NEW:
		break;
	case RSMSI_STATE_CONNECTING:
		sharedp->rsmsi_state = RSMSI_STATE_ABORT_CONNECT;
		break;
	case RSMSI_STATE_ABORT_CONNECT:
		break;
	case RSMSI_STATE_CONNECTED:
		/* do the rsmpi disconnect */
		if (sharedp->rsmsi_node != my_nodeid) {
			e = adapter->rsmpi_ops->
			    rsm_disconnect(sharedp->rsmsi_handle);

			DBG_PRINTF((category, RSM_DEBUG,
			    "rsm:rsmpi disconnect seg=%x:err=%d\n",
			    sharedp->rsmsi_segid, e));
		}

		sharedp->rsmsi_handle = NULL;

		sharedp->rsmsi_state = RSMSI_STATE_CONN_QUIESCE;
		break;
	case RSMSI_STATE_CONN_QUIESCE:
		break;
	case RSMSI_STATE_MAPPED:
		/* do the rsmpi unmap and disconnect */
		if (sharedp->rsmsi_node != my_nodeid) {
			e = adapter->rsmpi_ops->rsm_unmap(seg->s_handle.in);

			DBG_PRINTF((category, RSM_DEBUG,
			    "rsmshare_suspend: rsmpi unmap %d\n", e));

			e = adapter->rsmpi_ops->
			    rsm_disconnect(sharedp->rsmsi_handle);
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsm:rsmpi disconnect seg=%x:err=%d\n",
			    sharedp->rsmsi_segid, e));
		}

		sharedp->rsmsi_handle = NULL;

		sharedp->rsmsi_state = RSMSI_STATE_MAP_QUIESCE;
		break;
	case RSMSI_STATE_MAP_QUIESCE:
		break;
	case RSMSI_STATE_DISCONNECTED:
		break;
	default:
		ASSERT(0); /* invalid state */
	}

	rsmsharelock_release(seg);
	rsmseglock_release(seg);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmsegshare_suspend done\n"));
}

/*
 * This should get called on receiving a RESUME message or from
 * the pathmanger if the node undergoing DR dies.
 */
static void
importer_resume(rsm_node_id_t src_node)
{
	int		i;
	rsmresource_t	*p = NULL;
	rsmhash_table_t *rhash = &rsm_import_segs;
	void		*cookie;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "importer_resume enter\n"));

	rw_enter(&rhash->rsmhash_rw, RW_READER);

	for (i = 0; i < rsm_hash_size; i++) {
		p = rhash->bucket[i];

		for (; p; p = p->rsmrc_next) {
			rsmseg_t *seg = (rsmseg_t *)p;

			rsmseglock_acquire(seg);

			/* process only importers of node undergoing DR */
			if (seg->s_node != src_node) {
				rsmseglock_release(seg);
				continue;
			}

			if (rsmseg_resume(seg, &cookie) != RSM_SUCCESS) {
				rsmipc_request_t	request;
				/*
				 * rsmpi map/connect failed
				 * inform the exporter so that it can
				 * remove the importer.
				 */
				request.rsmipc_hdr.rsmipc_type =
				    RSMIPC_MSG_NOTIMPORTING;
				request.rsmipc_key = seg->s_segid;
				request.rsmipc_segment_cookie = cookie;
				rsmseglock_release(seg);
				(void) rsmipc_send(seg->s_node, &request,
				    RSM_NO_REPLY);
			} else {
				rsmseglock_release(seg);
			}
		}
	}

	rw_exit(&rhash->rsmhash_rw);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "importer_resume done\n"));
}

static int
rsmseg_resume(rsmseg_t *seg, void **cookie)
{
	int			e;
	int			retc;
	off_t			dev_offset;
	size_t			maplen;
	uint_t			maxprot;
	rsm_mapinfo_t		*p;
	rsmcookie_t		*hdl;
	rsm_import_share_t	*sharedp;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmseg_resume enter: key=%u\n", seg->s_key));

	*cookie = NULL;

	ASSERT(rsmseglock_held(seg));

	if ((seg->s_state != RSM_STATE_CONN_QUIESCE) &&
	    (seg->s_state != RSM_STATE_MAP_QUIESCE)) {
		return (RSM_SUCCESS);
	}

	sharedp = seg->s_share;

	rsmsharelock_acquire(seg);

	/* resume the shared connection and/or mapping */
	retc = rsmsegshare_resume(seg);

	if (seg->s_state == RSM_STATE_CONN_QUIESCE) {
		/* shared state can either be connected or mapped */
		if ((sharedp->rsmsi_state == RSMSI_STATE_CONNECTED) ||
		    (sharedp->rsmsi_state == RSMSI_STATE_MAPPED)) {
			ASSERT(retc == RSM_SUCCESS);
			seg->s_handle.in = sharedp->rsmsi_handle;
			rsmsharelock_release(seg);
			seg->s_state = RSM_STATE_CONNECT;

		} else { /* error in rsmpi connect during resume */
			seg->s_handle.in = NULL;
			seg->s_state = RSM_STATE_DISCONNECT;

			sharedp->rsmsi_refcnt--;
			cookie = (void *)sharedp->rsmsi_cookie;

			if (sharedp->rsmsi_refcnt == 0) {
				ASSERT(sharedp->rsmsi_mapcnt == 0);
				rsmsharelock_release(seg);

				/* clean up the shared data structure */
				mutex_destroy(&sharedp->rsmsi_lock);
				cv_destroy(&sharedp->rsmsi_cv);
				kmem_free((void *)(sharedp),
				    sizeof (rsm_import_share_t));

			} else {
				rsmsharelock_release(seg);
			}
			/*
			 * The following needs to be done after any
			 * rsmsharelock calls which use seg->s_share.
			 */
			seg->s_share = NULL;
		}

		/* signal any waiting segment */
		cv_broadcast(&seg->s_cv);

		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmseg_resume done:state=%d\n", seg->s_state));
		return (retc);
	}

	ASSERT(seg->s_state == RSM_STATE_MAP_QUIESCE);

	/* Setup protections for remap */
	maxprot = PROT_USER;
	if (seg->s_mode & RSM_PERM_READ) {
		maxprot |= PROT_READ;
	}
	if (seg->s_mode & RSM_PERM_WRITE) {
		maxprot |= PROT_WRITE;
	}

	if (sharedp->rsmsi_state != RSMSI_STATE_MAPPED) {
		/* error in rsmpi connect or map during resume */

		/* remap to trash page */
		ASSERT(seg->s_ckl != NULL);

		for (hdl = seg->s_ckl; hdl != NULL; hdl = hdl->c_next) {
			e = devmap_umem_remap(hdl->c_dhp, rsm_dip,
			    remap_cookie, hdl->c_off, hdl->c_len,
			    maxprot, 0, NULL);

			DBG_PRINTF((category, RSM_ERR,
			    "rsmseg_resume:remap=%d\n", e));
		}

		seg->s_handle.in = NULL;
		seg->s_state = RSM_STATE_DISCONNECT;

		sharedp->rsmsi_refcnt--;

		sharedp->rsmsi_mapcnt--;
		seg->s_mapinfo = NULL;

		if (sharedp->rsmsi_refcnt == 0) {
			ASSERT(sharedp->rsmsi_mapcnt == 0);
			rsmsharelock_release(seg);

			/* clean up the shared data structure */
			mutex_destroy(&sharedp->rsmsi_lock);
			cv_destroy(&sharedp->rsmsi_cv);
			kmem_free((void *)(sharedp),
			    sizeof (rsm_import_share_t));

		} else {
			rsmsharelock_release(seg);
		}
		/*
		 * The following needs to be done after any
		 * rsmsharelock calls which use seg->s_share.
		 */
		seg->s_share = NULL;

		/* signal any waiting segment */
		cv_broadcast(&seg->s_cv);

		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmseg_resume done:seg=%x,err=%d\n",
		    seg->s_key, retc));
		return (retc);

	}

	seg->s_handle.in = sharedp->rsmsi_handle;

	if (seg->s_node == my_nodeid) { /* loopback */
		ASSERT(seg->s_mapinfo == NULL);

		for (hdl = seg->s_ckl; hdl != NULL; hdl = hdl->c_next) {
			e = devmap_umem_remap(hdl->c_dhp,
			    rsm_dip, seg->s_cookie,
			    hdl->c_off, hdl->c_len,
			    maxprot, 0, NULL);

			DBG_PRINTF((category, RSM_ERR,
			    "rsmseg_resume:remap=%d\n", e));
		}
	} else { /* remote exporter */
		/* remap to the new rsmpi maps */
		seg->s_mapinfo = sharedp->rsmsi_mapinfo;

		for (hdl = seg->s_ckl; hdl != NULL; hdl = hdl->c_next) {
			p = rsm_get_mapinfo(seg, hdl->c_off, hdl->c_len,
			    &dev_offset, &maplen);
			e = devmap_devmem_remap(hdl->c_dhp,
			    p->dip, p->dev_register, dev_offset,
			    maplen, maxprot, 0, NULL);

			DBG_PRINTF((category, RSM_ERR,
			    "rsmseg_resume:remap=%d\n", e));
		}
	}

	rsmsharelock_release(seg);

	seg->s_state = RSM_STATE_ACTIVE;
	cv_broadcast(&seg->s_cv);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmseg_resume done\n"));

	return (retc);
}

static int
rsmsegshare_resume(rsmseg_t *seg)
{
	int			e = RSM_SUCCESS;
	adapter_t		*adapter;
	rsm_import_share_t	*sharedp;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmsegshare_resume enter\n"));

	ASSERT(rsmseglock_held(seg));
	ASSERT(rsmsharelock_held(seg));

	sharedp = seg->s_share;

	/*
	 * If we are not in a xxxx_QUIESCE state that means shared
	 * connect/mapping processing has been already been done
	 * so return success.
	 */
	if ((sharedp->rsmsi_state != RSMSI_STATE_CONN_QUIESCE) &&
	    (sharedp->rsmsi_state != RSMSI_STATE_MAP_QUIESCE)) {
		return (RSM_SUCCESS);
	}

	adapter = seg->s_adapter;

	if (sharedp->rsmsi_node != my_nodeid) {
		rsm_addr_t	hwaddr;
		hwaddr = get_remote_hwaddr(adapter, sharedp->rsmsi_node);

		e = adapter->rsmpi_ops->rsm_connect(
		    adapter->rsmpi_handle, hwaddr,
		    sharedp->rsmsi_segid, &sharedp->rsmsi_handle);

		DBG_PRINTF((category, RSM_DEBUG,
		    "rsmsegshare_resume:rsmpi connect seg=%x:err=%d\n",
		    sharedp->rsmsi_segid, e));

		if (e != RSM_SUCCESS) {
			/* when do we send the NOT_IMPORTING message */
			sharedp->rsmsi_handle = NULL;
			sharedp->rsmsi_state = RSMSI_STATE_DISCONNECTED;
			/* signal any waiting segment */
			cv_broadcast(&sharedp->rsmsi_cv);
			return (e);
		}
	}

	if (sharedp->rsmsi_state == RSMSI_STATE_CONN_QUIESCE) {
		sharedp->rsmsi_state = RSMSI_STATE_CONNECTED;
		/* signal any waiting segment */
		cv_broadcast(&sharedp->rsmsi_cv);
		return (e);
	}

	ASSERT(sharedp->rsmsi_state == RSMSI_STATE_MAP_QUIESCE);

	/* do the rsmpi map of the whole segment here */
	if (sharedp->rsmsi_node != my_nodeid) {
		size_t mapped_len;
		rsm_mapinfo_t *p;

		/*
		 * We need to do rsmpi maps with <off, lens> identical to
		 * the old mapinfo list because the segment mapping handles
		 * dhp and such need the fragmentation of rsmpi maps to be
		 * identical to what it was during the mmap of the segment
		 */
		p = sharedp->rsmsi_mapinfo;

		while (p != NULL) {
			mapped_len = 0;

			e = adapter->rsmpi_ops->rsm_map(
			    sharedp->rsmsi_handle, p->start_offset,
			    p->individual_len, &mapped_len,
			    &p->dip, &p->dev_register, &p->dev_offset,
			    NULL, NULL);

			if (e != 0) {
				DBG_PRINTF((category, RSM_ERR,
				    "rsmsegshare_resume: rsmpi map err=%d\n",
				    e));
				break;
			}

			if (mapped_len != p->individual_len) {
				DBG_PRINTF((category, RSM_ERR,
				    "rsmsegshare_resume: rsmpi maplen"
				    "< reqlen=%lx\n", mapped_len));
				e = RSMERR_BAD_LENGTH;
				break;
			}

			p = p->next;

		}


		if (e != RSM_SUCCESS) { /* rsmpi map failed */
			int	err;
			/* Check if this is the first rsm_map */
			if (p != sharedp->rsmsi_mapinfo) {
				/*
				 * A single rsm_unmap undoes multiple rsm_maps.
				 */
				(void) seg->s_adapter->rsmpi_ops->
				    rsm_unmap(sharedp->rsmsi_handle);
			}

			rsm_free_mapinfo(sharedp->rsmsi_mapinfo);
			sharedp->rsmsi_mapinfo = NULL;

			err = adapter->rsmpi_ops->
			    rsm_disconnect(sharedp->rsmsi_handle);

			DBG_PRINTF((category, RSM_DEBUG,
			    "rsmsegshare_resume:disconn seg=%x:err=%d\n",
			    sharedp->rsmsi_segid, err));

			sharedp->rsmsi_handle = NULL;
			sharedp->rsmsi_state = RSMSI_STATE_DISCONNECTED;

			/* signal the waiting segments */
			cv_broadcast(&sharedp->rsmsi_cv);
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsmsegshare_resume done: rsmpi map err\n"));
			return (e);
		}
	}

	sharedp->rsmsi_state = RSMSI_STATE_MAPPED;

	/* signal any waiting segment */
	cv_broadcast(&sharedp->rsmsi_cv);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmsegshare_resume done\n"));

	return (e);
}

/*
 * this is the routine that gets called by recv_taskq which is the
 * thread that processes messages that are flow-controlled.
 */
static void
rsm_intr_proc_deferred(void *arg)
{
	path_t			*path = (path_t *)arg;
	rsmipc_request_t	*msg;
	rsmipc_msghdr_t		*msghdr;
	rsm_node_id_t		src_node;
	msgbuf_elem_t		*head;
	int			e;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_intr_proc_deferred enter\n"));

	mutex_enter(&path->mutex);

	/* use the head of the msgbuf_queue */
	head = rsmka_gethead_msgbuf(path);

	mutex_exit(&path->mutex);

	msg = (rsmipc_request_t *)&(head->msg);
	msghdr = (rsmipc_msghdr_t *)msg;

	src_node = msghdr->rsmipc_src;

	/*
	 * messages that need to send a reply should check the message version
	 * before processing the message. And all messages that need to
	 * send a reply should be processed here by the worker thread.
	 */
	switch (msghdr->rsmipc_type) {
	case RSMIPC_MSG_SEGCONNECT:
		if (msghdr->rsmipc_version != RSM_VERSION) {
			rsmipc_reply_t reply;
			reply.rsmipc_status = RSMERR_BAD_DRIVER_VERSION;
			reply.rsmipc_hdr.rsmipc_type = RSMIPC_MSG_REPLY;
			reply.rsmipc_hdr.rsmipc_cookie = msghdr->rsmipc_cookie;
			(void) rsmipc_send(msghdr->rsmipc_src, NULL, &reply);
		} else {
			rsm_intr_segconnect(src_node, msg);
		}
		break;
	case RSMIPC_MSG_DISCONNECT:
		rsm_force_unload(src_node, msg->rsmipc_key, DISCONNECT);
		break;
	case RSMIPC_MSG_SUSPEND:
		importer_suspend(src_node);
		break;
	case RSMIPC_MSG_SUSPEND_DONE:
		rsm_suspend_complete(src_node, 0);
		break;
	case RSMIPC_MSG_RESUME:
		importer_resume(src_node);
		break;
	default:
		ASSERT(0);
	}

	mutex_enter(&path->mutex);

	rsmka_dequeue_msgbuf(path);

	/* incr procmsg_cnt can be at most RSMIPC_MAX_MESSAGES */
	if (path->procmsg_cnt < RSMIPC_MAX_MESSAGES)
		path->procmsg_cnt++;

	ASSERT(path->procmsg_cnt <= RSMIPC_MAX_MESSAGES);

	/* No need to send credits if path is going down */
	if ((path->state == RSMKA_PATH_ACTIVE) &&
	    (path->procmsg_cnt >= RSMIPC_LOTSFREE_MSGBUFS)) {
		/*
		 * send credits and reset procmsg_cnt if success otherwise
		 * credits will be sent after processing the next message
		 */
		e = rsmipc_send_controlmsg(path, RSMIPC_MSG_CREDIT);
		if (e == 0)
			path->procmsg_cnt = 0;
		else
			DBG_PRINTF((category, RSM_ERR,
			    "rsm_intr_proc_deferred:send credits err=%d\n", e));
	}

	/*
	 * decrement the path refcnt since we incremented it in
	 * rsm_intr_callback_dispatch
	 */
	PATH_RELE_NOLOCK(path);

	mutex_exit(&path->mutex);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_intr_proc_deferred done\n"));
}

/*
 * Flow-controlled messages are enqueued and dispatched onto a taskq here
 */
static void
rsm_intr_callback_dispatch(void *data, rsm_addr_t src_hwaddr,
    rsm_intr_hand_arg_t arg)
{
	srv_handler_arg_t	*hdlr_argp = (srv_handler_arg_t *)arg;
	path_t			*path;
	rsmipc_msghdr_t *msghdr = (rsmipc_msghdr_t *)data;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_intr_callback_dispatch enter\n"));
	ASSERT(data && hdlr_argp);

	/* look up the path - incr the path refcnt */
	path = rsm_find_path(hdlr_argp->adapter_name,
	    hdlr_argp->adapter_instance, src_hwaddr);

	/* the path has been removed - drop this message */
	if (path == NULL) {
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_intr_callback_dispatch done: msg dropped\n"));
		return;
	}
	/* the path is not active - don't accept new messages */
	if (path->state != RSMKA_PATH_ACTIVE) {
		PATH_RELE_NOLOCK(path);
		mutex_exit(&path->mutex);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_intr_callback_dispatch done: msg dropped"
		    " path=%lx !ACTIVE\n", path));
		return;
	}

	/*
	 * Check if this message was sent to an older incarnation
	 * of the path/sendq.
	 */
	if (path->local_incn != msghdr->rsmipc_incn) {
		/* decrement the refcnt */
		PATH_RELE_NOLOCK(path);
		mutex_exit(&path->mutex);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_intr_callback_dispatch done: old incn %lld\n",
		    msghdr->rsmipc_incn));
		return;
	}

	/* copy and enqueue msg on the path's msgbuf queue */
	rsmka_enqueue_msgbuf(path, data);

	/*
	 * schedule task to process messages - ignore retval from
	 * task_dispatch because we sender cannot send more than
	 * what receiver can handle.
	 */
	(void) taskq_dispatch(path->recv_taskq,
	    rsm_intr_proc_deferred, path, KM_NOSLEEP);

	mutex_exit(&path->mutex);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_intr_callback_dispatch done\n"));
}

/*
 * This procedure is called from rsm_srv_func when a remote node creates a
 * a send queue.  This event is used as a hint that an  earlier failed
 * attempt to create a send queue to that remote node may now succeed and
 * should be retried.  Indication of an earlier failed attempt is provided
 * by the RSMKA_SQCREATE_PENDING flag.
 */
static void
rsm_sqcreateop_callback(rsm_addr_t src_hwaddr, rsm_intr_hand_arg_t arg)
{
	srv_handler_arg_t	*hdlr_argp = (srv_handler_arg_t *)arg;
	path_t			*path;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_sqcreateop_callback enter\n"));

	/* look up the path - incr the path refcnt */
	path = rsm_find_path(hdlr_argp->adapter_name,
	    hdlr_argp->adapter_instance, src_hwaddr);

	if (path == NULL) {
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_sqcreateop_callback done: no path\n"));
		return;
	}

	if ((path->state == RSMKA_PATH_UP) &&
	    (path->flags & RSMKA_SQCREATE_PENDING)) {
		/*
		 * previous attempt to create sendq had failed, retry
		 * it and move to RSMKA_PATH_ACTIVE state if successful.
		 * the refcnt will be decremented in the do_deferred_work
		 */
		(void) rsmka_do_path_active(path, RSMKA_NO_SLEEP);
	} else {
		/* decrement the refcnt */
		PATH_RELE_NOLOCK(path);
	}
	mutex_exit(&path->mutex);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_sqcreateop_callback done\n"));
}

static void
rsm_intr_callback(void *data, rsm_addr_t src_hwaddr, rsm_intr_hand_arg_t arg)
{
	rsmipc_msghdr_t *msghdr = (rsmipc_msghdr_t *)data;
	rsmipc_request_t *msg = (rsmipc_request_t *)data;
	rsmipc_controlmsg_t *ctrlmsg = (rsmipc_controlmsg_t *)data;
	rsm_node_id_t src_node;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_intr_callback enter:"
	    "src=%d, type=%d\n", msghdr->rsmipc_src,
	    msghdr->rsmipc_type));

	/*
	 * Check for the version number in the msg header. If it is not
	 * RSM_VERSION, drop the message. In the future, we need to manage
	 * incompatible version numbers in some way
	 */
	if (msghdr->rsmipc_version != RSM_VERSION) {
		DBG_PRINTF((category, RSM_ERR, "wrong KA version\n"));
		/*
		 * Drop requests that don't have a reply right here
		 * Request with reply will send a BAD_VERSION reply
		 * when they get processed by the worker thread.
		 */
		if (msghdr->rsmipc_type != RSMIPC_MSG_SEGCONNECT) {
			return;
		}

	}

	src_node = msghdr->rsmipc_src;

	switch (msghdr->rsmipc_type) {
	case RSMIPC_MSG_SEGCONNECT:
	case RSMIPC_MSG_DISCONNECT:
	case RSMIPC_MSG_SUSPEND:
	case RSMIPC_MSG_SUSPEND_DONE:
	case RSMIPC_MSG_RESUME:
		/*
		 * These message types are handled by a worker thread using
		 * the flow-control algorithm.
		 * Any message processing that does one or more of the
		 * following should be handled in a worker thread.
		 *	- allocates resources and might sleep
		 *	- makes RSMPI calls down to the interconnect driver
		 *	this by defn include requests with reply.
		 *	- takes a long duration of time
		 */
		rsm_intr_callback_dispatch(data, src_hwaddr, arg);
		break;
	case RSMIPC_MSG_NOTIMPORTING:
		importer_list_rm(src_node, msg->rsmipc_key,
		    msg->rsmipc_segment_cookie);
		break;
	case RSMIPC_MSG_SQREADY:
		rsm_proc_sqready(data, src_hwaddr, arg);
		break;
	case RSMIPC_MSG_SQREADY_ACK:
		rsm_proc_sqready_ack(data, src_hwaddr, arg);
		break;
	case RSMIPC_MSG_CREDIT:
		rsm_add_credits(ctrlmsg, src_hwaddr, arg);
		break;
	case RSMIPC_MSG_REPLY:
		rsm_intr_reply(msghdr);
		break;
	case RSMIPC_MSG_BELL:
		rsm_intr_event(msg);
		break;
	case RSMIPC_MSG_IMPORTING:
		importer_list_add(src_node, msg->rsmipc_key,
		    msg->rsmipc_adapter_hwaddr,
		    msg->rsmipc_segment_cookie);
		break;
	case RSMIPC_MSG_REPUBLISH:
		importer_update(src_node, msg->rsmipc_key, msg->rsmipc_perm);
		break;
	default:
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_intr_callback: bad msg %lx type %d data %lx\n",
		    (size_t)msg, (int)(msghdr->rsmipc_type), (size_t)data));
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_intr_callback done\n"));

}

rsm_intr_hand_ret_t rsm_srv_func(rsm_controller_object_t *chd,
    rsm_intr_q_op_t opcode, rsm_addr_t src,
    void *data, size_t size, rsm_intr_hand_arg_t arg)
{
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_srv_func enter\n"));

	switch (opcode) {
	case RSM_INTR_Q_OP_CREATE:
		DBG_PRINTF((category, RSM_DEBUG, "rsm_srv_func:OP_CREATE\n"));
		rsm_sqcreateop_callback(src, arg);
		break;
	case RSM_INTR_Q_OP_DESTROY:
		DBG_PRINTF((category, RSM_DEBUG, "rsm_srv_func:OP_DESTROY\n"));
		break;
	case RSM_INTR_Q_OP_RECEIVE:
		rsm_intr_callback(data, src, arg);
		break;
	default:
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_srv_func: unknown opcode = %x\n", opcode));
	}

	chd = chd;
	size = size;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_srv_func done\n"));

	return (RSM_INTR_HAND_CLAIMED);
}

/* *************************** IPC slots ************************* */
static rsmipc_slot_t *
rsmipc_alloc()
{
	int i;
	rsmipc_slot_t *slot;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmipc_alloc enter\n"));

	/* try to find a free slot, if not wait */
	mutex_enter(&rsm_ipc.lock);

	while (rsm_ipc.count == 0) {
		rsm_ipc.wanted = 1;
		cv_wait(&rsm_ipc.cv, &rsm_ipc.lock);
	}

	/* An empty slot is available, find it */
	slot = &rsm_ipc.slots[0];
	for (i = 0; i < RSMIPC_SZ; i++, slot++) {
		if (RSMIPC_GET(slot, RSMIPC_FREE)) {
			RSMIPC_CLEAR(slot, RSMIPC_FREE);
			break;
		}
	}

	ASSERT(i < RSMIPC_SZ);
	rsm_ipc.count--;	/* one less is available */
	rsm_ipc.sequence++; /* new sequence */

	slot->rsmipc_cookie.ic.sequence = (uint_t)rsm_ipc.sequence;
	slot->rsmipc_cookie.ic.index = (uint_t)i;

	mutex_exit(&rsm_ipc.lock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmipc_alloc done\n"));

	return (slot);
}

static void
rsmipc_free(rsmipc_slot_t *slot)
{
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmipc_free enter\n"));

	ASSERT(MUTEX_HELD(&slot->rsmipc_lock));
	ASSERT(&rsm_ipc.slots[slot->rsmipc_cookie.ic.index] == slot);

	mutex_enter(&rsm_ipc.lock);

	RSMIPC_SET(slot, RSMIPC_FREE);

	slot->rsmipc_cookie.ic.sequence = 0;

	mutex_exit(&slot->rsmipc_lock);
	rsm_ipc.count++;
	ASSERT(rsm_ipc.count <= RSMIPC_SZ);
	if (rsm_ipc.wanted) {
		rsm_ipc.wanted = 0;
		cv_broadcast(&rsm_ipc.cv);
	}

	mutex_exit(&rsm_ipc.lock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmipc_free done\n"));
}

static int
rsmipc_send(rsm_node_id_t dest, rsmipc_request_t *req, rsmipc_reply_t *reply)
{
	int		e = 0;
	int		credit_check = 0;
	int		retry_cnt = 0;
	int		min_retry_cnt = 10;
	rsm_send_t	is;
	rsmipc_slot_t	*rslot;
	adapter_t	*adapter;
	path_t		*path;
	sendq_token_t	*sendq_token;
	sendq_token_t	*used_sendq_token = NULL;
	rsm_send_q_handle_t	ipc_handle;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmipc_send enter:dest=%d",
	    dest));

	/*
	 * Check if this is a local case
	 */
	if (dest == my_nodeid) {
		switch (req->rsmipc_hdr.rsmipc_type) {
		case RSMIPC_MSG_SEGCONNECT:
			reply->rsmipc_status = (short)rsmsegacl_validate(
			    req, dest, reply);
			break;
		case RSMIPC_MSG_BELL:
			req->rsmipc_hdr.rsmipc_src = dest;
			rsm_intr_event(req);
			break;
		case RSMIPC_MSG_IMPORTING:
			importer_list_add(dest, req->rsmipc_key,
			    req->rsmipc_adapter_hwaddr,
			    req->rsmipc_segment_cookie);
			break;
		case RSMIPC_MSG_NOTIMPORTING:
			importer_list_rm(dest, req->rsmipc_key,
			    req->rsmipc_segment_cookie);
			break;
		case RSMIPC_MSG_REPUBLISH:
			importer_update(dest, req->rsmipc_key,
			    req->rsmipc_perm);
			break;
		case RSMIPC_MSG_SUSPEND:
			importer_suspend(dest);
			break;
		case RSMIPC_MSG_SUSPEND_DONE:
			rsm_suspend_complete(dest, 0);
			break;
		case RSMIPC_MSG_RESUME:
			importer_resume(dest);
			break;
		default:
			ASSERT(0);
		}
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmipc_send done\n"));
		return (0);
	}

	if (dest >= MAX_NODES) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm: rsmipc_send bad node number %x\n", dest));
		return (RSMERR_REMOTE_NODE_UNREACHABLE);
	}

	/*
	 * Oh boy! we are going remote.
	 */

	/*
	 * identify if we need to have credits to send this message
	 * - only selected requests are flow controlled
	 */
	if (req != NULL) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmipc_send:request type=%d\n",
		    req->rsmipc_hdr.rsmipc_type));

		switch (req->rsmipc_hdr.rsmipc_type) {
		case RSMIPC_MSG_SEGCONNECT:
		case RSMIPC_MSG_DISCONNECT:
		case RSMIPC_MSG_IMPORTING:
		case RSMIPC_MSG_SUSPEND:
		case RSMIPC_MSG_SUSPEND_DONE:
		case RSMIPC_MSG_RESUME:
			credit_check = 1;
			break;
		default:
			credit_check = 0;
		}
	}

again:
	if (retry_cnt++ == min_retry_cnt) {
		/* backoff before further retries for 10ms */
		delay(drv_usectohz(10000));
		retry_cnt = 0; /* reset retry_cnt */
	}
	sendq_token = rsmka_get_sendq_token(dest, used_sendq_token);
	if (sendq_token == NULL) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm: rsmipc_send no device to reach node %d\n", dest));
		return (RSMERR_REMOTE_NODE_UNREACHABLE);
	}

	if ((sendq_token == used_sendq_token) &&
	    ((e == RSMERR_CONN_ABORTED) || (e == RSMERR_TIMEOUT) ||
	    (e == RSMERR_COMM_ERR_MAYBE_DELIVERED))) {
		rele_sendq_token(sendq_token);
		DBG_PRINTF((category, RSM_DEBUG, "rsmipc_send done=%d\n", e));
		return (RSMERR_CONN_ABORTED);
	} else
		used_sendq_token = sendq_token;

/* lint -save -e413 */
	path = SQ_TOKEN_TO_PATH(sendq_token);
	adapter = path->local_adapter;
/* lint -restore */
	ipc_handle = sendq_token->rsmpi_sendq_handle;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmipc_send: path=%lx sendq_hdl=%lx\n", path, ipc_handle));

	if (reply == NULL) {
		/* Send request without ack */
		/*
		 * Set the rsmipc_version number in the msghdr for KA
		 * communication versioning
		 */
		req->rsmipc_hdr.rsmipc_version = RSM_VERSION;
		req->rsmipc_hdr.rsmipc_src = my_nodeid;
		/*
		 * remote endpoints incn should match the value in our
		 * path's remote_incn field. No need to grab any lock
		 * since we have refcnted the path in rsmka_get_sendq_token
		 */
		req->rsmipc_hdr.rsmipc_incn = path->remote_incn;

		is.is_data = (void *)req;
		is.is_size = sizeof (*req);
		is.is_flags = RSM_INTR_SEND_DELIVER | RSM_INTR_SEND_SLEEP;
		is.is_wait = 0;

		if (credit_check) {
			mutex_enter(&path->mutex);
			/*
			 * wait till we recv credits or path goes down. If path
			 * goes down rsm_send will fail and we handle the error
			 * then
			 */
			while ((sendq_token->msgbuf_avail == 0) &&
			    (path->state == RSMKA_PATH_ACTIVE)) {
				e = cv_wait_sig(&sendq_token->sendq_cv,
				    &path->mutex);
				if (e == 0) {
					mutex_exit(&path->mutex);
					no_reply_cnt++;
					rele_sendq_token(sendq_token);
					DBG_PRINTF((category, RSM_DEBUG,
					    "rsmipc_send done: "
					    "cv_wait INTERRUPTED"));
					return (RSMERR_INTERRUPTED);
				}
			}

			/*
			 * path is not active retry on another path.
			 */
			if (path->state != RSMKA_PATH_ACTIVE) {
				mutex_exit(&path->mutex);
				rele_sendq_token(sendq_token);
				e = RSMERR_CONN_ABORTED;
				DBG_PRINTF((category, RSM_ERR,
				    "rsm: rsmipc_send: path !ACTIVE"));
				goto again;
			}

			ASSERT(sendq_token->msgbuf_avail > 0);

			/*
			 * reserve a msgbuf
			 */
			sendq_token->msgbuf_avail--;

			mutex_exit(&path->mutex);

			e = adapter->rsmpi_ops->rsm_send(ipc_handle, &is,
			    NULL);

			if (e != RSM_SUCCESS) {
				mutex_enter(&path->mutex);
				/*
				 * release the reserved msgbuf since
				 * the send failed
				 */
				sendq_token->msgbuf_avail++;
				cv_broadcast(&sendq_token->sendq_cv);
				mutex_exit(&path->mutex);
			}
		} else
			e = adapter->rsmpi_ops->rsm_send(ipc_handle, &is,
			    NULL);

		no_reply_cnt++;
		rele_sendq_token(sendq_token);
		if (e != RSM_SUCCESS) {
			DBG_PRINTF((category, RSM_ERR,
			    "rsm: rsmipc_send no reply send"
			    " err = %d no reply count = %d\n",
			    e, no_reply_cnt));
			ASSERT(e != RSMERR_QUEUE_FENCE_UP &&
			    e != RSMERR_BAD_BARRIER_HNDL);
			atomic_inc_64(&rsm_ipcsend_errcnt);
			goto again;
		} else {
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsmipc_send done\n"));
			return (e);
		}

	}

	if (req == NULL) {
		/* Send reply - No flow control is done for reply */
		/*
		 * Set the version in the msg header for KA communication
		 * versioning
		 */
		reply->rsmipc_hdr.rsmipc_version = RSM_VERSION;
		reply->rsmipc_hdr.rsmipc_src = my_nodeid;
		/* incn number is not used for reply msgs currently */
		reply->rsmipc_hdr.rsmipc_incn = path->remote_incn;

		is.is_data = (void *)reply;
		is.is_size = sizeof (*reply);
		is.is_flags = RSM_INTR_SEND_DELIVER | RSM_INTR_SEND_SLEEP;
		is.is_wait = 0;
		e = adapter->rsmpi_ops->rsm_send(ipc_handle, &is, NULL);
		rele_sendq_token(sendq_token);
		if (e != RSM_SUCCESS) {
			DBG_PRINTF((category, RSM_ERR,
			    "rsm: rsmipc_send reply send"
			    " err = %d\n", e));
			atomic_inc_64(&rsm_ipcsend_errcnt);
			goto again;
		} else {
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsmipc_send done\n"));
			return (e);
		}
	}

	/* Reply needed */
	rslot = rsmipc_alloc(); /* allocate a new ipc slot */

	mutex_enter(&rslot->rsmipc_lock);

	rslot->rsmipc_data = (void *)reply;
	RSMIPC_SET(rslot, RSMIPC_PENDING);

	while (RSMIPC_GET(rslot, RSMIPC_PENDING)) {
		/*
		 * Set the rsmipc_version number in the msghdr for KA
		 * communication versioning
		 */
		req->rsmipc_hdr.rsmipc_version = RSM_VERSION;
		req->rsmipc_hdr.rsmipc_src = my_nodeid;
		req->rsmipc_hdr.rsmipc_cookie = rslot->rsmipc_cookie;
		/*
		 * remote endpoints incn should match the value in our
		 * path's remote_incn field. No need to grab any lock
		 * since we have refcnted the path in rsmka_get_sendq_token
		 */
		req->rsmipc_hdr.rsmipc_incn = path->remote_incn;

		is.is_data = (void *)req;
		is.is_size = sizeof (*req);
		is.is_flags = RSM_INTR_SEND_DELIVER | RSM_INTR_SEND_SLEEP;
		is.is_wait = 0;
		if (credit_check) {

			mutex_enter(&path->mutex);
			/*
			 * wait till we recv credits or path goes down. If path
			 * goes down rsm_send will fail and we handle the error
			 * then.
			 */
			while ((sendq_token->msgbuf_avail == 0) &&
			    (path->state == RSMKA_PATH_ACTIVE)) {
				e = cv_wait_sig(&sendq_token->sendq_cv,
				    &path->mutex);
				if (e == 0) {
					mutex_exit(&path->mutex);
					RSMIPC_CLEAR(rslot, RSMIPC_PENDING);
					rsmipc_free(rslot);
					rele_sendq_token(sendq_token);
					DBG_PRINTF((category, RSM_DEBUG,
					    "rsmipc_send done: "
					    "cv_wait INTERRUPTED"));
					return (RSMERR_INTERRUPTED);
				}
			}

			/*
			 * path is not active retry on another path.
			 */
			if (path->state != RSMKA_PATH_ACTIVE) {
				mutex_exit(&path->mutex);
				RSMIPC_CLEAR(rslot, RSMIPC_PENDING);
				rsmipc_free(rslot);
				rele_sendq_token(sendq_token);
				e = RSMERR_CONN_ABORTED;
				DBG_PRINTF((category, RSM_ERR,
				    "rsm: rsmipc_send: path !ACTIVE"));
				goto again;
			}

			ASSERT(sendq_token->msgbuf_avail > 0);

			/*
			 * reserve a msgbuf
			 */
			sendq_token->msgbuf_avail--;

			mutex_exit(&path->mutex);

			e = adapter->rsmpi_ops->rsm_send(ipc_handle, &is,
			    NULL);

			if (e != RSM_SUCCESS) {
				mutex_enter(&path->mutex);
				/*
				 * release the reserved msgbuf since
				 * the send failed
				 */
				sendq_token->msgbuf_avail++;
				cv_broadcast(&sendq_token->sendq_cv);
				mutex_exit(&path->mutex);
			}
		} else
			e = adapter->rsmpi_ops->rsm_send(ipc_handle, &is,
			    NULL);

		if (e != RSM_SUCCESS) {
			DBG_PRINTF((category, RSM_ERR,
			    "rsm: rsmipc_send rsmpi send err = %d\n", e));
			RSMIPC_CLEAR(rslot, RSMIPC_PENDING);
			rsmipc_free(rslot);
			rele_sendq_token(sendq_token);
			atomic_inc_64(&rsm_ipcsend_errcnt);
			goto again;
		}

		/* wait for a reply signal, a SIGINT, or 5 sec. timeout */
		e = cv_reltimedwait_sig(&rslot->rsmipc_cv, &rslot->rsmipc_lock,
		    drv_usectohz(5000000), TR_CLOCK_TICK);
		if (e < 0) {
			/* timed out - retry */
			e = RSMERR_TIMEOUT;
		} else if (e == 0) {
			/* signalled - return error */
			e = RSMERR_INTERRUPTED;
			break;
		} else {
			e = RSM_SUCCESS;
		}
	}

	RSMIPC_CLEAR(rslot, RSMIPC_PENDING);
	rsmipc_free(rslot);
	rele_sendq_token(sendq_token);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmipc_send done=%d\n", e));
	return (e);
}

static int
rsm_send_notimporting(rsm_node_id_t dest, rsm_memseg_id_t segid,  void *cookie)
{
	rsmipc_request_t request;

	/*
	 *  inform the exporter to delete this importer
	 */
	request.rsmipc_hdr.rsmipc_type = RSMIPC_MSG_NOTIMPORTING;
	request.rsmipc_key = segid;
	request.rsmipc_segment_cookie = cookie;
	return (rsmipc_send(dest, &request, RSM_NO_REPLY));
}

static void
rsm_send_republish(rsm_memseg_id_t segid, rsmapi_access_entry_t	*acl,
    int acl_len, rsm_permission_t default_permission)
{
	int			i;
	importing_token_t	*token;
	rsmipc_request_t	request;
	republish_token_t	*republish_list = NULL;
	republish_token_t	*rp;
	rsm_permission_t	permission;
	int			index;

	/*
	 * send the new access mode to all the nodes that have imported
	 * this segment.
	 * If the new acl does not have a node that was present in
	 * the old acl a access permission of 0 is sent.
	 */

	index = rsmhash(segid);

	/*
	 * create a list of node/permissions to send the republish message
	 */
	mutex_enter(&importer_list.lock);

	token = importer_list.bucket[index];
	while (token != NULL) {
		if (segid == token->key) {
			permission = default_permission;

			for (i = 0; i < acl_len; i++) {
				if (token->importing_node == acl[i].ae_node) {
					permission = acl[i].ae_permission;
					break;
				}
			}
			rp = kmem_zalloc(sizeof (republish_token_t), KM_SLEEP);

			rp->key = segid;
			rp->importing_node = token->importing_node;
			rp->permission = permission;
			rp->next = republish_list;
			republish_list = rp;
		}
		token = token->next;
	}

	mutex_exit(&importer_list.lock);

	request.rsmipc_hdr.rsmipc_type = RSMIPC_MSG_REPUBLISH;
	request.rsmipc_key = segid;

	while (republish_list != NULL) {
		request.rsmipc_perm = republish_list->permission;
		(void) rsmipc_send(republish_list->importing_node,
		    &request, RSM_NO_REPLY);
		rp = republish_list;
		republish_list = republish_list->next;
		kmem_free(rp, sizeof (republish_token_t));
	}
}

static void
rsm_send_suspend()
{
	int			i, e;
	rsmipc_request_t 	request;
	list_element_t		*tokp;
	list_element_t		*head = NULL;
	importing_token_t	*token;
	DBG_PRINTF((RSM_KERNEL_AGENT | RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_send_suspend enter\n"));

	/*
	 * create a list of node to send the suspend message
	 *
	 * Currently the whole importer list is scanned and we obtain
	 * all the nodes - this basically gets all nodes that at least
	 * import one segment from the local node.
	 *
	 * no need to grab the rsm_suspend_list lock here since we are
	 * single threaded when suspend is called.
	 */

	mutex_enter(&importer_list.lock);
	for (i = 0; i < rsm_hash_size; i++) {

		token = importer_list.bucket[i];

		while (token != NULL) {

			tokp = head;

			/*
			 * make sure that the token's node
			 * is not already on the suspend list
			 */
			while (tokp != NULL) {
				if (tokp->nodeid == token->importing_node) {
					break;
				}
				tokp = tokp->next;
			}

			if (tokp == NULL) { /* not in suspend list */
				tokp = kmem_zalloc(sizeof (list_element_t),
				    KM_SLEEP);
				tokp->nodeid = token->importing_node;
				tokp->next = head;
				head = tokp;
			}

			token = token->next;
		}
	}
	mutex_exit(&importer_list.lock);

	if (head == NULL) { /* no importers so go ahead and quiesce segments */
		exporter_quiesce();
		return;
	}

	mutex_enter(&rsm_suspend_list.list_lock);
	ASSERT(rsm_suspend_list.list_head == NULL);
	/*
	 * update the suspend list righaway so that if a node dies the
	 * pathmanager can set the NODE dead flag
	 */
	rsm_suspend_list.list_head = head;
	mutex_exit(&rsm_suspend_list.list_lock);

	tokp = head;

	while (tokp != NULL) {
		request.rsmipc_hdr.rsmipc_type = RSMIPC_MSG_SUSPEND;
		e = rsmipc_send(tokp->nodeid, &request, RSM_NO_REPLY);
		/*
		 * Error in rsmipc_send currently happens due to inaccessibility
		 * of the remote node.
		 */
		if (e == RSM_SUCCESS) { /* send failed - don't wait for ack */
			tokp->flags |= RSM_SUSPEND_ACKPENDING;
		}

		tokp = tokp->next;
	}

	DBG_PRINTF((RSM_KERNEL_AGENT | RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_send_suspend done\n"));

}

static void
rsm_send_resume()
{
	rsmipc_request_t 	request;
	list_element_t		*elem, *head;

	/*
	 * save the suspend list so that we know where to send
	 * the resume messages and make the suspend list head
	 * NULL.
	 */
	mutex_enter(&rsm_suspend_list.list_lock);
	head = rsm_suspend_list.list_head;
	rsm_suspend_list.list_head = NULL;
	mutex_exit(&rsm_suspend_list.list_lock);

	while (head != NULL) {
		elem = head;
		head = head->next;

		request.rsmipc_hdr.rsmipc_type = RSMIPC_MSG_RESUME;

		(void) rsmipc_send(elem->nodeid, &request, RSM_NO_REPLY);

		kmem_free((void *)elem, sizeof (list_element_t));

	}

}

/*
 * This function takes path and sends a message using the sendq
 * corresponding to it. The RSMIPC_MSG_SQREADY, RSMIPC_MSG_SQREADY_ACK
 * and RSMIPC_MSG_CREDIT are sent using this function.
 */
int
rsmipc_send_controlmsg(path_t *path, int msgtype)
{
	int			e;
	int			retry_cnt = 0;
	int			min_retry_cnt = 10;
	adapter_t		*adapter;
	rsm_send_t		is;
	rsm_send_q_handle_t	ipc_handle;
	rsmipc_controlmsg_t	msg;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_FLOWCONTROL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmipc_send_controlmsg enter\n"));

	ASSERT(MUTEX_HELD(&path->mutex));

	adapter = path->local_adapter;

	DBG_PRINTF((category, RSM_DEBUG, "rsmipc_send_controlmsg:path=%lx "
	    "msgtype=%d %lx:%llx->%lx:%llx procmsg=%d\n", path, msgtype,
	    my_nodeid, adapter->hwaddr, path->remote_node,
	    path->remote_hwaddr, path->procmsg_cnt));

	if (path->state != RSMKA_PATH_ACTIVE) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmipc_send_controlmsg done: ! RSMKA_PATH_ACTIVE"));
		return (1);
	}

	ipc_handle = path->sendq_token.rsmpi_sendq_handle;

	msg.rsmipc_hdr.rsmipc_version = RSM_VERSION;
	msg.rsmipc_hdr.rsmipc_src = my_nodeid;
	msg.rsmipc_hdr.rsmipc_type = msgtype;
	msg.rsmipc_hdr.rsmipc_incn = path->remote_incn;

	if (msgtype == RSMIPC_MSG_CREDIT)
		msg.rsmipc_credits = path->procmsg_cnt;

	msg.rsmipc_local_incn = path->local_incn;

	msg.rsmipc_adapter_hwaddr = adapter->hwaddr;
	/* incr the sendq, path refcnt */
	PATH_HOLD_NOLOCK(path);
	SENDQ_TOKEN_HOLD(path);

	do {
		/* drop the path lock before doing the rsm_send */
		mutex_exit(&path->mutex);

		is.is_data = (void *)&msg;
		is.is_size = sizeof (msg);
		is.is_flags = RSM_INTR_SEND_DELIVER | RSM_INTR_SEND_SLEEP;
		is.is_wait = 0;

		e = adapter->rsmpi_ops->rsm_send(ipc_handle, &is, NULL);

		ASSERT(e != RSMERR_QUEUE_FENCE_UP &&
		    e != RSMERR_BAD_BARRIER_HNDL);

		mutex_enter(&path->mutex);

		if (e == RSM_SUCCESS) {
			break;
		}
		/* error counter for statistics */
		atomic_inc_64(&rsm_ctrlmsg_errcnt);

		DBG_PRINTF((category, RSM_ERR,
		    "rsmipc_send_controlmsg:rsm_send error=%d", e));

		if (++retry_cnt == min_retry_cnt) { /* backoff before retry */
			(void) cv_reltimedwait(&path->sendq_token.sendq_cv,
			    &path->mutex, drv_usectohz(10000), TR_CLOCK_TICK);
			retry_cnt = 0;
		}
	} while (path->state == RSMKA_PATH_ACTIVE);

	/* decrement the sendq,path refcnt that we incr before rsm_send */
	SENDQ_TOKEN_RELE(path);
	PATH_RELE_NOLOCK(path);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmipc_send_controlmsg done=%d", e));
	return (e);
}

/*
 * Called from rsm_force_unload and path_importer_disconnect. The memory
 * mapping for the imported segment is removed and the segment is
 * disconnected at the interconnect layer if disconnect_flag is TRUE.
 * rsm_force_unload will get disconnect_flag TRUE from rsm_intr_callback
 * and FALSE from rsm_rebind.
 *
 * When subsequent accesses cause page faulting, the dummy page is mapped
 * to resolve the fault, and the mapping generation number is incremented
 * so that the application can be notified on a close barrier operation.
 *
 * It is important to note that the caller of rsmseg_unload is responsible for
 * acquiring the segment lock before making a call to rsmseg_unload. This is
 * required to make the caller and rsmseg_unload thread safe. The segment lock
 * will be released by the rsmseg_unload function.
 */
void
rsmseg_unload(rsmseg_t *im_seg)
{
	rsmcookie_t		*hdl;
	void			*shared_cookie;
	rsmipc_request_t	request;
	uint_t			maxprot;

	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_INTR_CALLBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmseg_unload enter\n"));

	ASSERT(im_seg->s_hdr.rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT);

	/* wait until segment leaves the mapping state */
	while (im_seg->s_state == RSM_STATE_MAPPING)
		cv_wait(&im_seg->s_cv, &im_seg->s_lock);
	/*
	 * An unload is only necessary if the segment is connected. However,
	 * if the segment was on the import list in state RSM_STATE_CONNECTING
	 * then a connection was in progress. Change to RSM_STATE_NEW
	 * here to cause an early exit from the connection process.
	 */
	if (im_seg->s_state == RSM_STATE_NEW) {
		rsmseglock_release(im_seg);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmseg_unload done: RSM_STATE_NEW\n"));
		return;
	} else if (im_seg->s_state == RSM_STATE_CONNECTING) {
		im_seg->s_state = RSM_STATE_ABORT_CONNECT;
		rsmsharelock_acquire(im_seg);
		im_seg->s_share->rsmsi_state = RSMSI_STATE_ABORT_CONNECT;
		rsmsharelock_release(im_seg);
		rsmseglock_release(im_seg);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmseg_unload done: RSM_STATE_CONNECTING\n"));
		return;
	}

	if (im_seg->s_flags & RSM_FORCE_DISCONNECT) {
		if (im_seg->s_ckl != NULL) {
			int e;
			/* Setup protections for remap */
			maxprot = PROT_USER;
			if (im_seg->s_mode & RSM_PERM_READ) {
				maxprot |= PROT_READ;
			}
			if (im_seg->s_mode & RSM_PERM_WRITE) {
				maxprot |= PROT_WRITE;
			}
			hdl = im_seg->s_ckl;
			for (; hdl != NULL; hdl = hdl->c_next) {
				e = devmap_umem_remap(hdl->c_dhp, rsm_dip,
				    remap_cookie,
				    hdl->c_off, hdl->c_len,
				    maxprot, 0, NULL);

				DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
				    "remap returns %d\n", e));
			}
		}

		(void) rsm_closeconnection(im_seg, &shared_cookie);

		if (shared_cookie != NULL) {
			/*
			 * inform the exporting node so this import
			 * can be deleted from the list of importers.
			 */
			request.rsmipc_hdr.rsmipc_type =
			    RSMIPC_MSG_NOTIMPORTING;
			request.rsmipc_key = im_seg->s_segid;
			request.rsmipc_segment_cookie = shared_cookie;
			rsmseglock_release(im_seg);
			(void) rsmipc_send(im_seg->s_node, &request,
			    RSM_NO_REPLY);
		} else {
			rsmseglock_release(im_seg);
		}
	}
	else
		rsmseglock_release(im_seg);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmseg_unload done\n"));

}

/* ****************************** Importer Calls ************************ */

static int
rsm_access(uid_t owner, gid_t group, int perm, int mode, const struct cred *cr)
{
	int shifts = 0;

	if (crgetuid(cr) != owner) {
		shifts += 3;
		if (!groupmember(group, cr))
			shifts += 3;
	}

	mode &= ~(perm << shifts);

	if (mode == 0)
		return (0);

	return (secpolicy_rsm_access(cr, owner, mode));
}


static int
rsm_connect(rsmseg_t *seg, rsm_ioctlmsg_t *msg, cred_t *cred,
    intptr_t dataptr, int mode)
{
	int e;
	int			recheck_state = 0;
	void			*shared_cookie;
	rsmipc_request_t	request;
	rsmipc_reply_t		reply;
	rsm_permission_t	access;
	adapter_t		*adapter;
	rsm_addr_t		addr = 0;
	rsm_import_share_t	*sharedp;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IMPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_connect enter\n"));

	adapter = rsm_getadapter(msg, mode);
	if (adapter == NULL) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_connect done:ENODEV adapter=NULL\n"));
		return (RSMERR_CTLR_NOT_PRESENT);
	}

	if ((adapter == &loopback_adapter) && (msg->nodeid != my_nodeid)) {
		rsmka_release_adapter(adapter);
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_connect done:ENODEV loopback\n"));
		return (RSMERR_CTLR_NOT_PRESENT);
	}


	ASSERT(seg->s_hdr.rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT);
	ASSERT(seg->s_state == RSM_STATE_NEW);

	/*
	 * Translate perm to access
	 */
	if (msg->perm & ~RSM_PERM_RDWR) {
		rsmka_release_adapter(adapter);
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_connect done:EINVAL invalid perms\n"));
		return (RSMERR_BAD_PERMS);
	}
	access = 0;
	if (msg->perm & RSM_PERM_READ)
		access |= RSM_ACCESS_READ;
	if (msg->perm & RSM_PERM_WRITE)
		access |= RSM_ACCESS_WRITE;

	seg->s_node = msg->nodeid;

	/*
	 * Adding to the import list locks the segment; release the segment
	 * lock so we can get the reply for the send.
	 */
	e = rsmimport_add(seg, msg->key);
	if (e) {
		rsmka_release_adapter(adapter);
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_connect done:rsmimport_add failed %d\n", e));
		return (e);
	}
	seg->s_state = RSM_STATE_CONNECTING;

	/*
	 * Set the s_adapter field here so as to have a valid comparison of
	 * the adapter and the s_adapter value during rsmshare_get. For
	 * any error, set s_adapter to NULL before doing a release_adapter
	 */
	seg->s_adapter = adapter;

	rsmseglock_release(seg);

	/*
	 * get the pointer to the shared data structure; the
	 * shared data is locked and refcount has been incremented
	 */
	sharedp = rsmshare_get(msg->key, msg->nodeid, adapter, seg);

	ASSERT(rsmsharelock_held(seg));

	do {
		/* flag indicates whether we need to recheck the state */
		recheck_state = 0;
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_connect:RSMSI_STATE=%d\n", sharedp->rsmsi_state));
		switch (sharedp->rsmsi_state) {
		case RSMSI_STATE_NEW:
			sharedp->rsmsi_state = RSMSI_STATE_CONNECTING;
			break;
		case RSMSI_STATE_CONNECTING:
			/* FALLTHRU */
		case RSMSI_STATE_CONN_QUIESCE:
			/* FALLTHRU */
		case RSMSI_STATE_MAP_QUIESCE:
			/* wait for the state to change */
			while ((sharedp->rsmsi_state ==
			    RSMSI_STATE_CONNECTING) ||
			    (sharedp->rsmsi_state ==
			    RSMSI_STATE_CONN_QUIESCE) ||
			    (sharedp->rsmsi_state ==
			    RSMSI_STATE_MAP_QUIESCE)) {
				if (cv_wait_sig(&sharedp->rsmsi_cv,
				    &sharedp->rsmsi_lock) == 0) {
					/* signalled - clean up and return */
					rsmsharelock_release(seg);
					rsmimport_rm(seg);
					seg->s_adapter = NULL;
					rsmka_release_adapter(adapter);
					seg->s_state = RSM_STATE_NEW;
					DBG_PRINTF((category, RSM_ERR,
					    "rsm_connect done: INTERRUPTED\n"));
					return (RSMERR_INTERRUPTED);
				}
			}
			/*
			 * the state changed, loop back and check what it is
			 */
			recheck_state = 1;
			break;
		case RSMSI_STATE_ABORT_CONNECT:
			/* exit the loop and clean up further down */
			break;
		case RSMSI_STATE_CONNECTED:
			/* already connected, good - fall through */
		case RSMSI_STATE_MAPPED:
			/* already mapped, wow - fall through */
			/* access validation etc is done further down */
			break;
		case RSMSI_STATE_DISCONNECTED:
			/* disconnected - so reconnect now */
			sharedp->rsmsi_state = RSMSI_STATE_CONNECTING;
			break;
		default:
			ASSERT(0); /* Invalid State */
		}
	} while (recheck_state);

	if (sharedp->rsmsi_state == RSMSI_STATE_CONNECTING) {
		/* we are the first to connect */
		rsmsharelock_release(seg);

		if (msg->nodeid != my_nodeid) {
			addr = get_remote_hwaddr(adapter, msg->nodeid);

			if ((int64_t)addr < 0) {
				rsmsharelock_acquire(seg);
				rsmsharecv_signal(seg, RSMSI_STATE_CONNECTING,
				    RSMSI_STATE_NEW);
				rsmsharelock_release(seg);
				rsmimport_rm(seg);
				seg->s_adapter = NULL;
				rsmka_release_adapter(adapter);
				seg->s_state = RSM_STATE_NEW;
				DBG_PRINTF((category, RSM_ERR,
				    "rsm_connect done: hwaddr<0\n"));
				return (RSMERR_INTERNAL_ERROR);
			}
		} else {
			addr = adapter->hwaddr;
		}

		/*
		 * send request to node [src, dest, key, msgid] and get back
		 * [status, msgid, cookie]
		 */
		request.rsmipc_key = msg->key;
		/*
		 * we need the s_mode of the exporter so pass
		 * RSM_ACCESS_TRUSTED
		 */
		request.rsmipc_perm = RSM_ACCESS_TRUSTED;
		request.rsmipc_hdr.rsmipc_type = RSMIPC_MSG_SEGCONNECT;
		request.rsmipc_adapter_hwaddr = addr;
		request.rsmipc_segment_cookie = sharedp;

		e = (int)rsmipc_send(msg->nodeid, &request, &reply);
		if (e) {
			rsmsharelock_acquire(seg);
			rsmsharecv_signal(seg, RSMSI_STATE_CONNECTING,
			    RSMSI_STATE_NEW);
			rsmsharelock_release(seg);
			rsmimport_rm(seg);
			seg->s_adapter = NULL;
			rsmka_release_adapter(adapter);
			seg->s_state = RSM_STATE_NEW;
			DBG_PRINTF((category, RSM_ERR,
			    "rsm_connect done:rsmipc_send failed %d\n", e));
			return (e);
		}

		if (reply.rsmipc_status != RSM_SUCCESS) {
			rsmsharelock_acquire(seg);
			rsmsharecv_signal(seg, RSMSI_STATE_CONNECTING,
			    RSMSI_STATE_NEW);
			rsmsharelock_release(seg);
			rsmimport_rm(seg);
			seg->s_adapter = NULL;
			rsmka_release_adapter(adapter);
			seg->s_state = RSM_STATE_NEW;
			DBG_PRINTF((category, RSM_ERR,
			    "rsm_connect done:rsmipc_send reply err %d\n",
			    reply.rsmipc_status));
			return (reply.rsmipc_status);
		}

		rsmsharelock_acquire(seg);
		/* store the information recvd into the shared data struct */
		sharedp->rsmsi_mode = reply.rsmipc_mode;
		sharedp->rsmsi_uid = reply.rsmipc_uid;
		sharedp->rsmsi_gid = reply.rsmipc_gid;
		sharedp->rsmsi_seglen = reply.rsmipc_seglen;
		sharedp->rsmsi_cookie = sharedp;
	}

	rsmsharelock_release(seg);

	/*
	 * Get the segment lock and check for a force disconnect
	 * from the export side which would have changed the state
	 * back to RSM_STATE_NEW. Once the segment lock is acquired a
	 * force disconnect will be held off until the connection
	 * has completed.
	 */
	rsmseglock_acquire(seg);
	rsmsharelock_acquire(seg);
	ASSERT(seg->s_state == RSM_STATE_CONNECTING ||
	    seg->s_state == RSM_STATE_ABORT_CONNECT);

	shared_cookie = sharedp->rsmsi_cookie;

	if ((seg->s_state == RSM_STATE_ABORT_CONNECT) ||
	    (sharedp->rsmsi_state == RSMSI_STATE_ABORT_CONNECT)) {
		seg->s_state = RSM_STATE_NEW;
		seg->s_adapter = NULL;
		rsmsharelock_release(seg);
		rsmseglock_release(seg);
		rsmimport_rm(seg);
		rsmka_release_adapter(adapter);

		rsmsharelock_acquire(seg);
		if (!(sharedp->rsmsi_flags & RSMSI_FLAGS_ABORTDONE)) {
			/*
			 * set a flag indicating abort handling has been
			 * done
			 */
			sharedp->rsmsi_flags |= RSMSI_FLAGS_ABORTDONE;
			rsmsharelock_release(seg);
			/* send a message to exporter - only once */
			(void) rsm_send_notimporting(msg->nodeid,
			    msg->key, shared_cookie);
			rsmsharelock_acquire(seg);
			/*
			 * wake up any waiting importers and inform that
			 * connection has been aborted
			 */
			cv_broadcast(&sharedp->rsmsi_cv);
		}
		rsmsharelock_release(seg);

		DBG_PRINTF((category, RSM_ERR,
		    "rsm_connect done: RSM_STATE_ABORT_CONNECT\n"));
		return (RSMERR_INTERRUPTED);
	}


	/*
	 * We need to verify that this process has access
	 */
	e = rsm_access(sharedp->rsmsi_uid, sharedp->rsmsi_gid,
	    access & sharedp->rsmsi_mode,
	    (int)(msg->perm & RSM_PERM_RDWR), cred);
	if (e) {
		rsmsharelock_release(seg);
		seg->s_state = RSM_STATE_NEW;
		seg->s_adapter = NULL;
		rsmseglock_release(seg);
		rsmimport_rm(seg);
		rsmka_release_adapter(adapter);
		/*
		 * No need to lock segment it has been removed
		 * from the hash table
		 */
		rsmsharelock_acquire(seg);
		if (sharedp->rsmsi_state == RSMSI_STATE_CONNECTING) {
			rsmsharelock_release(seg);
			/* this is the first importer */

			(void) rsm_send_notimporting(msg->nodeid, msg->key,
			    shared_cookie);
			rsmsharelock_acquire(seg);
			sharedp->rsmsi_state = RSMSI_STATE_NEW;
			cv_broadcast(&sharedp->rsmsi_cv);
		}
		rsmsharelock_release(seg);

		DBG_PRINTF((category, RSM_ERR,
		    "rsm_connect done: ipcaccess failed\n"));
		return (RSMERR_PERM_DENIED);
	}

	/* update state and cookie */
	seg->s_segid = sharedp->rsmsi_segid;
	seg->s_len = sharedp->rsmsi_seglen;
	seg->s_mode = access & sharedp->rsmsi_mode;
	seg->s_pid = ddi_get_pid();
	seg->s_mapinfo = NULL;

	if (seg->s_node != my_nodeid) {
		if (sharedp->rsmsi_state == RSMSI_STATE_CONNECTING) {
			e = adapter->rsmpi_ops->rsm_connect(
			    adapter->rsmpi_handle,
			    addr, seg->s_segid, &sharedp->rsmsi_handle);

			if (e != RSM_SUCCESS) {
				seg->s_state = RSM_STATE_NEW;
				seg->s_adapter = NULL;
				rsmsharelock_release(seg);
				rsmseglock_release(seg);
				rsmimport_rm(seg);
				rsmka_release_adapter(adapter);
				/*
				 *  inform the exporter to delete this importer
				 */
				(void) rsm_send_notimporting(msg->nodeid,
				    msg->key, shared_cookie);

				/*
				 * Now inform any waiting importers to
				 * retry connect. This needs to be done
				 * after sending notimporting so that
				 * the notimporting is sent before a waiting
				 * importer sends a segconnect while retrying
				 *
				 * No need to lock segment it has been removed
				 * from the hash table
				 */

				rsmsharelock_acquire(seg);
				sharedp->rsmsi_state = RSMSI_STATE_NEW;
				cv_broadcast(&sharedp->rsmsi_cv);
				rsmsharelock_release(seg);

				DBG_PRINTF((category, RSM_ERR,
				    "rsm_connect error %d\n", e));
				if (e == RSMERR_SEG_NOT_PUBLISHED_TO_RSM_ADDR)
					return (
					    RSMERR_SEG_NOT_PUBLISHED_TO_NODE);
				else if ((e == RSMERR_RSM_ADDR_UNREACHABLE) ||
				    (e == RSMERR_UNKNOWN_RSM_ADDR))
					return (RSMERR_REMOTE_NODE_UNREACHABLE);
				else
					return (e);
			}

		}
		seg->s_handle.in = sharedp->rsmsi_handle;

	}

	seg->s_state = RSM_STATE_CONNECT;


	seg->s_flags &= ~RSM_IMPORT_DUMMY;	/* clear dummy flag */
	if (bar_va) {
		/* increment generation number on barrier page */
		atomic_inc_16(bar_va + seg->s_hdr.rsmrc_num);
		/* return user off into barrier page where status will be */
		msg->off = (int)seg->s_hdr.rsmrc_num;
		msg->gnum = bar_va[msg->off]; 	/* gnum race */
	} else {
		msg->off = 0;
		msg->gnum = 0;	/* gnum race */
	}

	msg->len = (int)sharedp->rsmsi_seglen;
	msg->rnum = seg->s_minor;
	rsmsharecv_signal(seg, RSMSI_STATE_CONNECTING, RSMSI_STATE_CONNECTED);
	rsmsharelock_release(seg);
	rsmseglock_release(seg);

	/* Return back to user the segment size & perm in case it's needed */

#ifdef _MULTI_DATAMODEL
	if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
		rsm_ioctlmsg32_t msg32;

		if (msg->len > UINT_MAX)
			msg32.len = RSM_MAXSZ_PAGE_ALIGNED;
		else
			msg32.len = msg->len;
		msg32.off = msg->off;
		msg32.perm = msg->perm;
		msg32.gnum = msg->gnum;
		msg32.rnum = msg->rnum;

		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_connect done\n"));

		if (ddi_copyout((caddr_t)&msg32, (caddr_t)dataptr,
		    sizeof (msg32), mode))
			return (RSMERR_BAD_ADDR);
		else
			return (RSM_SUCCESS);
	}
#endif
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_connect done\n"));

	if (ddi_copyout((caddr_t)msg, (caddr_t)dataptr, sizeof (*msg),
	    mode))
		return (RSMERR_BAD_ADDR);
	else
		return (RSM_SUCCESS);
}

static int
rsm_unmap(rsmseg_t *seg)
{
	int			err;
	adapter_t		*adapter;
	rsm_import_share_t	*sharedp;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IMPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_unmap enter %u\n", seg->s_segid));

	ASSERT(seg->s_hdr.rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT);

	/* assert seg is locked */
	ASSERT(rsmseglock_held(seg));
	ASSERT(seg->s_state != RSM_STATE_MAPPING);

	if ((seg->s_state != RSM_STATE_ACTIVE) &&
	    (seg->s_state != RSM_STATE_MAP_QUIESCE)) {
		/* segment unmap has already been done */
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_unmap done\n"));
		return (RSM_SUCCESS);
	}

	sharedp = seg->s_share;

	rsmsharelock_acquire(seg);

	/*
	 *	- shared data struct is in MAPPED or MAP_QUIESCE state
	 */

	ASSERT(sharedp->rsmsi_state == RSMSI_STATE_MAPPED ||
	    sharedp->rsmsi_state == RSMSI_STATE_MAP_QUIESCE);

	/*
	 * Unmap pages - previously rsm_memseg_import_unmap was called only if
	 * the segment cookie list was NULL; but it is always NULL when
	 * called from rsmmap_unmap and won't be NULL when called for
	 * a force disconnect - so the check for NULL cookie list was removed
	 */

	ASSERT(sharedp->rsmsi_mapcnt > 0);

	sharedp->rsmsi_mapcnt--;

	if (sharedp->rsmsi_mapcnt == 0) {
		if (sharedp->rsmsi_state == RSMSI_STATE_MAPPED) {
			/* unmap the shared RSMPI mapping */
			adapter = seg->s_adapter;
			if (seg->s_node != my_nodeid) {
				ASSERT(sharedp->rsmsi_handle != NULL);
				err = adapter->rsmpi_ops->
				    rsm_unmap(sharedp->rsmsi_handle);
				DBG_PRINTF((category, RSM_DEBUG,
				    "rsm_unmap: rsmpi unmap %d\n", err));
				rsm_free_mapinfo(sharedp->rsmsi_mapinfo);
				sharedp->rsmsi_mapinfo = NULL;
			}
			sharedp->rsmsi_state = RSMSI_STATE_CONNECTED;
		} else { /* MAP_QUIESCE --munmap()--> CONN_QUIESCE */
			sharedp->rsmsi_state = RSMSI_STATE_CONN_QUIESCE;
		}
	}

	rsmsharelock_release(seg);

	/*
	 * The s_cookie field is used to store the cookie returned from the
	 * ddi_umem_lock when binding the pages for an export segment. This
	 * is the primary use of the s_cookie field and does not normally
	 * pertain to any importing segment except in the loopback case.
	 * For the loopback case, the import segment and export segment are
	 * on the same node, the s_cookie field of the segment structure for
	 * the importer is initialized to the s_cookie field in the exported
	 * segment during the map operation and is used during the call to
	 * devmap_umem_setup for the import mapping.
	 * Thus, during unmap, we simply need to set s_cookie to NULL to
	 * indicate that the mapping no longer exists.
	 */
	seg->s_cookie = NULL;

	seg->s_mapinfo = NULL;

	if (seg->s_state == RSM_STATE_ACTIVE)
		seg->s_state = RSM_STATE_CONNECT;
	else
		seg->s_state = RSM_STATE_CONN_QUIESCE;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_unmap done\n"));

	return (RSM_SUCCESS);
}

/*
 * cookie returned here if not null indicates that it is
 * the last importer and it can be used in the RSMIPC_NOT_IMPORTING
 * message.
 */
static int
rsm_closeconnection(rsmseg_t *seg, void **cookie)
{
	int			e;
	adapter_t		*adapter;
	rsm_import_share_t	*sharedp;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IMPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_closeconnection enter\n"));

	*cookie = (void *)NULL;

	ASSERT(seg->s_hdr.rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT);

	/* assert seg is locked */
	ASSERT(rsmseglock_held(seg));

	if (seg->s_state == RSM_STATE_DISCONNECT) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_closeconnection done: already disconnected\n"));
		return (RSM_SUCCESS);
	}

	/* wait for all putv/getv ops to get done */
	while (seg->s_rdmacnt > 0) {
		cv_wait(&seg->s_cv, &seg->s_lock);
	}

	(void) rsm_unmap(seg);

	ASSERT(seg->s_state == RSM_STATE_CONNECT ||
	    seg->s_state == RSM_STATE_CONN_QUIESCE);

	adapter = seg->s_adapter;
	sharedp = seg->s_share;

	ASSERT(sharedp != NULL);

	rsmsharelock_acquire(seg);

	/*
	 * Disconnect on adapter
	 *
	 * The current algorithm is stateless, I don't have to contact
	 * server when I go away. He only gives me permissions. Of course,
	 * the adapters will talk to terminate the connect.
	 *
	 * disconnect is needed only if we are CONNECTED not in CONN_QUIESCE
	 */
	if ((sharedp->rsmsi_state == RSMSI_STATE_CONNECTED) &&
	    (sharedp->rsmsi_node != my_nodeid)) {

		if (sharedp->rsmsi_refcnt == 1) {
			/* this is the last importer */
			ASSERT(sharedp->rsmsi_mapcnt == 0);

			e = adapter->rsmpi_ops->
			    rsm_disconnect(sharedp->rsmsi_handle);
			if (e != RSM_SUCCESS) {
				DBG_PRINTF((category, RSM_DEBUG,
				    "rsm:disconnect failed seg=%x:err=%d\n",
				    seg->s_key, e));
			}
		}
	}

	seg->s_handle.in = NULL;

	sharedp->rsmsi_refcnt--;

	if (sharedp->rsmsi_refcnt == 0) {
		*cookie = (void *)sharedp->rsmsi_cookie;
		sharedp->rsmsi_state = RSMSI_STATE_DISCONNECTED;
		sharedp->rsmsi_handle = NULL;
		rsmsharelock_release(seg);

		/* clean up the shared data structure */
		mutex_destroy(&sharedp->rsmsi_lock);
		cv_destroy(&sharedp->rsmsi_cv);
		kmem_free((void *)(sharedp), sizeof (rsm_import_share_t));

	} else {
		rsmsharelock_release(seg);
	}

	/* increment generation number on barrier page */
	if (bar_va) {
		atomic_inc_16(bar_va + seg->s_hdr.rsmrc_num);
	}

	/*
	 * The following needs to be done after any
	 * rsmsharelock calls which use seg->s_share.
	 */
	seg->s_share = NULL;

	seg->s_state = RSM_STATE_DISCONNECT;
	/* signal anyone waiting in the CONN_QUIESCE state */
	cv_broadcast(&seg->s_cv);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_closeconnection done\n"));

	return (RSM_SUCCESS);
}

int
rsm_disconnect(rsmseg_t *seg)
{
	rsmipc_request_t	request;
	void			*shared_cookie;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IMPORT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_disconnect enter\n"));

	ASSERT(seg->s_hdr.rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT);

	/* assert seg isn't locked */
	ASSERT(!rsmseglock_held(seg));


	/* Remove segment from imported list */
	rsmimport_rm(seg);

	/* acquire the segment */
	rsmseglock_acquire(seg);

	/* wait until segment leaves the mapping state */
	while (seg->s_state == RSM_STATE_MAPPING)
		cv_wait(&seg->s_cv, &seg->s_lock);

	if (seg->s_state == RSM_STATE_DISCONNECT) {
		seg->s_state = RSM_STATE_NEW;
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_disconnect done: already disconnected\n"));
		return (RSM_SUCCESS);
	}

	(void) rsm_closeconnection(seg, &shared_cookie);

	/* update state */
	seg->s_state = RSM_STATE_NEW;

	if (shared_cookie != NULL) {
		/*
		 *  This is the last importer so inform the exporting node
		 *  so this import can be deleted from the list of importers.
		 */
		request.rsmipc_hdr.rsmipc_type = RSMIPC_MSG_NOTIMPORTING;
		request.rsmipc_key = seg->s_segid;
		request.rsmipc_segment_cookie = shared_cookie;
		rsmseglock_release(seg);
		(void) rsmipc_send(seg->s_node, &request, RSM_NO_REPLY);
	} else {
		rsmseglock_release(seg);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_disconnect done\n"));

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
rsm_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	minor_t		rnum;
	rsmresource_t	*res;
	rsmseg_t 	*seg;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_chpoll enter\n"));

	/* find minor, no lock */
	rnum = getminor(dev);
	res = rsmresource_lookup(rnum, RSM_NOLOCK);

	/* poll is supported only for export/import segments */
	if ((res == NULL) || (res == RSMRC_RESERVED) ||
	    (res->rsmrc_type == RSM_RESOURCE_BAR)) {
		return (ENXIO);
	}

	*reventsp = 0;

	/*
	 * An exported segment must be in state RSM_STATE_EXPORT; an
	 * imported segment must be in state RSM_STATE_ACTIVE.
	 */
	seg = (rsmseg_t *)res;

	if (seg->s_pollevent) {
		*reventsp = POLLRDNORM;
	} else if (!anyyet) {
		/* cannot take segment lock here */
		*phpp = &seg->s_poll;
		seg->s_pollflag |= RSM_SEGMENT_POLL;
	}
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_chpoll done\n"));
	return (0);
}



/* ************************* IOCTL Commands ********************* */

static rsmseg_t *
rsmresource_seg(rsmresource_t *res, minor_t rnum, cred_t *credp,
    rsm_resource_type_t type)
{
	/* get segment from resource handle */
	rsmseg_t *seg;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmresource_seg enter\n"));


	if (res != RSMRC_RESERVED) {
		seg = (rsmseg_t *)res;
	} else {
		/* Allocate segment now and bind it */
		seg = rsmseg_alloc(rnum, credp);

		/*
		 * if DR pre-processing is going on or DR is in progress
		 * then the new export segments should be in the NEW_QSCD state
		 */
		if (type == RSM_RESOURCE_EXPORT_SEGMENT) {
			mutex_enter(&rsm_drv_data.drv_lock);
			if ((rsm_drv_data.drv_state ==
			    RSM_DRV_PREDEL_STARTED) ||
			    (rsm_drv_data.drv_state ==
			    RSM_DRV_PREDEL_COMPLETED) ||
			    (rsm_drv_data.drv_state ==
			    RSM_DRV_DR_IN_PROGRESS)) {
				seg->s_state = RSM_STATE_NEW_QUIESCED;
			}
			mutex_exit(&rsm_drv_data.drv_lock);
		}

		rsmresource_insert(rnum, (rsmresource_t *)seg, type);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmresource_seg done\n"));

	return (seg);
}

static int
rsmexport_ioctl(rsmseg_t *seg, rsm_ioctlmsg_t *msg, int cmd, intptr_t arg,
    int mode, cred_t *credp)
{
	int error;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmexport_ioctl enter\n"));

	arg = arg;
	credp = credp;

	ASSERT(seg != NULL);

	switch (cmd) {
	case RSM_IOCTL_BIND:
		error = rsm_bind(seg, msg, arg, mode);
		break;
	case RSM_IOCTL_REBIND:
		error = rsm_rebind(seg, msg);
		break;
	case RSM_IOCTL_UNBIND:
		error = ENOTSUP;
		break;
	case RSM_IOCTL_PUBLISH:
		error = rsm_publish(seg, msg, arg, mode);
		break;
	case RSM_IOCTL_REPUBLISH:
		error = rsm_republish(seg, msg, mode);
		break;
	case RSM_IOCTL_UNPUBLISH:
		error = rsm_unpublish(seg, 1);
		break;
	default:
		error = EINVAL;
		break;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmexport_ioctl done: %d\n",
	    error));

	return (error);
}
static int
rsmimport_ioctl(rsmseg_t *seg, rsm_ioctlmsg_t *msg, int cmd, intptr_t arg,
    int mode, cred_t *credp)
{
	int error;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IMPORT | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmimport_ioctl enter\n"));

	ASSERT(seg);

	switch (cmd) {
	case RSM_IOCTL_CONNECT:
		error = rsm_connect(seg, msg, credp, arg, mode);
		break;
	default:
		error = EINVAL;
		break;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmimport_ioctl done: %d\n",
	    error));
	return (error);
}

static int
rsmbar_ioctl(rsmseg_t *seg, rsm_ioctlmsg_t *msg, int cmd, intptr_t arg,
    int mode)
{
	int e;
	adapter_t *adapter;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IMPORT | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmbar_ioctl enter\n"));


	if ((seg->s_flags & RSM_IMPORT_DUMMY) != 0) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmbar_ioctl done: RSM_IMPORT_DUMMY\n"));
		return (RSMERR_CONN_ABORTED);
	} else if (seg->s_node == my_nodeid) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmbar_ioctl done: loopback\n"));
		return (RSM_SUCCESS);
	}

	adapter = seg->s_adapter;

	switch (cmd) {
	case RSM_IOCTL_BAR_CHECK:
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmbar_ioctl done: RSM_BAR_CHECK %d\n", bar_va));
		return (bar_va ? RSM_SUCCESS : EINVAL);
	case RSM_IOCTL_BAR_OPEN:
		e = adapter->rsmpi_ops->
		    rsm_open_barrier_ctrl(adapter->rsmpi_handle, &msg->bar);
		break;
	case RSM_IOCTL_BAR_ORDER:
		e = adapter->rsmpi_ops->rsm_order_barrier(&msg->bar);
		break;
	case RSM_IOCTL_BAR_CLOSE:
		e = adapter->rsmpi_ops->rsm_close_barrier(&msg->bar);
		break;
	default:
		e = EINVAL;
		break;
	}

	if (e == RSM_SUCCESS) {
#ifdef _MULTI_DATAMODEL
		if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
			rsm_ioctlmsg32_t msg32;
			int i;

			for (i = 0; i < 4; i++) {
				msg32.bar.comp[i].u64 = msg->bar.comp[i].u64;
			}

			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsmbar_ioctl done\n"));
			if (ddi_copyout((caddr_t)&msg32, (caddr_t)arg,
			    sizeof (msg32), mode))
				return (RSMERR_BAD_ADDR);
			else
				return (RSM_SUCCESS);
		}
#endif
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmbar_ioctl done\n"));
		if (ddi_copyout((caddr_t)&msg->bar, (caddr_t)arg,
		    sizeof (*msg), mode))
			return (RSMERR_BAD_ADDR);
		else
			return (RSM_SUCCESS);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmbar_ioctl done: error=%d\n", e));

	return (e);
}

/*
 * Ring the doorbell of the export segment to which this segment is
 * connected.
 */
static int
exportbell_ioctl(rsmseg_t *seg, int cmd /*ARGSUSED*/)
{
	int e = 0;
	rsmipc_request_t request;

	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IMPORT | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "exportbell_ioctl enter\n"));

	request.rsmipc_key = seg->s_segid;
	request.rsmipc_hdr.rsmipc_type = RSMIPC_MSG_BELL;
	request.rsmipc_segment_cookie = NULL;
	e = rsmipc_send(seg->s_node, &request, RSM_NO_REPLY);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "exportbell_ioctl done: %d\n", e));

	return (e);
}

/*
 * Ring the doorbells of all segments importing this segment
 */
static int
importbell_ioctl(rsmseg_t *seg, int cmd /*ARGSUSED*/)
{
	importing_token_t	*token = NULL;
	rsmipc_request_t	request;
	int			index;

	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_EXPORT | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "importbell_ioctl enter\n"));

	ASSERT(seg->s_state != RSM_STATE_NEW &&
	    seg->s_state != RSM_STATE_NEW_QUIESCED);

	request.rsmipc_key = seg->s_segid;
	request.rsmipc_hdr.rsmipc_type = RSMIPC_MSG_BELL;

	index = rsmhash(seg->s_segid);

	token = importer_list.bucket[index];

	while (token != NULL) {
		if (seg->s_key == token->key) {
			request.rsmipc_segment_cookie =
			    token->import_segment_cookie;
			(void) rsmipc_send(token->importing_node,
			    &request, RSM_NO_REPLY);
		}
		token = token->next;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "importbell_ioctl done\n"));
	return (RSM_SUCCESS);
}

static int
rsm_consumeevent_copyin(caddr_t arg, rsm_consume_event_msg_t *msgp,
    rsm_poll_event_t **eventspp, int mode)
{
	rsm_poll_event_t	*evlist = NULL;
	size_t			evlistsz;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IOCTL);

#ifdef _MULTI_DATAMODEL
	if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
		int i;
		rsm_consume_event_msg32_t cemsg32 = {0};
		rsm_poll_event32_t	event32[RSM_MAX_POLLFDS];
		rsm_poll_event32_t	*evlist32;
		size_t			evlistsz32;

		/* copyin the ioctl message */
		if (ddi_copyin(arg, (caddr_t)&cemsg32,
		    sizeof (rsm_consume_event_msg32_t), mode)) {
			DBG_PRINTF((category, RSM_ERR,
			    "consumeevent_copyin msgp: RSMERR_BAD_ADDR\n"));
			return (RSMERR_BAD_ADDR);
		}
		msgp->seglist = (caddr_t)(uintptr_t)cemsg32.seglist;
		msgp->numents = (int)cemsg32.numents;

		evlistsz32 = sizeof (rsm_poll_event32_t) * msgp->numents;
		/*
		 * If numents is large alloc events list on heap otherwise
		 * use the address of array that was passed in.
		 */
		if (msgp->numents > RSM_MAX_POLLFDS) {
			if (msgp->numents > max_segs) { /* validate numents */
				DBG_PRINTF((category, RSM_ERR,
				    "consumeevent_copyin: "
				    "RSMERR_BAD_ARGS_ERRORS\n"));
				return (RSMERR_BAD_ARGS_ERRORS);
			}
			evlist32 = kmem_zalloc(evlistsz32, KM_SLEEP);
		} else {
			evlist32 = event32;
		}

		/* copyin the seglist into the rsm_poll_event32_t array */
		if (ddi_copyin((caddr_t)msgp->seglist, (caddr_t)evlist32,
		    evlistsz32, mode)) {
			if ((msgp->numents > RSM_MAX_POLLFDS) && evlist32) {
				kmem_free(evlist32, evlistsz32);
			}
			DBG_PRINTF((category, RSM_ERR,
			    "consumeevent_copyin evlist: RSMERR_BAD_ADDR\n"));
			return (RSMERR_BAD_ADDR);
		}

		/* evlist and evlistsz are based on rsm_poll_event_t type */
		evlistsz = sizeof (rsm_poll_event_t)* msgp->numents;

		if (msgp->numents > RSM_MAX_POLLFDS) {
			evlist = kmem_zalloc(evlistsz, KM_SLEEP);
			*eventspp = evlist;
		} else {
			evlist = *eventspp;
		}
		/*
		 * copy the rsm_poll_event32_t array to the rsm_poll_event_t
		 * array
		 */
		for (i = 0; i < msgp->numents; i++) {
			evlist[i].rnum = evlist32[i].rnum;
			evlist[i].fdsidx = evlist32[i].fdsidx;
			evlist[i].revent = evlist32[i].revent;
		}
		/* free the temp 32-bit event list */
		if ((msgp->numents > RSM_MAX_POLLFDS) && evlist32) {
			kmem_free(evlist32, evlistsz32);
		}

		return (RSM_SUCCESS);
	}
#endif
	/* copyin the ioctl message */
	if (ddi_copyin(arg, (caddr_t)msgp, sizeof (rsm_consume_event_msg_t),
	    mode)) {
		DBG_PRINTF((category, RSM_ERR,
		    "consumeevent_copyin msgp: RSMERR_BAD_ADDR\n"));
		return (RSMERR_BAD_ADDR);
	}
	/*
	 * If numents is large alloc events list on heap otherwise
	 * use the address of array that was passed in.
	 */
	if (msgp->numents > RSM_MAX_POLLFDS) {
		if (msgp->numents > max_segs) { /* validate numents */
			DBG_PRINTF((category, RSM_ERR,
			    "consumeevent_copyin: RSMERR_BAD_ARGS_ERRORS\n"));
			return (RSMERR_BAD_ARGS_ERRORS);
		}
		evlistsz = sizeof (rsm_poll_event_t)*msgp->numents;
		evlist = kmem_zalloc(evlistsz, KM_SLEEP);
		*eventspp  = evlist;
	}

	/* copyin the seglist */
	if (ddi_copyin((caddr_t)msgp->seglist, (caddr_t)(*eventspp),
	    sizeof (rsm_poll_event_t)*msgp->numents, mode)) {
		if (evlist) {
			kmem_free(evlist, evlistsz);
			*eventspp = NULL;
		}
		DBG_PRINTF((category, RSM_ERR,
		    "consumeevent_copyin evlist: RSMERR_BAD_ADDR\n"));
		return (RSMERR_BAD_ADDR);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "consumeevent_copyin done\n"));
	return (RSM_SUCCESS);
}

static int
rsm_consumeevent_copyout(rsm_consume_event_msg_t *msgp,
    rsm_poll_event_t *eventsp, int mode)
{
	size_t			evlistsz;
	int			err = RSM_SUCCESS;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "consumeevent_copyout enter: numents(%d) eventsp(%p)\n",
	    msgp->numents, eventsp));

#ifdef _MULTI_DATAMODEL
	if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
		int i;
		rsm_poll_event32_t	event32[RSM_MAX_POLLFDS];
		rsm_poll_event32_t	*evlist32;
		size_t			evlistsz32;

		evlistsz32 = sizeof (rsm_poll_event32_t)*msgp->numents;
		if (msgp->numents > RSM_MAX_POLLFDS) {
			evlist32 = kmem_zalloc(evlistsz32, KM_SLEEP);
		} else {
			evlist32 = event32;
		}

		/*
		 * copy the rsm_poll_event_t array to the rsm_poll_event32_t
		 * array
		 */
		for (i = 0; i < msgp->numents; i++) {
			evlist32[i].rnum = eventsp[i].rnum;
			evlist32[i].fdsidx = eventsp[i].fdsidx;
			evlist32[i].revent = eventsp[i].revent;
		}

		if (ddi_copyout((caddr_t)evlist32, (caddr_t)msgp->seglist,
		    evlistsz32, mode)) {
			err = RSMERR_BAD_ADDR;
		}

		if (msgp->numents > RSM_MAX_POLLFDS) {
			if (evlist32) {	/* free the temp 32-bit event list */
				kmem_free(evlist32, evlistsz32);
			}
			/*
			 * eventsp and evlistsz are based on rsm_poll_event_t
			 * type
			 */
			evlistsz = sizeof (rsm_poll_event_t)*msgp->numents;
			/* event list on the heap and needs to be freed here */
			if (eventsp) {
				kmem_free(eventsp, evlistsz);
			}
		}

		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "consumeevent_copyout done: err=%d\n", err));
		return (err);
	}
#endif
	evlistsz = sizeof (rsm_poll_event_t)*msgp->numents;

	if (ddi_copyout((caddr_t)eventsp, (caddr_t)msgp->seglist, evlistsz,
	    mode)) {
		err = RSMERR_BAD_ADDR;
	}

	if ((msgp->numents > RSM_MAX_POLLFDS) && eventsp) {
		/* event list on the heap and needs to be freed here */
		kmem_free(eventsp, evlistsz);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "consumeevent_copyout done: err=%d\n", err));
	return (err);
}

static int
rsm_consumeevent_ioctl(caddr_t arg, int mode)
{
	int	rc;
	int	i;
	minor_t	rnum;
	rsm_consume_event_msg_t	msg = {0};
	rsmseg_t		*seg;
	rsm_poll_event_t	*event_list;
	rsm_poll_event_t	events[RSM_MAX_POLLFDS];
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IOCTL);

	event_list = events;

	if ((rc = rsm_consumeevent_copyin(arg, &msg, &event_list, mode)) !=
	    RSM_SUCCESS) {
		return (rc);
	}

	for (i = 0; i < msg.numents; i++) {
		rnum = event_list[i].rnum;
		event_list[i].revent = 0;
		/* get the segment structure */
		seg = (rsmseg_t *)rsmresource_lookup(rnum, RSM_LOCK);
		if (seg) {
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "consumeevent_ioctl: rnum(%d) seg(%p)\n", rnum,
			    seg));
			if (seg->s_pollevent) {
				/* consume the event */
				atomic_dec_32(&seg->s_pollevent);
				event_list[i].revent = POLLRDNORM;
			}
			rsmseglock_release(seg);
		}
	}

	if ((rc = rsm_consumeevent_copyout(&msg, event_list, mode)) !=
	    RSM_SUCCESS) {
		return (rc);
	}

	return (RSM_SUCCESS);
}

static int
iovec_copyin(caddr_t user_vec, rsmka_iovec_t *iovec, int count, int mode)
{
	int size;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IMPORT | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "iovec_copyin enter\n"));

#ifdef _MULTI_DATAMODEL
	if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
		rsmka_iovec32_t	*iovec32, *iovec32_base;
		int i;

		size = count * sizeof (rsmka_iovec32_t);
		iovec32_base = iovec32 = kmem_zalloc(size, KM_SLEEP);
		if (ddi_copyin((caddr_t)user_vec,
		    (caddr_t)iovec32, size, mode)) {
			kmem_free(iovec32, size);
			DBG_PRINTF((category, RSM_DEBUG,
			    "iovec_copyin: returning RSMERR_BAD_ADDR\n"));
			return (RSMERR_BAD_ADDR);
		}

		for (i = 0; i < count; i++, iovec++, iovec32++) {
			iovec->io_type = (int)iovec32->io_type;
			if (iovec->io_type == RSM_HANDLE_TYPE)
				iovec->local.segid = (rsm_memseg_id_t)
				    iovec32->local;
			else
				iovec->local.vaddr =
				    (caddr_t)(uintptr_t)iovec32->local;
			iovec->local_offset = (size_t)iovec32->local_offset;
			iovec->remote_offset = (size_t)iovec32->remote_offset;
			iovec->transfer_len = (size_t)iovec32->transfer_len;

		}
		kmem_free(iovec32_base, size);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "iovec_copyin done\n"));
		return (DDI_SUCCESS);
	}
#endif

	size = count * sizeof (rsmka_iovec_t);
	if (ddi_copyin((caddr_t)user_vec, (caddr_t)iovec, size, mode)) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "iovec_copyin done: RSMERR_BAD_ADDR\n"));
		return (RSMERR_BAD_ADDR);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "iovec_copyin done\n"));

	return (DDI_SUCCESS);
}


static int
sgio_copyin(caddr_t arg, rsmka_scat_gath_t *sg_io, int mode)
{
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IMPORT | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "sgio_copyin enter\n"));

#ifdef _MULTI_DATAMODEL
	if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
		rsmka_scat_gath32_t sg_io32;

		if (ddi_copyin(arg, (caddr_t)&sg_io32, sizeof (sg_io32),
		    mode)) {
			DBG_PRINTF((category, RSM_DEBUG,
			    "sgio_copyin done: returning EFAULT\n"));
			return (RSMERR_BAD_ADDR);
		}
		sg_io->local_nodeid = (rsm_node_id_t)sg_io32.local_nodeid;
		sg_io->io_request_count =  (size_t)sg_io32.io_request_count;
		sg_io->io_residual_count = (size_t)sg_io32.io_residual_count;
		sg_io->flags = (size_t)sg_io32.flags;
		sg_io->remote_handle = (rsm_memseg_import_handle_t)
		    (uintptr_t)sg_io32.remote_handle;
		sg_io->iovec = (rsmka_iovec_t *)(uintptr_t)sg_io32.iovec;
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "sgio_copyin done\n"));
		return (DDI_SUCCESS);
	}
#endif
	if (ddi_copyin(arg, (caddr_t)sg_io, sizeof (rsmka_scat_gath_t),
	    mode)) {
		DBG_PRINTF((category, RSM_DEBUG,
		    "sgio_copyin done: returning EFAULT\n"));
		return (RSMERR_BAD_ADDR);
	}
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "sgio_copyin done\n"));
	return (DDI_SUCCESS);
}

static int
sgio_resid_copyout(caddr_t arg, rsmka_scat_gath_t *sg_io, int mode)
{
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IMPORT | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "sgio_resid_copyout enter\n"));

#ifdef _MULTI_DATAMODEL
	if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
		rsmka_scat_gath32_t sg_io32;

		sg_io32.io_residual_count = sg_io->io_residual_count;
		sg_io32.flags = sg_io->flags;

		if (ddi_copyout((caddr_t)&sg_io32.io_residual_count,
		    (caddr_t)&((rsmka_scat_gath32_t *)arg)->io_residual_count,
		    sizeof (uint32_t), mode)) {

			DBG_PRINTF((category, RSM_ERR,
			    "sgio_resid_copyout error: rescnt\n"));
			return (RSMERR_BAD_ADDR);
		}

		if (ddi_copyout((caddr_t)&sg_io32.flags,
		    (caddr_t)&((rsmka_scat_gath32_t *)arg)->flags,
		    sizeof (uint32_t), mode)) {

			DBG_PRINTF((category, RSM_ERR,
			    "sgio_resid_copyout error: flags\n"));
			return (RSMERR_BAD_ADDR);
		}
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "sgio_resid_copyout done\n"));
		return (DDI_SUCCESS);
	}
#endif
	if (ddi_copyout((caddr_t)&sg_io->io_residual_count,
	    (caddr_t)&((rsmka_scat_gath_t *)arg)->io_residual_count,
	    sizeof (ulong_t), mode)) {

		DBG_PRINTF((category, RSM_ERR,
		    "sgio_resid_copyout error:rescnt\n"));
		return (RSMERR_BAD_ADDR);
	}

	if (ddi_copyout((caddr_t)&sg_io->flags,
	    (caddr_t)&((rsmka_scat_gath_t *)arg)->flags,
	    sizeof (uint_t), mode)) {

		DBG_PRINTF((category, RSM_ERR,
		    "sgio_resid_copyout error:flags\n"));
		return (RSMERR_BAD_ADDR);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "sgio_resid_copyout done\n"));
	return (DDI_SUCCESS);
}


static int
rsm_iovec_ioctl(dev_t dev, caddr_t arg, int cmd, int mode, cred_t *credp)
{
	rsmka_scat_gath_t	sg_io;
	rsmka_iovec_t		ka_iovec_arr[RSM_MAX_IOVLEN];
	rsmka_iovec_t		*ka_iovec;
	rsmka_iovec_t		*ka_iovec_start;
	rsmpi_scat_gath_t	rsmpi_sg_io;
	rsmpi_iovec_t		iovec_arr[RSM_MAX_IOVLEN];
	rsmpi_iovec_t		*iovec;
	rsmpi_iovec_t		*iovec_start = NULL;
	rsmapi_access_entry_t	*acl;
	rsmresource_t		*res;
	minor_t			rnum;
	rsmseg_t		*im_seg, *ex_seg;
	int			e;
	int			error = 0;
	uint_t			i;
	uint_t			iov_proc = 0; /* num of iovecs processed */
	size_t			size = 0;
	size_t			ka_size;

	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_IMPORT | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_iovec_ioctl enter\n"));

	credp = credp;

	/*
	 * Copyin the scatter/gather structure  and build new structure
	 * for rsmpi.
	 */
	e = sgio_copyin(arg, &sg_io, mode);
	if (e != DDI_SUCCESS) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_iovec_ioctl done: sgio_copyin %d\n", e));
		return (e);
	}

	if (sg_io.io_request_count > RSM_MAX_SGIOREQS) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_iovec_ioctl done: request_count(%d) too large\n",
		    sg_io.io_request_count));
		return (RSMERR_BAD_SGIO);
	}

	rsmpi_sg_io.io_request_count = sg_io.io_request_count;
	rsmpi_sg_io.io_residual_count = sg_io.io_request_count;
	rsmpi_sg_io.io_segflg = 0;

	/* Allocate memory and copyin io vector array  */
	if (sg_io.io_request_count > RSM_MAX_IOVLEN) {
		ka_size =  sg_io.io_request_count * sizeof (rsmka_iovec_t);
		ka_iovec_start = ka_iovec = kmem_zalloc(ka_size, KM_SLEEP);
	} else {
		ka_iovec_start = ka_iovec = ka_iovec_arr;
	}
	e = iovec_copyin((caddr_t)sg_io.iovec, ka_iovec,
	    sg_io.io_request_count, mode);
	if (e != DDI_SUCCESS) {
		if (sg_io.io_request_count > RSM_MAX_IOVLEN)
			kmem_free(ka_iovec, ka_size);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_iovec_ioctl done: iovec_copyin %d\n", e));
		return (e);
	}

	/* get the import segment descriptor */
	rnum = getminor(dev);
	res = rsmresource_lookup(rnum, RSM_LOCK);

	/*
	 * The following sequence of locking may (or MAY NOT) cause a
	 * deadlock but this is currently not addressed here since the
	 * implementation will be changed to incorporate the use of
	 * reference counting for both the import and the export segments.
	 */

	/* rsmseglock_acquire(im_seg) done in rsmresource_lookup */

	im_seg = (rsmseg_t *)res;

	if (im_seg == NULL) {
		if (sg_io.io_request_count > RSM_MAX_IOVLEN)
			kmem_free(ka_iovec, ka_size);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_iovec_ioctl done: rsmresource_lookup failed\n"));
		return (EINVAL);
	}
	/* putv/getv supported is supported only on import segments */
	if (im_seg->s_type != RSM_RESOURCE_IMPORT_SEGMENT) {
		rsmseglock_release(im_seg);
		if (sg_io.io_request_count > RSM_MAX_IOVLEN)
			kmem_free(ka_iovec, ka_size);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_iovec_ioctl done: not an import segment\n"));
		return (EINVAL);
	}

	/*
	 * wait for a remote DR to complete ie. for segments to get UNQUIESCED
	 * as well as wait for a local DR to complete.
	 */
	while ((im_seg->s_state == RSM_STATE_CONN_QUIESCE) ||
	    (im_seg->s_state == RSM_STATE_MAP_QUIESCE) ||
	    (im_seg->s_flags & RSM_DR_INPROGRESS)) {
		if (cv_wait_sig(&im_seg->s_cv, &im_seg->s_lock) == 0) {
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsm_iovec_ioctl done: cv_wait INTR"));
			rsmseglock_release(im_seg);
			return (RSMERR_INTERRUPTED);
		}
	}

	if ((im_seg->s_state != RSM_STATE_CONNECT) &&
	    (im_seg->s_state != RSM_STATE_ACTIVE)) {

		ASSERT(im_seg->s_state == RSM_STATE_DISCONNECT ||
		    im_seg->s_state == RSM_STATE_NEW);

		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_iovec_ioctl done: im_seg not conn/map"));
		rsmseglock_release(im_seg);
		e = RSMERR_BAD_SGIO;
		goto out;
	}

	im_seg->s_rdmacnt++;
	rsmseglock_release(im_seg);

	/*
	 * Allocate and set up the io vector for rsmpi
	 */
	if (sg_io.io_request_count > RSM_MAX_IOVLEN) {
		size = sg_io.io_request_count * sizeof (rsmpi_iovec_t);
		iovec_start = iovec = kmem_zalloc(size, KM_SLEEP);
	} else {
		iovec_start = iovec = iovec_arr;
	}

	rsmpi_sg_io.iovec = iovec;
	for (iov_proc = 0; iov_proc < sg_io.io_request_count; iov_proc++) {
		if (ka_iovec->io_type == RSM_HANDLE_TYPE) {
			ex_seg = rsmexport_lookup(ka_iovec->local.segid);

			if (ex_seg == NULL) {
				e = RSMERR_BAD_SGIO;
				break;
			}
			ASSERT(ex_seg->s_state == RSM_STATE_EXPORT);

			acl = ex_seg->s_acl;
			if (acl[0].ae_permission == 0) {
				struct buf *xbuf;
				dev_t sdev = 0;

				xbuf = ddi_umem_iosetup(ex_seg->s_cookie,
				    0, ex_seg->s_len, B_WRITE,
				    sdev, 0, NULL, DDI_UMEM_SLEEP);

				ASSERT(xbuf != NULL);

				iovec->local_mem.ms_type = RSM_MEM_BUF;
				iovec->local_mem.ms_memory.bp = xbuf;
			} else {
				iovec->local_mem.ms_type = RSM_MEM_HANDLE;
				iovec->local_mem.ms_memory.handle =
				    ex_seg->s_handle.out;
			}
			ex_seg->s_rdmacnt++; /* refcnt the handle */
			rsmseglock_release(ex_seg);
		} else {
			iovec->local_mem.ms_type = RSM_MEM_VADDR;
			iovec->local_mem.ms_memory.vr.vaddr =
			    ka_iovec->local.vaddr;
		}

		iovec->local_offset = ka_iovec->local_offset;
		iovec->remote_handle = im_seg->s_handle.in;
		iovec->remote_offset = ka_iovec->remote_offset;
		iovec->transfer_length = ka_iovec->transfer_len;
		iovec++;
		ka_iovec++;
	}

	if (iov_proc <  sg_io.io_request_count) {
		/* error while processing handle */
		rsmseglock_acquire(im_seg);
		im_seg->s_rdmacnt--;   /* decrement the refcnt for importseg */
		if (im_seg->s_rdmacnt == 0) {
			cv_broadcast(&im_seg->s_cv);
		}
		rsmseglock_release(im_seg);
		goto out;
	}

	/* call rsmpi */
	if (cmd == RSM_IOCTL_PUTV)
		e = im_seg->s_adapter->rsmpi_ops->rsm_memseg_import_putv(
		    im_seg->s_adapter->rsmpi_handle,
		    &rsmpi_sg_io);
	else if (cmd == RSM_IOCTL_GETV)
		e = im_seg->s_adapter->rsmpi_ops->rsm_memseg_import_getv(
		    im_seg->s_adapter->rsmpi_handle,
		    &rsmpi_sg_io);
	else {
		e = EINVAL;
		DBG_PRINTF((category, RSM_DEBUG,
		    "iovec_ioctl: bad command = %x\n", cmd));
	}


	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_iovec_ioctl RSMPI oper done %d\n", e));

	sg_io.io_residual_count = rsmpi_sg_io.io_residual_count;

	/*
	 * Check for implicit signal post flag and do the signal
	 * post if needed
	 */
	if (sg_io.flags & RSM_IMPLICIT_SIGPOST &&
	    e == RSM_SUCCESS) {
		rsmipc_request_t request;

		request.rsmipc_key = im_seg->s_segid;
		request.rsmipc_hdr.rsmipc_type = RSMIPC_MSG_BELL;
		request.rsmipc_segment_cookie = NULL;
		e = rsmipc_send(im_seg->s_node, &request, RSM_NO_REPLY);
		/*
		 * Reset the implicit signal post flag to 0 to indicate
		 * that the signal post has been done and need not be
		 * done in the RSMAPI library
		 */
		sg_io.flags &= ~RSM_IMPLICIT_SIGPOST;
	}

	rsmseglock_acquire(im_seg);
	im_seg->s_rdmacnt--;
	if (im_seg->s_rdmacnt == 0) {
		cv_broadcast(&im_seg->s_cv);
	}
	rsmseglock_release(im_seg);
	error = sgio_resid_copyout(arg, &sg_io, mode);
out:
	iovec = iovec_start;
	ka_iovec = ka_iovec_start;
	for (i = 0; i < iov_proc; i++) {
		if (ka_iovec->io_type == RSM_HANDLE_TYPE) {
			ex_seg = rsmexport_lookup(ka_iovec->local.segid);

			ASSERT(ex_seg != NULL);
			ASSERT(ex_seg->s_state == RSM_STATE_EXPORT);

			ex_seg->s_rdmacnt--; /* unrefcnt the handle */
			if (ex_seg->s_rdmacnt == 0) {
				cv_broadcast(&ex_seg->s_cv);
			}
			rsmseglock_release(ex_seg);
		}

		ASSERT(iovec != NULL); /* true if iov_proc > 0 */

		/*
		 * At present there is no dependency on the existence of xbufs
		 * created by ddi_umem_iosetup for each of the iovecs. So we
		 * can these xbufs here.
		 */
		if (iovec->local_mem.ms_type == RSM_MEM_BUF) {
			freerbuf(iovec->local_mem.ms_memory.bp);
		}

		iovec++;
		ka_iovec++;
	}

	if (sg_io.io_request_count > RSM_MAX_IOVLEN) {
		if (iovec_start)
			kmem_free(iovec_start, size);
		kmem_free(ka_iovec_start, ka_size);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_iovec_ioctl done %d\n", e));
	/* if RSMPI call fails return that else return copyout's retval */
	return ((e != RSM_SUCCESS) ? e : error);

}


static int
rsmaddr_ioctl(int cmd, rsm_ioctlmsg_t *msg, int mode)
{
	adapter_t	*adapter;
	rsm_addr_t	addr;
	rsm_node_id_t	node;
	int		rval = DDI_SUCCESS;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmaddr_ioctl enter\n"));

	adapter =  rsm_getadapter(msg, mode);
	if (adapter == NULL) {
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsmaddr_ioctl done: adapter not found\n"));
		return (RSMERR_CTLR_NOT_PRESENT);
	}

	switch (cmd) {
	case RSM_IOCTL_MAP_TO_ADDR: /* nodeid to hwaddr mapping */
		/* returns the hwaddr in msg->hwaddr */
		if (msg->nodeid == my_nodeid) {
			msg->hwaddr = adapter->hwaddr;
		} else {
			addr = get_remote_hwaddr(adapter, msg->nodeid);
			if ((int64_t)addr < 0) {
				rval = RSMERR_INTERNAL_ERROR;
			} else {
				msg->hwaddr = addr;
			}
		}
		break;
	case RSM_IOCTL_MAP_TO_NODEID: /* hwaddr to nodeid mapping */
		/* returns the nodeid in msg->nodeid */
		if (msg->hwaddr == adapter->hwaddr) {
			msg->nodeid = my_nodeid;
		} else {
			node = get_remote_nodeid(adapter, msg->hwaddr);
			if ((int)node < 0) {
				rval = RSMERR_INTERNAL_ERROR;
			} else {
				msg->nodeid = (rsm_node_id_t)node;
			}
		}
		break;
	default:
		rval = EINVAL;
		break;
	}

	rsmka_release_adapter(adapter);
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmaddr_ioctl done: %d\n", rval));
	return (rval);
}

static int
rsm_ddi_copyin(caddr_t arg, rsm_ioctlmsg_t *msg, int mode)
{
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_IOCTL | RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_ddi_copyin enter\n"));

#ifdef _MULTI_DATAMODEL

	if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
		rsm_ioctlmsg32_t msg32;
		int i;

		if (ddi_copyin(arg, (caddr_t)&msg32, sizeof (msg32), mode)) {
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsm_ddi_copyin done: EFAULT\n"));
			return (RSMERR_BAD_ADDR);
		}
		msg->len = msg32.len;
		msg->vaddr = (caddr_t)(uintptr_t)msg32.vaddr;
		msg->arg = (caddr_t)(uintptr_t)msg32.arg;
		msg->key = msg32.key;
		msg->acl_len = msg32.acl_len;
		msg->acl = (rsmapi_access_entry_t *)(uintptr_t)msg32.acl;
		msg->cnum = msg32.cnum;
		msg->cname = (caddr_t)(uintptr_t)msg32.cname;
		msg->cname_len = msg32.cname_len;
		msg->nodeid = msg32.nodeid;
		msg->hwaddr = msg32.hwaddr;
		msg->perm = msg32.perm;
		for (i = 0; i < 4; i++) {
			msg->bar.comp[i].u64 = msg32.bar.comp[i].u64;
		}
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_ddi_copyin done\n"));
		return (RSM_SUCCESS);
	}
#endif
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_ddi_copyin done\n"));
	if (ddi_copyin(arg, (caddr_t)msg, sizeof (*msg), mode))
		return (RSMERR_BAD_ADDR);
	else
		return (RSM_SUCCESS);
}

static int
rsmattr_ddi_copyout(adapter_t *adapter, caddr_t arg, int mode)
{
	rsmka_int_controller_attr_t	rsm_cattr;
	DBG_DEFINE(category,
	    RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_IOCTL | RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmattr_ddi_copyout enter\n"));
	/*
	 * need to copy appropriate data from rsm_controller_attr_t
	 * to rsmka_int_controller_attr_t
	 */
#ifdef	_MULTI_DATAMODEL
	if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
		rsmka_int_controller_attr32_t rsm_cattr32;

		rsm_cattr32.attr_direct_access_sizes =
		    adapter->rsm_attr.attr_direct_access_sizes;
		rsm_cattr32.attr_atomic_sizes =
		    adapter->rsm_attr.attr_atomic_sizes;
		rsm_cattr32.attr_page_size =
		    adapter->rsm_attr.attr_page_size;
		if (adapter->rsm_attr.attr_max_export_segment_size >
		    UINT_MAX)
			rsm_cattr32.attr_max_export_segment_size =
			    RSM_MAXSZ_PAGE_ALIGNED;
		else
			rsm_cattr32.attr_max_export_segment_size =
			    adapter->rsm_attr.attr_max_export_segment_size;
		if (adapter->rsm_attr.attr_tot_export_segment_size >
		    UINT_MAX)
			rsm_cattr32.attr_tot_export_segment_size =
			    RSM_MAXSZ_PAGE_ALIGNED;
		else
			rsm_cattr32.attr_tot_export_segment_size =
			    adapter->rsm_attr.attr_tot_export_segment_size;
		if (adapter->rsm_attr.attr_max_export_segments >
		    UINT_MAX)
			rsm_cattr32.attr_max_export_segments =
			    UINT_MAX;
		else
			rsm_cattr32.attr_max_export_segments =
			    adapter->rsm_attr.attr_max_export_segments;
		if (adapter->rsm_attr.attr_max_import_map_size >
		    UINT_MAX)
			rsm_cattr32.attr_max_import_map_size =
			    RSM_MAXSZ_PAGE_ALIGNED;
		else
			rsm_cattr32.attr_max_import_map_size =
			    adapter->rsm_attr.attr_max_import_map_size;
		if (adapter->rsm_attr.attr_tot_import_map_size >
		    UINT_MAX)
			rsm_cattr32.attr_tot_import_map_size =
			    RSM_MAXSZ_PAGE_ALIGNED;
		else
			rsm_cattr32.attr_tot_import_map_size =
			    adapter->rsm_attr.attr_tot_import_map_size;
		if (adapter->rsm_attr.attr_max_import_segments >
		    UINT_MAX)
			rsm_cattr32.attr_max_import_segments =
			    UINT_MAX;
		else
			rsm_cattr32.attr_max_import_segments =
			    adapter->rsm_attr.attr_max_import_segments;
		rsm_cattr32.attr_controller_addr =
		    adapter->rsm_attr.attr_controller_addr;

		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmattr_ddi_copyout done\n"));
		if (ddi_copyout((caddr_t)&rsm_cattr32, arg,
		    sizeof (rsmka_int_controller_attr32_t), mode)) {
			return (RSMERR_BAD_ADDR);
		}
		else
			return (RSM_SUCCESS);
	}
#endif
	rsm_cattr.attr_direct_access_sizes =
	    adapter->rsm_attr.attr_direct_access_sizes;
	rsm_cattr.attr_atomic_sizes =
	    adapter->rsm_attr.attr_atomic_sizes;
	rsm_cattr.attr_page_size =
	    adapter->rsm_attr.attr_page_size;
	rsm_cattr.attr_max_export_segment_size =
	    adapter->rsm_attr.attr_max_export_segment_size;
	rsm_cattr.attr_tot_export_segment_size =
	    adapter->rsm_attr.attr_tot_export_segment_size;
	rsm_cattr.attr_max_export_segments =
	    adapter->rsm_attr.attr_max_export_segments;
	rsm_cattr.attr_max_import_map_size =
	    adapter->rsm_attr.attr_max_import_map_size;
	rsm_cattr.attr_tot_import_map_size =
	    adapter->rsm_attr.attr_tot_import_map_size;
	rsm_cattr.attr_max_import_segments =
	    adapter->rsm_attr.attr_max_import_segments;
	rsm_cattr.attr_controller_addr =
	    adapter->rsm_attr.attr_controller_addr;
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmattr_ddi_copyout done\n"));
	if (ddi_copyout((caddr_t)&rsm_cattr, arg,
	    sizeof (rsmka_int_controller_attr_t), mode)) {
		return (RSMERR_BAD_ADDR);
	}
	else
		return (RSM_SUCCESS);
}

/*ARGSUSED*/
static int
rsm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	rsmseg_t *seg;
	rsmresource_t	*res;
	minor_t		rnum;
	rsm_ioctlmsg_t msg = {0};
	int error;
	adapter_t *adapter;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_IOCTL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_ioctl enter\n"));

	if (cmd == RSM_IOCTL_CONSUMEEVENT) {
		error = rsm_consumeevent_ioctl((caddr_t)arg, mode);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_ioctl RSM_IOCTL_CONSUMEEVENT done: %d\n", error));
		return (error);
	}

	/* topology cmd does not use the arg common to other cmds */
	if (RSM_IOCTL_CMDGRP(cmd) == RSM_IOCTL_TOPOLOGY) {
		error = rsmka_topology_ioctl((caddr_t)arg, cmd, mode);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_ioctl done: %d\n", error));
		return (error);
	}

	if (RSM_IOCTL_CMDGRP(cmd) == RSM_IOCTL_IOVEC) {
		error = rsm_iovec_ioctl(dev, (caddr_t)arg, cmd, mode, credp);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_ioctl done: %d\n", error));
		return (error);
	}

	/*
	 * try to load arguments
	 */
	if (cmd != RSM_IOCTL_RING_BELL &&
	    rsm_ddi_copyin((caddr_t)arg, &msg, mode)) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_ioctl done: EFAULT\n"));
		return (RSMERR_BAD_ADDR);
	}

	if (cmd == RSM_IOCTL_ATTR) {
		adapter =  rsm_getadapter(&msg, mode);
		if (adapter == NULL) {
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsm_ioctl done: ENODEV\n"));
			return (RSMERR_CTLR_NOT_PRESENT);
		}
		error = rsmattr_ddi_copyout(adapter, msg.arg, mode);
		rsmka_release_adapter(adapter);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_ioctl:after copyout %d\n", error));
		return (error);
	}

	if (cmd == RSM_IOCTL_BAR_INFO) {
		/* Return library off,len of barrier page */
		msg.off = barrier_offset;
		msg.len = (int)barrier_size;
#ifdef _MULTI_DATAMODEL
		if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
			rsm_ioctlmsg32_t msg32;

			if (msg.len > UINT_MAX)
				msg.len = RSM_MAXSZ_PAGE_ALIGNED;
			else
				msg32.len = (int32_t)msg.len;
			msg32.off = (int32_t)msg.off;
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsm_ioctl done\n"));
			if (ddi_copyout((caddr_t)&msg32, (caddr_t)arg,
			    sizeof (msg32), mode))
				return (RSMERR_BAD_ADDR);
			else
				return (RSM_SUCCESS);
		}
#endif
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_ioctl done\n"));
		if (ddi_copyout((caddr_t)&msg, (caddr_t)arg,
		    sizeof (msg), mode))
			return (RSMERR_BAD_ADDR);
		else
			return (RSM_SUCCESS);
	}

	if (RSM_IOCTL_CMDGRP(cmd) == RSM_IOCTL_MAP_ADDR) {
		/* map the nodeid or hwaddr */
		error = rsmaddr_ioctl(cmd, &msg, mode);
		if (error == RSM_SUCCESS) {
#ifdef _MULTI_DATAMODEL
			if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
				rsm_ioctlmsg32_t msg32;

				msg32.hwaddr = (uint64_t)msg.hwaddr;
				msg32.nodeid = (uint32_t)msg.nodeid;

				DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
				    "rsm_ioctl done\n"));
				if (ddi_copyout((caddr_t)&msg32, (caddr_t)arg,
				    sizeof (msg32), mode))
					return (RSMERR_BAD_ADDR);
				else
					return (RSM_SUCCESS);
			}
#endif
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsm_ioctl done\n"));
			if (ddi_copyout((caddr_t)&msg, (caddr_t)arg,
			    sizeof (msg), mode))
				return (RSMERR_BAD_ADDR);
			else
				return (RSM_SUCCESS);
		}
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_ioctl done: %d\n", error));
		return (error);
	}

	/* Find resource and look it in read mode */
	rnum = getminor(dev);
	res = rsmresource_lookup(rnum, RSM_NOLOCK);
	ASSERT(res != NULL);

	/*
	 * Find command group
	 */
	switch (RSM_IOCTL_CMDGRP(cmd)) {
	case RSM_IOCTL_EXPORT_SEG:
		/*
		 * Export list is searched during publish, loopback and
		 * remote lookup call.
		 */
		seg = rsmresource_seg(res, rnum, credp,
		    RSM_RESOURCE_EXPORT_SEGMENT);
		if (seg->s_type == RSM_RESOURCE_EXPORT_SEGMENT) {
			error = rsmexport_ioctl(seg, &msg, cmd, arg, mode,
			    credp);
		} else { /* export ioctl on an import/barrier resource */
			error = RSMERR_BAD_SEG_HNDL;
		}
		break;
	case RSM_IOCTL_IMPORT_SEG:
		/* Import list is searched during remote unmap call. */
		seg = rsmresource_seg(res, rnum, credp,
		    RSM_RESOURCE_IMPORT_SEGMENT);
		if (seg->s_type == RSM_RESOURCE_IMPORT_SEGMENT) {
			error = rsmimport_ioctl(seg, &msg, cmd, arg, mode,
			    credp);
		} else  { /* import ioctl on an export/barrier resource */
			error = RSMERR_BAD_SEG_HNDL;
		}
		break;
	case RSM_IOCTL_BAR:
		if (res != RSMRC_RESERVED &&
		    res->rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT) {
			error = rsmbar_ioctl((rsmseg_t *)res, &msg, cmd, arg,
			    mode);
		} else { /* invalid res value */
			error = RSMERR_BAD_SEG_HNDL;
		}
		break;
	case RSM_IOCTL_BELL:
		if (res != RSMRC_RESERVED) {
			if (res->rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT)
				error = exportbell_ioctl((rsmseg_t *)res, cmd);
			else if (res->rsmrc_type == RSM_RESOURCE_EXPORT_SEGMENT)
				error = importbell_ioctl((rsmseg_t *)res, cmd);
			else /* RSM_RESOURCE_BAR */
				error = RSMERR_BAD_SEG_HNDL;
		} else { /* invalid res value */
			error = RSMERR_BAD_SEG_HNDL;
		}
		break;
	default:
		error = EINVAL;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_ioctl done: %d\n",
	    error));
	return (error);
}


/* **************************** Segment Mapping Operations ********* */
static rsm_mapinfo_t *
rsm_get_mapinfo(rsmseg_t *seg, off_t off, size_t len, off_t *dev_offset,
    size_t *map_len)
{
	rsm_mapinfo_t	*p;
	/*
	 * Find the correct mapinfo structure to use during the mapping
	 * from the seg->s_mapinfo list.
	 * The seg->s_mapinfo list contains in reverse order the mappings
	 * as returned by the RSMPI rsm_map. In rsm_devmap, we need to
	 * access the correct entry within this list for the mapping
	 * requested.
	 *
	 * The algorithm for selecting a list entry is as follows:
	 *
	 * When start_offset of an entry <= off we have found the entry
	 * we were looking for. Adjust the dev_offset and map_len (needs
	 * to be PAGESIZE aligned).
	 */
	p = seg->s_mapinfo;
	for (; p; p = p->next) {
		if (p->start_offset <= off) {
			*dev_offset = p->dev_offset + off - p->start_offset;
			*map_len = (len > p->individual_len) ?
			    p->individual_len : ptob(btopr(len));
			return (p);
		}
		p = p->next;
	}

	return (NULL);
}

static void
rsm_free_mapinfo(rsm_mapinfo_t  *mapinfo)
{
	rsm_mapinfo_t *p;

	while (mapinfo != NULL) {
		p = mapinfo;
		mapinfo = mapinfo->next;
		kmem_free(p, sizeof (*p));
	}
}

static int
rsmmap_map(devmap_cookie_t dhp, dev_t dev, uint_t flags, offset_t off,
    size_t len, void **pvtp)
{
	rsmcookie_t	*p;
	rsmresource_t	*res;
	rsmseg_t	*seg;
	minor_t rnum;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmmap_map enter\n"));

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmmap_map: dhp = %x\n", dhp));

	flags = flags;

	rnum = getminor(dev);
	res = (rsmresource_t *)rsmresource_lookup(rnum, RSM_NOLOCK);
	ASSERT(res != NULL);

	seg = (rsmseg_t *)res;

	rsmseglock_acquire(seg);

	ASSERT(seg->s_hdr.rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT);

	/*
	 * Allocate structure and add cookie to segment list
	 */
	p = kmem_alloc(sizeof (*p), KM_SLEEP);

	p->c_dhp = dhp;
	p->c_off = off;
	p->c_len = len;
	p->c_next = seg->s_ckl;
	seg->s_ckl = p;

	*pvtp = (void *)seg;

	rsmseglock_release(seg);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmmap_map done\n"));
	return (DDI_SUCCESS);
}

/*
 * Page fault handling is done here. The prerequisite mapping setup
 * has been done in rsm_devmap with calls to ddi_devmem_setup or
 * ddi_umem_setup
 */
static int
rsmmap_access(devmap_cookie_t dhp, void *pvt, offset_t offset, size_t len,
    uint_t type, uint_t rw)
{
	int e;
	rsmseg_t *seg = (rsmseg_t *)pvt;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmmap_access enter\n"));

	rsmseglock_acquire(seg);

	ASSERT(seg->s_hdr.rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT);

	while (seg->s_state == RSM_STATE_MAP_QUIESCE) {
		if (cv_wait_sig(&seg->s_cv, &seg->s_lock) == 0) {
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsmmap_access done: cv_wait INTR"));
			rsmseglock_release(seg);
			return (RSMERR_INTERRUPTED);
		}
	}

	ASSERT(seg->s_state == RSM_STATE_DISCONNECT ||
	    seg->s_state == RSM_STATE_ACTIVE);

	if (seg->s_state == RSM_STATE_DISCONNECT)
		seg->s_flags |= RSM_IMPORT_DUMMY;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmmap_access: dhp = %x\n", dhp));

	rsmseglock_release(seg);

	if (e = devmap_load(dhp, offset, len, type, rw)) {
		DBG_PRINTF((category, RSM_ERR, "devmap_load failed\n"));
	}


	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmmap_access done\n"));

	return (e);
}

static int
rsmmap_dup(devmap_cookie_t dhp, void *oldpvt, devmap_cookie_t new_dhp,
	void **newpvt)
{
	rsmseg_t	*seg = (rsmseg_t *)oldpvt;
	rsmcookie_t	*p, *old;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmmap_dup enter\n"));

	/*
	 * Same as map, create an entry to hold cookie and add it to
	 * connect segment list. The oldpvt is a pointer to segment.
	 * Return segment pointer in newpvt.
	 */
	rsmseglock_acquire(seg);

	ASSERT(seg->s_hdr.rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT);

	/*
	 * Find old cookie
	 */
	for (old = seg->s_ckl; old != NULL; old = old->c_next) {
		if (old->c_dhp == dhp) {
			break;
		}
	}
	if (old == NULL) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmmap_dup done: EINVAL\n"));
		rsmseglock_release(seg);
		return (EINVAL);
	}

	p = kmem_alloc(sizeof (*p), KM_SLEEP);

	p->c_dhp = new_dhp;
	p->c_off = old->c_off;
	p->c_len = old->c_len;
	p->c_next = seg->s_ckl;
	seg->s_ckl = p;

	*newpvt = (void *)seg;

	rsmseglock_release(seg);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmmap_dup done\n"));

	return (DDI_SUCCESS);
}

static void
rsmmap_unmap(devmap_cookie_t dhp, void *pvtp, offset_t off, size_t len,
	devmap_cookie_t new_dhp1, void **pvtp1,
	devmap_cookie_t new_dhp2, void **pvtp2)
{
	/*
	 * Remove pvtp structure from segment list.
	 */
	rsmseg_t	*seg = (rsmseg_t *)pvtp;
	int freeflag;

	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmmap_unmap enter\n"));

	off = off; len = len;
	pvtp1 = pvtp1; pvtp2 = pvtp2;

	rsmseglock_acquire(seg);

	ASSERT(seg->s_hdr.rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmmap_unmap: dhp = %x\n", dhp));
	/*
	 * We can go ahead and remove the dhps even if we are in
	 * the MAPPING state because the dhps being removed here
	 * belong to a different mmap and we are holding the segment
	 * lock.
	 */
	if (new_dhp1 == NULL && new_dhp2 == NULL) {
		/* find and remove dhp handle */
		rsmcookie_t *tmp, **back = &seg->s_ckl;

		while (*back != NULL) {
			tmp = *back;
			if (tmp->c_dhp == dhp) {
				*back = tmp->c_next;
				kmem_free(tmp, sizeof (*tmp));
				break;
			}
			back = &tmp->c_next;
		}
	} else {
		DBG_PRINTF((category, RSM_DEBUG_LVL2,
		    "rsmmap_unmap:parital unmap"
		    "new_dhp1 %lx, new_dhp2 %lx\n",
		    (size_t)new_dhp1, (size_t)new_dhp2));
	}

	/*
	 * rsmmap_unmap is called for each mapping cookie on the list.
	 * When the list becomes empty and we are not in the MAPPING
	 * state then unmap in the rsmpi driver.
	 */
	if ((seg->s_ckl == NULL) && (seg->s_state != RSM_STATE_MAPPING))
		(void) rsm_unmap(seg);

	if (seg->s_state == RSM_STATE_END && seg->s_ckl == NULL) {
		freeflag = 1;
	} else {
		freeflag = 0;
	}

	rsmseglock_release(seg);

	if (freeflag) {
		/* Free the segment structure */
		rsmseg_free(seg);
	}
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmmap_unmap done\n"));

}

static struct devmap_callback_ctl rsmmap_ops = {
	DEVMAP_OPS_REV,	/* devmap_ops version number	*/
	rsmmap_map,	/* devmap_ops map routine */
	rsmmap_access,	/* devmap_ops access routine */
	rsmmap_dup,		/* devmap_ops dup routine		*/
	rsmmap_unmap,	/* devmap_ops unmap routine */
};

static int
rsm_devmap(dev_t dev, devmap_cookie_t dhc, offset_t off, size_t len,
    size_t *maplen, uint_t model /*ARGSUSED*/)
{
	struct devmap_callback_ctl *callbackops = &rsmmap_ops;
	int		err;
	uint_t		maxprot;
	minor_t		rnum;
	rsmseg_t	*seg;
	off_t		dev_offset;
	size_t		cur_len;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_devmap enter\n"));

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_devmap: off = %lx, len = %lx\n", off, len));
	rnum = getminor(dev);
	seg = (rsmseg_t *)rsmresource_lookup(rnum, RSM_NOLOCK);
	ASSERT(seg != NULL);

	if (seg->s_hdr.rsmrc_type == RSM_RESOURCE_BAR) {
		if ((off == barrier_offset) &&
		    (len == barrier_size)) {

			ASSERT(bar_va != NULL && bar_cookie != NULL);

			/*
			 * The offset argument in devmap_umem_setup represents
			 * the offset within the kernel memory defined by the
			 * cookie. We use this offset as barrier_offset.
			 */
			err = devmap_umem_setup(dhc, rsm_dip, NULL, bar_cookie,
			    barrier_offset, len, PROT_USER|PROT_READ,
			    DEVMAP_DEFAULTS, 0);

			if (err != 0) {
				DBG_PRINTF((category, RSM_ERR,
				    "rsm_devmap done: %d\n", err));
				return (RSMERR_MAP_FAILED);
			}
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsm_devmap done: %d\n", err));

			*maplen = barrier_size;

			return (err);
		} else {
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsm_devmap done: %d\n", err));
			return (RSMERR_MAP_FAILED);
		}
	}

	ASSERT(seg->s_hdr.rsmrc_type == RSM_RESOURCE_IMPORT_SEGMENT);
	ASSERT(seg->s_state == RSM_STATE_MAPPING);

	/*
	 * Make sure we still have permission for the map operation.
	 */
	maxprot = PROT_USER;
	if (seg->s_mode & RSM_PERM_READ) {
		maxprot |= PROT_READ;
	}

	if (seg->s_mode & RSM_PERM_WRITE) {
		maxprot |= PROT_WRITE;
	}

	/*
	 * For each devmap call, rsmmap_map is called. This maintains driver
	 * private information for the mapping. Thus, if there are multiple
	 * devmap calls there will be multiple rsmmap_map calls and for each
	 * call, the mapping information will be stored.
	 * In case of an error during the processing of the devmap call, error
	 * will be returned. This error return causes the caller of rsm_devmap
	 * to undo all the mappings by calling rsmmap_unmap for each one.
	 * rsmmap_unmap will free up the private information for the requested
	 * mapping.
	 */
	if (seg->s_node != my_nodeid) {
		rsm_mapinfo_t *p;

		p = rsm_get_mapinfo(seg, off, len, &dev_offset, &cur_len);
		if (p == NULL) {
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsm_devmap: incorrect mapping info\n"));
			return (RSMERR_MAP_FAILED);
		}
		err = devmap_devmem_setup(dhc, p->dip,
		    callbackops, p->dev_register,
		    dev_offset, cur_len, maxprot,
		    DEVMAP_ALLOW_REMAP | DEVMAP_DEFAULTS, 0);

		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_devmap: dip=%lx,dreg=%lu,doff=%lx,"
		    "off=%lx,len=%lx\n",
		    p->dip, p->dev_register, dev_offset, off, cur_len));

		if (err != 0) {
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsm_devmap: devmap_devmem_setup failed %d\n",
			    err));
			return (RSMERR_MAP_FAILED);
		}
		/* cur_len is always an integral multiple pagesize */
		ASSERT((cur_len & (PAGESIZE-1)) == 0);
		*maplen = cur_len;
		return (err);

	} else {
		err = devmap_umem_setup(dhc, rsm_dip, callbackops,
		    seg->s_cookie, off, len, maxprot,
		    DEVMAP_ALLOW_REMAP|DEVMAP_DEFAULTS, 0);
		if (err != 0) {
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsm_devmap: devmap_umem_setup failed %d\n",
			    err));
			return (RSMERR_MAP_FAILED);
		}
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_devmap: loopback done\n"));

		*maplen = ptob(btopr(len));

		return (err);
	}
}

/*
 * We can use the devmap framework for mapping device memory to user space by
 * specifying this routine in the rsm_cb_ops structure. The kernel mmap
 * processing calls this entry point and devmap_setup is called within this
 * function, which eventually calls rsm_devmap
 */
static int
rsm_segmap(dev_t dev, off_t off, struct as *as, caddr_t *addrp, off_t len,
    uint_t prot, uint_t maxprot, uint_t flags, struct cred *cred)
{
	int			error = 0;
	int			old_state;
	minor_t			rnum;
	rsmseg_t		*seg, *eseg;
	adapter_t		*adapter;
	rsm_import_share_t	*sharedp;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_DDI);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_segmap enter\n"));

	/*
	 * find segment
	 */
	rnum = getminor(dev);
	seg = (rsmseg_t *)rsmresource_lookup(rnum, RSM_LOCK);

	if (seg == NULL) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_segmap done: invalid segment\n"));
		return (EINVAL);
	}

	/*
	 * the user is trying to map a resource that has not been
	 * defined yet. The library uses this to map in the
	 * barrier page.
	 */
	if (seg->s_hdr.rsmrc_type == RSM_RESOURCE_BAR) {
		rsmseglock_release(seg);

		/*
		 * The mapping for the barrier page is identified
		 * by the special offset barrier_offset
		 */

		if (off == (off_t)barrier_offset ||
		    len == (off_t)barrier_size) {
			if (bar_cookie == NULL || bar_va == NULL) {
				DBG_PRINTF((category, RSM_DEBUG,
				    "rsm_segmap: bar cookie/va is NULL\n"));
				return (EINVAL);
			}

			error = devmap_setup(dev, (offset_t)off, as, addrp,
			    (size_t)len, prot, maxprot, flags,  cred);

			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsm_segmap done: %d\n", error));
			return (error);
		} else {
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsm_segmap: bad offset/length\n"));
			return (EINVAL);
		}
	}

	/* Make sure you can only map imported segments */
	if (seg->s_hdr.rsmrc_type != RSM_RESOURCE_IMPORT_SEGMENT) {
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_segmap done: not an import segment\n"));
		return (EINVAL);
	}
	/* check means library is broken */
	ASSERT(seg->s_hdr.rsmrc_num == rnum);

	/* wait for the segment to become unquiesced */
	while (seg->s_state == RSM_STATE_CONN_QUIESCE) {
		if (cv_wait_sig(&seg->s_cv, &seg->s_lock) == 0) {
			rsmseglock_release(seg);
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsm_segmap done: cv_wait INTR"));
			return (ENODEV);
		}
	}

	/* wait until segment leaves the mapping state */
	while (seg->s_state == RSM_STATE_MAPPING)
		cv_wait(&seg->s_cv, &seg->s_lock);

	/*
	 * we allow multiple maps of the same segment in the KA
	 * and it works because we do an rsmpi map of the whole
	 * segment during the first map and all the device mapping
	 * information needed in rsm_devmap is in the mapinfo list.
	 */
	if ((seg->s_state != RSM_STATE_CONNECT) &&
	    (seg->s_state != RSM_STATE_ACTIVE)) {
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_segmap done: segment not connected\n"));
		return (ENODEV);
	}

	/*
	 * Make sure we are not mapping a larger segment than what's
	 * exported
	 */
	if ((size_t)off + ptob(btopr(len)) > seg->s_len) {
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_segmap done: off+len>seg size\n"));
		return (ENXIO);
	}

	/*
	 * Make sure we still have permission for the map operation.
	 */
	maxprot = PROT_USER;
	if (seg->s_mode & RSM_PERM_READ) {
		maxprot |= PROT_READ;
	}

	if (seg->s_mode & RSM_PERM_WRITE) {
		maxprot |= PROT_WRITE;
	}

	if ((prot & maxprot) != prot) {
		/* No permission */
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_segmap done: no permission\n"));
		return (EACCES);
	}

	old_state = seg->s_state;

	ASSERT(seg->s_share != NULL);

	rsmsharelock_acquire(seg);

	sharedp = seg->s_share;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_segmap:RSMSI_STATE=%d\n", sharedp->rsmsi_state));

	if ((sharedp->rsmsi_state != RSMSI_STATE_CONNECTED) &&
	    (sharedp->rsmsi_state != RSMSI_STATE_MAPPED)) {
		rsmsharelock_release(seg);
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsm_segmap done:RSMSI_STATE %d invalid\n",
		    sharedp->rsmsi_state));
		return (ENODEV);
	}

	/*
	 * Do the map - since we want importers to share mappings
	 * we do the rsmpi map for the whole segment
	 */
	if (seg->s_node != my_nodeid) {
		uint_t dev_register;
		off_t dev_offset;
		dev_info_t *dip;
		size_t tmp_len;
		size_t total_length_mapped = 0;
		size_t length_to_map = seg->s_len;
		off_t tmp_off = 0;
		rsm_mapinfo_t *p;

		/*
		 * length_to_map = seg->s_len is always an integral
		 * multiple of PAGESIZE. Length mapped in each entry in mapinfo
		 * list is a multiple of PAGESIZE - RSMPI map ensures this
		 */

		adapter = seg->s_adapter;
		ASSERT(sharedp->rsmsi_state == RSMSI_STATE_CONNECTED ||
		    sharedp->rsmsi_state == RSMSI_STATE_MAPPED);

		if (sharedp->rsmsi_state == RSMSI_STATE_CONNECTED) {
			error = 0;
			/* map the whole segment */
			while (total_length_mapped < seg->s_len) {
				tmp_len = 0;

				error = adapter->rsmpi_ops->rsm_map(
				    seg->s_handle.in, tmp_off,
				    length_to_map, &tmp_len,
				    &dip, &dev_register, &dev_offset,
				    NULL, NULL);

				if (error != 0)
					break;

				/*
				 * Store the mapping info obtained from rsm_map
				 */
				p = kmem_alloc(sizeof (*p), KM_SLEEP);
				p->dev_register = dev_register;
				p->dev_offset = dev_offset;
				p->dip = dip;
				p->individual_len = tmp_len;
				p->start_offset = tmp_off;
				p->next = sharedp->rsmsi_mapinfo;
				sharedp->rsmsi_mapinfo = p;

				total_length_mapped += tmp_len;
				length_to_map -= tmp_len;
				tmp_off += tmp_len;
			}
			seg->s_mapinfo = sharedp->rsmsi_mapinfo;

			if (error != RSM_SUCCESS) {
				/* Check if this is the the first rsm_map */
				if (sharedp->rsmsi_mapinfo != NULL) {
					/*
					 * A single rsm_unmap undoes
					 * multiple rsm_maps.
					 */
					(void) seg->s_adapter->rsmpi_ops->
					    rsm_unmap(sharedp->rsmsi_handle);
					rsm_free_mapinfo(sharedp->
					    rsmsi_mapinfo);
				}
				sharedp->rsmsi_mapinfo = NULL;
				sharedp->rsmsi_state = RSMSI_STATE_CONNECTED;
				rsmsharelock_release(seg);
				rsmseglock_release(seg);
				DBG_PRINTF((category, RSM_DEBUG,
				    "rsm_segmap done: rsmpi map err %d\n",
				    error));
				ASSERT(error != RSMERR_BAD_LENGTH &&
				    error != RSMERR_BAD_MEM_ALIGNMENT &&
				    error != RSMERR_BAD_SEG_HNDL);
				if (error == RSMERR_UNSUPPORTED_OPERATION)
					return (ENOTSUP);
				else if (error == RSMERR_INSUFFICIENT_RESOURCES)
					return (EAGAIN);
				else if (error == RSMERR_CONN_ABORTED)
					return (ENODEV);
				else
					return (error);
			} else {
				sharedp->rsmsi_state = RSMSI_STATE_MAPPED;
			}
		} else {
			seg->s_mapinfo = sharedp->rsmsi_mapinfo;
		}

		sharedp->rsmsi_mapcnt++;

		rsmsharelock_release(seg);

		/* move to an intermediate mapping state */
		seg->s_state = RSM_STATE_MAPPING;
		rsmseglock_release(seg);

		error = devmap_setup(dev, (offset_t)off, as, addrp,
		    len, prot, maxprot, flags, cred);

		rsmseglock_acquire(seg);
		ASSERT(seg->s_state == RSM_STATE_MAPPING);

		if (error == DDI_SUCCESS) {
			seg->s_state = RSM_STATE_ACTIVE;
		} else {
			rsmsharelock_acquire(seg);

			ASSERT(sharedp->rsmsi_state == RSMSI_STATE_MAPPED);

			sharedp->rsmsi_mapcnt--;
			if (sharedp->rsmsi_mapcnt == 0) {
				/* unmap the shared RSMPI mapping */
				ASSERT(sharedp->rsmsi_handle != NULL);
				(void) adapter->rsmpi_ops->
				    rsm_unmap(sharedp->rsmsi_handle);
				rsm_free_mapinfo(sharedp->rsmsi_mapinfo);
				sharedp->rsmsi_mapinfo = NULL;
				sharedp->rsmsi_state = RSMSI_STATE_CONNECTED;
			}

			rsmsharelock_release(seg);
			seg->s_state = old_state;
			DBG_PRINTF((category, RSM_ERR,
			    "rsm: devmap_setup failed %d\n", error));
		}
		cv_broadcast(&seg->s_cv);
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG_LVL2, "rsm_segmap done: %d\n",
		    error));
		return (error);
	} else {
		/*
		 * For loopback, the export segment mapping cookie (s_cookie)
		 * is also used as the s_cookie value for its import segments
		 * during mapping.
		 * Note that reference counting for s_cookie of the export
		 * segment is not required due to the following:
		 * We never have a case of the export segment being destroyed,
		 * leaving the import segments with a stale value for the
		 * s_cookie field, since a force disconnect is done prior to a
		 * destroy of an export segment. The force disconnect causes
		 * the s_cookie value to be reset to NULL. Also for the
		 * rsm_rebind operation, we change the s_cookie value of the
		 * export segment as well as of all its local (loopback)
		 * importers.
		 */
		DBG_ADDCATEGORY(category, RSM_LOOPBACK);

		rsmsharelock_release(seg);
		/*
		 * In order to maintain the lock ordering between the export
		 * and import segment locks, we need to acquire the export
		 * segment lock first and only then acquire the import
		 * segment lock.
		 * The above is necessary to avoid any deadlock scenarios
		 * with rsm_rebind which also acquires both the export
		 * and import segment locks in the above mentioned order.
		 * Based on code inspection, there seem to be no other
		 * situations in which both the export and import segment
		 * locks are acquired either in the same or opposite order
		 * as mentioned above.
		 * Thus in order to conform to the above lock order, we
		 * need to change the state of the import segment to
		 * RSM_STATE_MAPPING, release the lock. Once this is done we
		 * can now safely acquire the export segment lock first
		 * followed by the import segment lock which is as per
		 * the lock order mentioned above.
		 */
		/* move to an intermediate mapping state */
		seg->s_state = RSM_STATE_MAPPING;
		rsmseglock_release(seg);

		eseg = rsmexport_lookup(seg->s_key);

		if (eseg == NULL) {
			rsmseglock_acquire(seg);
			/*
			 * Revert to old_state and signal any waiters
			 * The shared state is not changed
			 */

			seg->s_state = old_state;
			cv_broadcast(&seg->s_cv);
			rsmseglock_release(seg);
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsm_segmap done: key %d not found\n", seg->s_key));
			return (ENODEV);
		}

		rsmsharelock_acquire(seg);
		ASSERT(sharedp->rsmsi_state == RSMSI_STATE_CONNECTED ||
		    sharedp->rsmsi_state == RSMSI_STATE_MAPPED);

		sharedp->rsmsi_mapcnt++;
		sharedp->rsmsi_state = RSMSI_STATE_MAPPED;
		rsmsharelock_release(seg);

		ASSERT(eseg->s_cookie != NULL);

		/*
		 * It is not required or necessary to acquire the import
		 * segment lock here to change the value of s_cookie since
		 * no one will touch the import segment as long as it is
		 * in the RSM_STATE_MAPPING state.
		 */
		seg->s_cookie = eseg->s_cookie;

		rsmseglock_release(eseg);

		error = devmap_setup(dev, (offset_t)off, as, addrp, (size_t)len,
		    prot, maxprot, flags, cred);

		rsmseglock_acquire(seg);
		ASSERT(seg->s_state == RSM_STATE_MAPPING);
		if (error == 0) {
			seg->s_state = RSM_STATE_ACTIVE;
		} else {
			rsmsharelock_acquire(seg);

			ASSERT(sharedp->rsmsi_state == RSMSI_STATE_MAPPED);

			sharedp->rsmsi_mapcnt--;
			if (sharedp->rsmsi_mapcnt == 0) {
				sharedp->rsmsi_mapinfo = NULL;
				sharedp->rsmsi_state = RSMSI_STATE_CONNECTED;
			}
			rsmsharelock_release(seg);
			seg->s_state = old_state;
			seg->s_cookie = NULL;
		}
		cv_broadcast(&seg->s_cv);
		rsmseglock_release(seg);
		DBG_PRINTF((category, RSM_DEBUG_LVL2,
		    "rsm_segmap done: %d\n", error));
		return (error);
	}
}

int
rsmka_null_seg_create(
    rsm_controller_handle_t argcp,
    rsm_memseg_export_handle_t *handle,
    size_t size,
    uint_t flags,
    rsm_memory_local_t *memory,
    rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg	/*ARGSUSED*/)
{
	return (RSM_SUCCESS);
}


int
rsmka_null_seg_destroy(
    rsm_memseg_export_handle_t argmemseg	/*ARGSUSED*/)
{
	return (RSM_SUCCESS);
}


int
rsmka_null_bind(
    rsm_memseg_export_handle_t argmemseg,
    off_t offset,
    rsm_memory_local_t *argmemory,
    rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg	/*ARGSUSED*/)
{
	return (RSM_SUCCESS);
}


int
rsmka_null_unbind(
    rsm_memseg_export_handle_t argmemseg,
    off_t offset,
    size_t length	/*ARGSUSED*/)
{
	return (DDI_SUCCESS);
}

int
rsmka_null_rebind(
    rsm_memseg_export_handle_t argmemseg,
    off_t offset,
    rsm_memory_local_t *memory,
    rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg	/*ARGSUSED*/)
{
	return (RSM_SUCCESS);
}

int
rsmka_null_publish(
    rsm_memseg_export_handle_t argmemseg,
    rsm_access_entry_t access_list[],
    uint_t access_list_length,
    rsm_memseg_id_t segment_id,
    rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg	/*ARGSUSED*/)
{
	return (RSM_SUCCESS);
}


int
rsmka_null_republish(
    rsm_memseg_export_handle_t memseg,
    rsm_access_entry_t access_list[],
    uint_t access_list_length,
    rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg	/*ARGSUSED*/)
{
	return (RSM_SUCCESS);
}

int
rsmka_null_unpublish(
    rsm_memseg_export_handle_t argmemseg	/*ARGSUSED*/)
{
	return (RSM_SUCCESS);
}


void
rsmka_init_loopback()
{
	rsm_ops_t	*ops = &null_rsmpi_ops;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL | RSM_LOOPBACK);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_init_loopback enter\n"));

	/* initialize null ops vector */
	ops->rsm_seg_create = rsmka_null_seg_create;
	ops->rsm_seg_destroy = rsmka_null_seg_destroy;
	ops->rsm_bind = rsmka_null_bind;
	ops->rsm_unbind = rsmka_null_unbind;
	ops->rsm_rebind = rsmka_null_rebind;
	ops->rsm_publish = rsmka_null_publish;
	ops->rsm_unpublish = rsmka_null_unpublish;
	ops->rsm_republish = rsmka_null_republish;

	/* initialize attributes for loopback adapter */
	loopback_attr.attr_name = loopback_str;
	loopback_attr.attr_page_size = 0x8; /* 8K */

	/* initialize loopback adapter */
	loopback_adapter.rsm_attr = loopback_attr;
	loopback_adapter.rsmpi_ops = &null_rsmpi_ops;
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_init_loopback done\n"));
}

/* ************** DR functions ********************************** */
static void
rsm_quiesce_exp_seg(rsmresource_t *resp)
{
	int		recheck_state;
	rsmseg_t	*segp = (rsmseg_t *)resp;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);
	DBG_DEFINE_STR(function, "rsm_unquiesce_exp_seg");

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "%s enter: key=%u\n", function, segp->s_key));

	rsmseglock_acquire(segp);
	do {
		recheck_state = 0;
		if ((segp->s_state == RSM_STATE_NEW_QUIESCED) ||
		    (segp->s_state == RSM_STATE_BIND_QUIESCED) ||
		    (segp->s_state == RSM_STATE_EXPORT_QUIESCING) ||
		    (segp->s_state == RSM_STATE_EXPORT_QUIESCED)) {
			rsmseglock_release(segp);
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "%s done:state =%d\n", function,
			    segp->s_state));
			return;
		}

		if (segp->s_state == RSM_STATE_NEW) {
			segp->s_state = RSM_STATE_NEW_QUIESCED;
			rsmseglock_release(segp);
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "%s done:state =%d\n", function,
			    segp->s_state));
			return;
		}

		if (segp->s_state == RSM_STATE_BIND) {
			/* unbind */
			(void) rsm_unbind_pages(segp);
			segp->s_state = RSM_STATE_BIND_QUIESCED;
			rsmseglock_release(segp);
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "%s done:state =%d\n", function,
			    segp->s_state));
			return;
		}

		if (segp->s_state == RSM_STATE_EXPORT) {
			/*
			 * wait for putv/getv to complete if the segp is
			 * a local memory handle
			 */
			while ((segp->s_state == RSM_STATE_EXPORT) &&
			    (segp->s_rdmacnt != 0)) {
				cv_wait(&segp->s_cv, &segp->s_lock);
			}

			if (segp->s_state != RSM_STATE_EXPORT) {
				/*
				 * state changed need to see what it
				 * should be changed to.
				 */
				recheck_state = 1;
				continue;
			}

			segp->s_state = RSM_STATE_EXPORT_QUIESCING;
			rsmseglock_release(segp);
			/*
			 * send SUSPEND messages - currently it will be
			 * done at the end
			 */
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "%s done:state =%d\n", function,
			    segp->s_state));
			return;
		}
	} while (recheck_state);

	rsmseglock_release(segp);
}

static void
rsm_unquiesce_exp_seg(rsmresource_t *resp)
{
	int			ret;
	rsmseg_t		*segp = (rsmseg_t *)resp;
	rsmapi_access_entry_t	*acl;
	rsm_access_entry_t	*rsmpi_acl;
	int			acl_len;
	int			create_flags = 0;
	struct buf		*xbuf;
	rsm_memory_local_t	mem;
	adapter_t		*adapter;
	dev_t			sdev = 0;
	rsm_resource_callback_t callback_flag;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);
	DBG_DEFINE_STR(function, "rsm_unquiesce_exp_seg");

	rsmseglock_acquire(segp);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "%s enter: key=%u, state=%d\n", function, segp->s_key,
	    segp->s_state));

	if ((segp->s_state == RSM_STATE_NEW) ||
	    (segp->s_state == RSM_STATE_BIND) ||
	    (segp->s_state == RSM_STATE_EXPORT)) {
		rsmseglock_release(segp);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "%s done:state=%d\n",
		    function, segp->s_state));
		return;
	}

	if (segp->s_state == RSM_STATE_NEW_QUIESCED) {
		segp->s_state = RSM_STATE_NEW;
		cv_broadcast(&segp->s_cv);
		rsmseglock_release(segp);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "%s done:state=%d\n",
		    function, segp->s_state));
		return;
	}

	if (segp->s_state == RSM_STATE_BIND_QUIESCED) {
		/* bind the segment */
		ret = rsm_bind_pages(&segp->s_cookie, segp->s_region.r_vaddr,
		    segp->s_len, segp->s_proc);
		if (ret == RSM_SUCCESS) { /* bind successful */
			segp->s_state = RSM_STATE_BIND;
		} else { /* bind failed - resource unavailable */
			segp->s_state = RSM_STATE_NEW;
		}
		cv_broadcast(&segp->s_cv);
		rsmseglock_release(segp);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "%s done: bind_qscd bind = %d\n", function, ret));
		return;
	}

	while (segp->s_state == RSM_STATE_EXPORT_QUIESCING) {
		/* wait for the segment to move to EXPORT_QUIESCED state */
		cv_wait(&segp->s_cv, &segp->s_lock);
	}

	if (segp->s_state == RSM_STATE_EXPORT_QUIESCED) {
		/* bind the segment */
		ret = rsm_bind_pages(&segp->s_cookie, segp->s_region.r_vaddr,
		    segp->s_len, segp->s_proc);

		if (ret != RSM_SUCCESS) {
			/* bind failed - resource unavailable */
			acl_len = segp->s_acl_len;
			acl = segp->s_acl;
			rsmpi_acl = segp->s_acl_in;
			segp->s_acl_len = 0;
			segp->s_acl = NULL;
			segp->s_acl_in = NULL;
			rsmseglock_release(segp);

			rsmexport_rm(segp);
			rsmacl_free(acl, acl_len);
			rsmpiacl_free(rsmpi_acl, acl_len);

			rsmseglock_acquire(segp);
			segp->s_state = RSM_STATE_NEW;
			cv_broadcast(&segp->s_cv);
			rsmseglock_release(segp);
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "%s done: exp_qscd bind failed = %d\n",
			    function, ret));
			return;
		}
		/*
		 * publish the segment
		 * if  successful
		 *   segp->s_state = RSM_STATE_EXPORT;
		 * else failed
		 *   segp->s_state = RSM_STATE_BIND;
		 */

		/* check whether it is a local_memory_handle */
		if (segp->s_acl != (rsmapi_access_entry_t *)NULL) {
			if ((segp->s_acl[0].ae_node == my_nodeid) &&
			    (segp->s_acl[0].ae_permission == 0)) {
				segp->s_state = RSM_STATE_EXPORT;
				cv_broadcast(&segp->s_cv);
				rsmseglock_release(segp);
				DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
				    "%s done:exp_qscd\n", function));
				return;
			}
		}
		xbuf = ddi_umem_iosetup(segp->s_cookie, 0, segp->s_len, B_WRITE,
		    sdev, 0, NULL, DDI_UMEM_SLEEP);
		ASSERT(xbuf != NULL);

		mem.ms_type = RSM_MEM_BUF;
		mem.ms_bp = xbuf;

		adapter = segp->s_adapter;

		if (segp->s_flags & RSMKA_ALLOW_UNBIND_REBIND) {
			create_flags = RSM_ALLOW_UNBIND_REBIND;
		}

		if (segp->s_flags & RSMKA_SET_RESOURCE_DONTWAIT) {
			callback_flag  = RSM_RESOURCE_DONTWAIT;
		} else {
			callback_flag  = RSM_RESOURCE_SLEEP;
		}

		ret = adapter->rsmpi_ops->rsm_seg_create(
		    adapter->rsmpi_handle, &segp->s_handle.out,
		    segp->s_len, create_flags, &mem,
		    callback_flag, NULL);

		if (ret != RSM_SUCCESS) {
			acl_len = segp->s_acl_len;
			acl = segp->s_acl;
			rsmpi_acl = segp->s_acl_in;
			segp->s_acl_len = 0;
			segp->s_acl = NULL;
			segp->s_acl_in = NULL;
			rsmseglock_release(segp);

			rsmexport_rm(segp);
			rsmacl_free(acl, acl_len);
			rsmpiacl_free(rsmpi_acl, acl_len);

			rsmseglock_acquire(segp);
			segp->s_state = RSM_STATE_BIND;
			cv_broadcast(&segp->s_cv);
			rsmseglock_release(segp);
			DBG_PRINTF((category, RSM_ERR,
			    "%s done: exp_qscd create failed = %d\n",
			    function, ret));
			return;
		}

		ret = adapter->rsmpi_ops->rsm_publish(
		    segp->s_handle.out, segp->s_acl_in, segp->s_acl_len,
		    segp->s_segid, RSM_RESOURCE_DONTWAIT, NULL);

		if (ret != RSM_SUCCESS) {
			acl_len = segp->s_acl_len;
			acl = segp->s_acl;
			rsmpi_acl = segp->s_acl_in;
			segp->s_acl_len = 0;
			segp->s_acl = NULL;
			segp->s_acl_in = NULL;
			adapter->rsmpi_ops->rsm_seg_destroy(segp->s_handle.out);
			rsmseglock_release(segp);

			rsmexport_rm(segp);
			rsmacl_free(acl, acl_len);
			rsmpiacl_free(rsmpi_acl, acl_len);

			rsmseglock_acquire(segp);
			segp->s_state = RSM_STATE_BIND;
			cv_broadcast(&segp->s_cv);
			rsmseglock_release(segp);
			DBG_PRINTF((category, RSM_ERR,
			    "%s done: exp_qscd publish failed = %d\n",
			    function, ret));
			return;
		}

		segp->s_state = RSM_STATE_EXPORT;
		cv_broadcast(&segp->s_cv);
		rsmseglock_release(segp);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "%s done: exp_qscd\n",
		    function));
		return;
	}

	rsmseglock_release(segp);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "%s done\n", function));
}

static void
rsm_quiesce_imp_seg(rsmresource_t *resp)
{
	rsmseg_t	*segp = (rsmseg_t *)resp;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);
	DBG_DEFINE_STR(function, "rsm_quiesce_imp_seg");

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "%s enter: key=%u\n", function, segp->s_key));

	rsmseglock_acquire(segp);
	segp->s_flags |= RSM_DR_INPROGRESS;

	while (segp->s_rdmacnt != 0) {
		/* wait for the RDMA to complete */
		cv_wait(&segp->s_cv, &segp->s_lock);
	}

	rsmseglock_release(segp);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "%s done\n", function));

}

static void
rsm_unquiesce_imp_seg(rsmresource_t *resp)
{
	rsmseg_t	*segp = (rsmseg_t *)resp;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);
	DBG_DEFINE_STR(function, "rsm_unquiesce_imp_seg");

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "%s enter: key=%u\n", function, segp->s_key));

	rsmseglock_acquire(segp);

	segp->s_flags &= ~RSM_DR_INPROGRESS;
	/* wake up any waiting putv/getv ops */
	cv_broadcast(&segp->s_cv);

	rsmseglock_release(segp);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "%s done\n", function));


}

static void
rsm_process_exp_seg(rsmresource_t *resp, int event)
{
	if (event == RSM_DR_QUIESCE)
		rsm_quiesce_exp_seg(resp);
	else /* UNQUIESCE */
		rsm_unquiesce_exp_seg(resp);
}

static void
rsm_process_imp_seg(rsmresource_t *resp, int event)
{
	if (event == RSM_DR_QUIESCE)
		rsm_quiesce_imp_seg(resp);
	else /* UNQUIESCE */
		rsm_unquiesce_imp_seg(resp);
}

static void
rsm_dr_process_local_segments(int event)
{

	int i, j;
	rsmresource_blk_t	*blk;
	rsmresource_t		*p;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_dr_process_local_segments enter\n"));

	/* iterate through the resource structure */

	rw_enter(&rsm_resource.rsmrc_lock, RW_READER);

	for (i = 0; i < rsm_resource.rsmrc_len; i++) {
		blk = rsm_resource.rsmrc_root[i];
		if (blk != NULL) {
			for (j = 0; j < RSMRC_BLKSZ; j++) {
				p = blk->rsmrcblk_blks[j];
				if ((p != NULL) && (p != RSMRC_RESERVED)) {
					/* valid resource */
					if (p->rsmrc_type ==
					    RSM_RESOURCE_EXPORT_SEGMENT)
						rsm_process_exp_seg(p, event);
					else if (p->rsmrc_type ==
					    RSM_RESOURCE_IMPORT_SEGMENT)
						rsm_process_imp_seg(p, event);
				}
			}
		}
	}

	rw_exit(&rsm_resource.rsmrc_lock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_dr_process_local_segments done\n"));
}

/* *************** DR callback functions ************ */
static void
rsm_dr_callback_post_add(void *arg, pgcnt_t delta /* ARGSUSED */)
{
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_dr_callback_post_add is a no-op\n"));
	/* Noop */
}

static int
rsm_dr_callback_pre_del(void *arg, pgcnt_t delta /* ARGSUSED */)
{
	int	recheck_state = 0;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_dr_callback_pre_del enter\n"));

	mutex_enter(&rsm_drv_data.drv_lock);

	do {
		recheck_state = 0;
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_dr_callback_pre_del:state=%d\n",
		    rsm_drv_data.drv_state));

		switch (rsm_drv_data.drv_state) {
		case RSM_DRV_NEW:
			/*
			 * The state should usually never be RSM_DRV_NEW
			 * since in this state the callbacks have not yet
			 * been registered. So, ASSERT.
			 */
			ASSERT(0);
			return (0);
		case RSM_DRV_REG_PROCESSING:
			/*
			 * The driver is in the process of registering
			 * with the DR framework. So, wait till the
			 * registration process is complete.
			 */
			recheck_state = 1;
			cv_wait(&rsm_drv_data.drv_cv, &rsm_drv_data.drv_lock);
			break;
		case RSM_DRV_UNREG_PROCESSING:
			/*
			 * If the state is RSM_DRV_UNREG_PROCESSING, the
			 * module is in the process of detaching and
			 * unregistering the callbacks from the DR
			 * framework. So, simply return.
			 */
			mutex_exit(&rsm_drv_data.drv_lock);
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsm_dr_callback_pre_del:"
			    "pre-del on NEW/UNREG\n"));
			return (0);
		case RSM_DRV_OK:
			rsm_drv_data.drv_state = RSM_DRV_PREDEL_STARTED;
			break;
		case RSM_DRV_PREDEL_STARTED:
			/* FALLTHRU */
		case RSM_DRV_PREDEL_COMPLETED:
			/* FALLTHRU */
		case RSM_DRV_POSTDEL_IN_PROGRESS:
			recheck_state = 1;
			cv_wait(&rsm_drv_data.drv_cv, &rsm_drv_data.drv_lock);
			break;
		case RSM_DRV_DR_IN_PROGRESS:
			rsm_drv_data.drv_memdel_cnt++;
			mutex_exit(&rsm_drv_data.drv_lock);
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsm_dr_callback_pre_del done\n"));
			return (0);
			/* break; */
		default:
			ASSERT(0);
			break;
		}

	} while (recheck_state);

	rsm_drv_data.drv_memdel_cnt++;

	mutex_exit(&rsm_drv_data.drv_lock);

	/* Do all the quiescing stuff here */
	DBG_PRINTF((category, RSM_DEBUG,
	    "rsm_dr_callback_pre_del: quiesce things now\n"));

	rsm_dr_process_local_segments(RSM_DR_QUIESCE);

	/*
	 * now that all local segments have been quiesced lets inform
	 * the importers
	 */
	rsm_send_suspend();

	/*
	 * In response to the suspend message the remote node(s) will process
	 * the segments and send a suspend_complete message. Till all
	 * the nodes send the suspend_complete message we wait in the
	 * RSM_DRV_PREDEL_STARTED state. In the exporter_quiesce
	 * function we transition to the RSM_DRV_PREDEL_COMPLETED state.
	 */
	mutex_enter(&rsm_drv_data.drv_lock);

	while (rsm_drv_data.drv_state == RSM_DRV_PREDEL_STARTED) {
		cv_wait(&rsm_drv_data.drv_cv, &rsm_drv_data.drv_lock);
	}

	ASSERT(rsm_drv_data.drv_state == RSM_DRV_PREDEL_COMPLETED);

	rsm_drv_data.drv_state = RSM_DRV_DR_IN_PROGRESS;
	cv_broadcast(&rsm_drv_data.drv_cv);

	mutex_exit(&rsm_drv_data.drv_lock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_dr_callback_pre_del done\n"));

	return (0);
}

static void
rsm_dr_callback_post_del(void *arg, pgcnt_t delta, int cancelled /* ARGSUSED */)
{
	int	recheck_state = 0;
	DBG_DEFINE(category, RSM_KERNEL_AGENT | RSM_FUNC_ALL);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_dr_callback_post_del enter\n"));

	mutex_enter(&rsm_drv_data.drv_lock);

	do {
		recheck_state = 0;
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsm_dr_callback_post_del:state=%d\n",
		    rsm_drv_data.drv_state));

		switch (rsm_drv_data.drv_state) {
		case RSM_DRV_NEW:
			/*
			 * The driver state cannot not be RSM_DRV_NEW
			 * since in this state the callbacks have not
			 * yet been registered.
			 */
			ASSERT(0);
			return;
		case RSM_DRV_REG_PROCESSING:
			/*
			 * The driver is in the process of registering with
			 * the DR framework. Wait till the registration is
			 * complete.
			 */
			recheck_state = 1;
			cv_wait(&rsm_drv_data.drv_cv, &rsm_drv_data.drv_lock);
			break;
		case RSM_DRV_UNREG_PROCESSING:
			/*
			 * RSM_DRV_UNREG_PROCESSING state means the module
			 * is detaching and unregistering the callbacks
			 * from the DR framework. So simply return.
			 */
			/* FALLTHRU */
		case RSM_DRV_OK:
			/*
			 * RSM_DRV_OK means we missed the pre-del
			 * corresponding to this post-del coz we had not
			 * registered yet, so simply return.
			 */
			mutex_exit(&rsm_drv_data.drv_lock);
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsm_dr_callback_post_del:"
			    "post-del on OK/UNREG\n"));
			return;
			/* break; */
		case RSM_DRV_PREDEL_STARTED:
			/* FALLTHRU */
		case RSM_DRV_PREDEL_COMPLETED:
			/* FALLTHRU */
		case RSM_DRV_POSTDEL_IN_PROGRESS:
			recheck_state = 1;
			cv_wait(&rsm_drv_data.drv_cv, &rsm_drv_data.drv_lock);
			break;
		case RSM_DRV_DR_IN_PROGRESS:
			rsm_drv_data.drv_memdel_cnt--;
			if (rsm_drv_data.drv_memdel_cnt > 0) {
				mutex_exit(&rsm_drv_data.drv_lock);
				DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
				    "rsm_dr_callback_post_del done:\n"));
				return;
			}
			rsm_drv_data.drv_state = RSM_DRV_POSTDEL_IN_PROGRESS;
			break;
		default:
			ASSERT(0);
			return;
			/* break; */
		}
	} while (recheck_state);

	mutex_exit(&rsm_drv_data.drv_lock);

	/* Do all the unquiescing stuff here */
	DBG_PRINTF((category, RSM_DEBUG,
	    "rsm_dr_callback_post_del: unquiesce things now\n"));

	rsm_dr_process_local_segments(RSM_DR_UNQUIESCE);

	/*
	 * now that all local segments have been unquiesced lets inform
	 * the importers
	 */
	rsm_send_resume();

	mutex_enter(&rsm_drv_data.drv_lock);

	rsm_drv_data.drv_state = RSM_DRV_OK;

	cv_broadcast(&rsm_drv_data.drv_cv);

	mutex_exit(&rsm_drv_data.drv_lock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_dr_callback_post_del done\n"));

	return;

}
