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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Domain Services Module
 *
 * The Domain Services (DS) module is responsible for communication
 * with external service entities. It provides an API for clients to
 * publish capabilities and handles the low level communication and
 * version negotiation required to export those capabilities to any
 * interested service entity. Once a capability has been successfully
 * registered with a service entity, the DS module facilitates all
 * data transfers between the service entity and the client providing
 * that particular capability.
 */

#include <sys/modctl.h>
#include <sys/ksynch.h>
#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/cmn_err.h>
#include <sys/note.h>

#include <sys/mach_descrip.h>
#include <sys/mdesc.h>
#include <sys/ldc.h>

#include <sys/ds.h>
#include <sys/ds_impl.h>

/*
 * All DS ports in the system
 *
 * The list of DS ports is read in from the MD when the DS module is
 * initialized and is never modified. This eliminates the need for
 * locking to access the port array itself. Access to the individual
 * ports are synchronized at the port level.
 */
static ds_port_t	ds_ports[DS_MAX_PORTS];
static ds_portset_t	ds_allports;	/* all DS ports in the system */

/*
 * Table of registered services
 *
 * Locking: Accesses to the table of services are synchronized using
 *   a RW lock. The reader lock must be held when looking up service
 *   information in the table. The writer lock must be held when any
 *   service information is being modified.
 */
static struct ds_svcs {
	ds_svc_t	**tbl;		/* the table itself */
	krwlock_t	rwlock;		/* table lock */
	uint_t		maxsvcs;	/* size of the table */
	uint_t		nsvcs;		/* current number of items */
} ds_svcs;

/* initial size of the table */
#define	DS_MAXSVCS_INIT		32

/*
 * Lock Usage
 *
 * ds_svcs.rwlock
 *
 *	See comment just above definition of ds_svcs structure above.
 *
 * ds_port mutex
 *
 *	Protects the elements of each port structure.  Must be acquired for
 *	access to any of the elements.
 *
 * ds_log mutex
 *
 *	See comment above definition of ds_log structure.
 *
 * Multiple lock requirements:
 *
 *	Some code will need to access both a ds_svc_t structure and
 *	a ds_port_t.  In that case, the acquisition order must be:
 *
 *	ds_svcs.rwlock -> port lock
 */

/*
 * Taskq for internal task processing
 */
static taskq_t *ds_taskq;
static boolean_t ds_enabled;	/* enable/disable taskq processing */

/*
 * The actual required number of parallel threads is not expected
 * to be very large. Use the maximum number of CPUs in the system
 * as a rough upper bound.
 */
#define	DS_MAX_TASKQ_THR	NCPU
#define	DS_DISPATCH(fn, arg)	taskq_dispatch(ds_taskq, fn, arg, TQ_SLEEP)

/*
 * Retry count and delay for LDC reads and writes
 */
#define	DS_DEFAULT_RETRIES	10000	/* number of times to retry */
#define	DS_DEFAULT_DELAY	1000	/* usecs to wait between retries */

static int ds_retries = DS_DEFAULT_RETRIES;
static clock_t ds_delay = DS_DEFAULT_DELAY;

/*
 * Supported versions of the DS message protocol
 *
 * The version array must be sorted in order from the highest
 * supported version to the lowest. Support for a particular
 * <major>.<minor> version implies all lower minor versions of
 * that same major version are supported as well.
 */
static ds_ver_t ds_vers[] = { { 1, 0 } };

#define	DS_NUM_VER	(sizeof (ds_vers) / sizeof (ds_vers[0]))

/*
 * Results of checking version array with ds_vers_isvalid()
 */
typedef enum {
	DS_VERS_OK,
	DS_VERS_INCREASING_MAJOR_ERR,
	DS_VERS_INCREASING_MINOR_ERR
} ds_vers_check_t;

/* incoming message handling functions */
typedef void (*ds_msg_handler_t)(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_init_req(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_init_ack(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_init_nack(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_reg_req(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_reg_ack(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_reg_nack(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_unreg_req(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_unreg_ack(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_unreg_nack(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_data(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_nack(ds_port_t *port, caddr_t buf, size_t len);

/*
 * DS Message Handler Dispatch Table
 *
 * A table used to dispatch all incoming messages. This table
 * contains handlers for all the fixed message types, as well as
 * the the messages defined in the 1.0 version of the DS protocol.
 */
static const ds_msg_handler_t ds_msg_handlers[] = {
	ds_handle_init_req,		/* DS_INIT_REQ */
	ds_handle_init_ack,		/* DS_INIT_ACK */
	ds_handle_init_nack,		/* DS_INIT_NACK */
	ds_handle_reg_req,		/* DS_REG_REQ */
	ds_handle_reg_ack,		/* DS_REG_ACK */
	ds_handle_reg_nack,		/* DS_REG_NACK */
	ds_handle_unreg_req,		/* DS_UNREG */
	ds_handle_unreg_ack,		/* DS_UNREG_ACK */
	ds_handle_unreg_nack,		/* DS_UNREG_NACK */
	ds_handle_data,			/* DS_DATA */
	ds_handle_nack			/* DS_NACK */
};

/*
 * DS message log
 *
 * Locking: The message log is protected by a single mutex. This
 *   protects all fields in the log structure itself as well as
 *   everything in the entry structures on both the log and the
 *   free list.
 */
static struct log {
	ds_log_entry_t		*head;		/* head of the log */
	ds_log_entry_t		*freelist;	/* head of the free list */
	size_t			size;		/* size of the log in bytes */
	uint32_t		nentry;		/* number of entries */
	kmutex_t		lock;		/* log lock */
} ds_log;

/* log soft limit */
uint_t ds_log_sz = DS_LOG_DEFAULT_SZ;

/* initial pool of log entry structures */
static ds_log_entry_t ds_log_entry_pool[DS_LOG_NPOOL];

/*
 * Error message features
 */
#define	DS_EBUFSIZE			80

/*
 * Debugging Features
 */
#ifdef DEBUG

#define	DS_DBG_FLAG_LDC			0x1
#define	DS_DBG_FLAG_LOG			0x2
#define	DS_DBG_FLAG_MSG			0x4
#define	DS_DBG_FLAG_ALL			0xf

#define	DS_DBG				if (ds_debug) printf
#define	DS_DBG_LDC			if (ds_debug & DS_DBG_FLAG_LDC) printf
#define	DS_DBG_LOG			if (ds_debug & DS_DBG_FLAG_LOG) printf
#define	DS_DBG_MSG			if (ds_debug & DS_DBG_FLAG_MSG) printf
#define	DS_DUMP_MSG(buf, len)		ds_dump_msg(buf, len)

uint_t ds_debug = 0;
static void ds_dump_msg(void *buf, size_t len);

#else /* DEBUG */

#define	DS_DBG				_NOTE(CONSTCOND) if (0) printf
#define	DS_DBG_LDC			DS_DBG
#define	DS_DBG_LOG			DS_DBG
#define	DS_DUMP_MSG(buf, len)

#endif /* DEBUG */


/* initialization functions */
static void ds_init(void);
static void ds_fini(void);
static int ds_ports_init(void);
static int ds_ports_fini(void);
static int ds_ldc_init(ds_port_t *port);
static int ds_ldc_fini(ds_port_t *port);

/* event processing functions */
static uint_t ds_ldc_reconnect(ds_port_t *port);
static uint_t ds_ldc_cb(uint64_t event, caddr_t arg);
static void ds_dispatch_event(void *arg);
static int ds_recv_msg(ds_port_t *port, caddr_t msgp, size_t *sizep);
static void ds_handle_recv(void *arg);

/* message sending functions */
static int ds_send_msg(ds_port_t *port, caddr_t msg, size_t msglen);
static void ds_send_init_req(ds_port_t *port);
static int ds_send_reg_req(ds_svc_t *svc);
static int ds_send_unreg_req(ds_svc_t *svc);
static void ds_send_unreg_nack(ds_port_t *port, ds_svc_hdl_t bad_hdl);
static void ds_send_data_nack(ds_port_t *port, ds_svc_hdl_t bad_hdl);

/* walker functions */
typedef int (*svc_cb_t)(ds_svc_t *svc, void *arg);
static int ds_walk_svcs(svc_cb_t svc_cb, void *arg);
static int ds_svc_isfree(ds_svc_t *svc, void *arg);
static int ds_svc_ismatch(ds_svc_t *svc, void *arg);
static int ds_svc_free(ds_svc_t *svc, void *arg);
static int ds_svc_register(ds_svc_t *svc, void *arg);
static int ds_svc_unregister(ds_svc_t *svc, void *arg);
static int ds_svc_port_up(ds_svc_t *svc, void *arg);

/* service utilities */
static ds_svc_t *ds_alloc_svc(void);
static void ds_reset_svc(ds_svc_t *svc, ds_port_t *port);
static ds_svc_t *ds_get_svc(ds_svc_hdl_t hdl);

/* port utilities */
static int ds_port_add(md_t *mdp, mde_cookie_t port, mde_cookie_t chan);
static void ds_port_reset(ds_port_t *port);

/* misc utilities */
static ds_vers_check_t ds_vers_isvalid(ds_ver_t *vers, int nvers);
static char *ds_errno_to_str(int errno, char *ebuf);

/* log functions */
static void ds_log_init(void);
static void ds_log_fini(void);
static int ds_log_add_msg(int32_t dest, uint8_t *msg, size_t sz);
static int ds_log_remove(void);
static void ds_log_purge(void *arg);


static struct modlmisc modlmisc = {
	&mod_miscops,
	"Domain Services 1.8"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

int
_init(void)
{
	int	rv;

	/*
	 * Perform all internal setup before initializing
	 * the DS ports. This ensures that events can be
	 * processed as soon as the port comes up.
	 */
	ds_init();

	/* force attach channel nexus */
	(void) i_ddi_attach_hw_nodes("cnex");

	if ((rv = ds_ports_init()) != 0) {
		cmn_err(CE_WARN, "Domain Services initialization failed");
		ds_fini();
		return (rv);
	}

	if ((rv = mod_install(&modlinkage)) != 0) {
		(void) ds_ports_fini();
		ds_fini();
	}

	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		(void) ds_ports_fini();
		ds_fini();
	}

	return (rv);
}

static void
ds_init(void)
{
	int	tblsz;

	/*
	 * Initialize table of registered service classes
	 */
	ds_svcs.maxsvcs = DS_MAXSVCS_INIT;

	tblsz = ds_svcs.maxsvcs * sizeof (ds_svc_t *);
	ds_svcs.tbl = kmem_zalloc(tblsz, KM_SLEEP);

	rw_init(&ds_svcs.rwlock, NULL, RW_DRIVER, NULL);

	ds_svcs.nsvcs = 0;

	/*
	 * Initialize the message log.
	 */
	ds_log_init();

	/*
	 * Create taskq for internal processing threads. This
	 * includes processing incoming request messages and
	 * sending out of band registration messages.
	 */
	ds_taskq = taskq_create("ds_taskq", 1, minclsyspri, 1,
	    DS_MAX_TASKQ_THR, TASKQ_PREPOPULATE | TASKQ_DYNAMIC);

	ds_enabled = B_TRUE;

	/* catch problems with the version array */
	ASSERT(ds_vers_isvalid(ds_vers, DS_NUM_VER) == DS_VERS_OK);
}

static void
ds_fini(void)
{
	int	idx;

	/*
	 * Flip the enabled switch to make sure that no
	 * incoming events get dispatched while things
	 * are being torn down.
	 */
	ds_enabled = B_FALSE;

	/*
	 * Destroy the taskq.
	 */
	taskq_destroy(ds_taskq);

	/*
	 * Destroy the message log.
	 */
	ds_log_fini();

	/*
	 * Deallocate the table of registered services
	 */

	/* clear out all entries */
	rw_enter(&ds_svcs.rwlock, RW_WRITER);
	idx = ds_walk_svcs(ds_svc_free, NULL);
	rw_exit(&ds_svcs.rwlock);

	/* should have gone through the whole table */
	ASSERT(idx == ds_svcs.maxsvcs);

	/* destroy the table itself */
	kmem_free(ds_svcs.tbl, ds_svcs.maxsvcs * sizeof (ds_svc_t *));
	rw_destroy(&ds_svcs.rwlock);
	bzero(&ds_svcs, sizeof (ds_svcs));
}

/*
 * Initialize the list of ports based on the MD.
 */
static int
ds_ports_init(void)
{
	int		idx;
	int		rv = 0;
	md_t		*mdp;
	int		num_nodes;
	int		listsz;
	mde_cookie_t	rootnode;
	mde_cookie_t	dsnode;
	mde_cookie_t	*portp = NULL;
	mde_cookie_t	*chanp = NULL;
	int		nport;
	int		nchan;
	ds_port_t	*port;

	if ((mdp = md_get_handle()) == NULL) {
		cmn_err(CE_WARN, "unable to initialize machine description");
		return (-1);
	}

	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);

	/* allocate temporary storage for MD scans */
	portp = kmem_zalloc(listsz, KM_SLEEP);
	chanp = kmem_zalloc(listsz, KM_SLEEP);

	rootnode = md_root_node(mdp);
	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);

	/*
	 * The root of the search for DS port nodes is the
	 * DS node. Perform a scan to find that node.
	 */
	nport = md_scan_dag(mdp, rootnode, md_find_name(mdp, DS_MD_ROOT_NAME),
	    md_find_name(mdp, "fwd"), portp);

	if (nport <= 0) {
		DS_DBG("No '%s' node in MD\n", DS_MD_ROOT_NAME);
		goto done;
	}

	/* expecting only one DS node */
	if (nport != 1) {
		DS_DBG("expected one '%s' node in the MD, found %d\n",
		    DS_MD_ROOT_NAME, nport);
	}

	dsnode = portp[0];

	/* find all the DS ports in the MD */
	nport = md_scan_dag(mdp, dsnode, md_find_name(mdp, DS_MD_PORT_NAME),
	    md_find_name(mdp, "fwd"), portp);

	if (nport <= 0) {
		DS_DBG("No '%s' nodes in MD\n", DS_MD_PORT_NAME);
		goto done;
	}

	/*
	 * Initialize all the ports found in the MD.
	 */
	for (idx = 0; idx < nport; idx++) {

		/* get the channels for this port */
		nchan = md_scan_dag(mdp, portp[idx],
		    md_find_name(mdp, DS_MD_CHAN_NAME),
		    md_find_name(mdp, "fwd"), chanp);

		if (nchan <= 0) {
			cmn_err(CE_NOTE, "No '%s' node for DS port",
			    DS_MD_CHAN_NAME);
			rv = -1;
			goto done;
		}

		/* expecting only one channel */
		if (nchan != 1) {
			DS_DBG("expected one '%s' node for DS port, found %d\n",
			    DS_MD_CHAN_NAME, nchan);
		}

		if (ds_port_add(mdp, portp[idx], chanp[0]) != 0) {
			rv = -1;
			goto done;
		}
	}

	/*
	 * Initialize the LDC channel for each port.
	 */
	for (idx = 0; idx < DS_MAX_PORTS; idx++) {

		if (!DS_PORT_IN_SET(ds_allports, idx))
			continue;

		port = &ds_ports[idx];

		mutex_enter(&port->lock);

		if (ds_ldc_init(port)) {
			cmn_err(CE_WARN, "ds@%lx: ports_init: failed to "
			    "initialize LDC %ld", port->id, port->ldc.id);
		} else {
			DS_DBG("ds@%lx: ports_init: initialization complete\n",
			    port->id);
		}

		mutex_exit(&port->lock);
	}

	rv = 0;

done:
	if (rv != 0)
		(void) ds_ports_fini();

	kmem_free(portp, listsz);
	kmem_free(chanp, listsz);

	(void) md_fini_handle(mdp);

	return (rv);
}

static int
ds_ports_fini(void)
{
	int		idx;
	ds_port_t	*port;

	/*
	 * Tear down each initialized port.
	 */
	for (idx = 0; idx < DS_MAX_PORTS; idx++) {

		if (!DS_PORT_IN_SET(ds_allports, idx))
			continue;

		port = &ds_ports[idx];

		mutex_enter(&port->lock);

		if (port->state >= DS_PORT_LDC_INIT) {
			/* shut down the LDC for this port */
			(void) ds_ldc_fini(port);
		}

		port->state = DS_PORT_FREE;

		mutex_exit(&port->lock);

		/* clean up the port structure */
		mutex_destroy(&port->lock);
		DS_PORTSET_DEL(ds_allports, idx);
	}

	return (0);
}

static int
ds_ldc_init(ds_port_t *port)
{
	int		rv;
	ldc_attr_t	ldc_attr;
	caddr_t		cb_arg = (caddr_t)port;
	char		ebuf[DS_EBUFSIZE];

	ASSERT(MUTEX_HELD(&port->lock));

	DS_DBG("ds@%lx: ldc_init: ldc_id=%ld\n", port->id, port->ldc.id);

	ldc_attr.devclass = LDC_DEV_GENERIC;
	ldc_attr.instance = 0;
	ldc_attr.mode = LDC_MODE_STREAM;
	ldc_attr.mtu = DS_STREAM_MTU;

	if ((rv = ldc_init(port->ldc.id, &ldc_attr, &port->ldc.hdl)) != 0) {
		cmn_err(CE_WARN, "ds@%lx: ldc_init: %s", port->id,
		    ds_errno_to_str(rv, ebuf));
		goto done;
	}

	/* register the LDC callback */
	if ((rv = ldc_reg_callback(port->ldc.hdl, ds_ldc_cb, cb_arg)) != 0) {
		cmn_err(CE_WARN, "ds@%lx: ldc_reg_callback: %s", port->id,
		    ds_errno_to_str(rv, ebuf));
		goto done;
	}

	if ((rv = ldc_open(port->ldc.hdl)) != 0) {
		cmn_err(CE_WARN, "ds@%lx: ldc_open: %s", port->id,
		    ds_errno_to_str(rv, ebuf));
		goto done;
	}

	(void) ldc_up(port->ldc.hdl);

	(void) ldc_status(port->ldc.hdl, &port->ldc.state);

	DS_DBG_LDC("ds@%lx: ldc_init: initial LDC state 0x%x\n",
	    port->id, port->ldc.state);

	port->state = DS_PORT_LDC_INIT;

	/* if port is up, send init message */
	if (port->ldc.state == LDC_UP) {
		ds_send_init_req(port);
	}

done:
	return (rv);
}

static int
ds_ldc_fini(ds_port_t *port)
{
	int	rv;
	char	ebuf[DS_EBUFSIZE];

	ASSERT(port->state >= DS_PORT_LDC_INIT);

	DS_DBG("ds@%lx: ldc_fini: ldc_id=%ld\n", port->id, port->ldc.id);

	if ((rv = ldc_close(port->ldc.hdl)) != 0) {
		cmn_err(CE_WARN, "ds@%lx: ldc_close: %s", port->id,
		    ds_errno_to_str(rv, ebuf));
		return (rv);
	}

	if ((rv = ldc_unreg_callback(port->ldc.hdl)) != 0) {
		cmn_err(CE_WARN, "ds@%lx: ldc_unreg_callback: %s", port->id,
		    ds_errno_to_str(rv, ebuf));
		return (rv);
	}

	if ((rv = ldc_fini(port->ldc.hdl)) != 0) {
		cmn_err(CE_WARN, "ds@%lx: ldc_fini: %s", port->id,
		    ds_errno_to_str(rv, ebuf));
		return (rv);
	}

	return (rv);
}

static uint_t
ds_ldc_reconnect(ds_port_t *port)
{
	ldc_status_t	ldc_state;
	int		rv;
	ldc_handle_t	ldc_hdl;
	int		read_held;
	int		write_held;
	char		ebuf[DS_EBUFSIZE];

	ldc_hdl = port->ldc.hdl;

	read_held = RW_READ_HELD(&ds_svcs.rwlock);
	write_held = RW_WRITE_HELD(&ds_svcs.rwlock);
	if (read_held) {
		if (!rw_tryupgrade(&ds_svcs.rwlock)) {
			rw_exit(&ds_svcs.rwlock);
			rw_enter(&ds_svcs.rwlock, RW_WRITER);
		}
	} else if (!write_held) {
		rw_enter(&ds_svcs.rwlock, RW_WRITER);
	}

	/* reset the port state */
	ds_port_reset(port);
	(void) ldc_up(ldc_hdl);

	/* read status after bringing LDC up */
	if ((rv = ldc_status(ldc_hdl, &ldc_state)) != 0) {
		cmn_err(CE_NOTE, "ds@%lx: ds_ldc_reconnect: ldc_status: %s",
		    port->id, ds_errno_to_str(rv, ebuf));
	} else {
		port->ldc.state = ldc_state;

		/*
		 * If the channel is already up, initiate
		 * the handshake.
		 */
		if (ldc_state == LDC_UP)
			ds_send_init_req(port);

		DS_DBG_LDC("ds@%lx: ds_ldc_reconnect: succeeded", port->id);
	}

	if (read_held) {
		rw_downgrade(&ds_svcs.rwlock);
	} else if (!write_held) {
		rw_exit(&ds_svcs.rwlock);
	}

	return (rv);
}

/*
 * A DS event consists of a buffer on a port.
 */
typedef struct ds_event {
	ds_port_t	*port;
	char		*buf;
	size_t		buflen;
} ds_event_t;

static uint_t
ds_ldc_cb(uint64_t event, caddr_t arg)
{
	ldc_status_t	ldc_state;
	int		rv;
	ds_port_t	*port = (ds_port_t *)arg;
	ldc_handle_t	ldc_hdl;
	char		ebuf[DS_EBUFSIZE];

	DS_DBG("ds@%lx: LDC event received: 0x%lx\n", port->id, event);

	if (!ds_enabled) {
		DS_DBG("ds@%lx: callback handling is disabled\n", port->id);
		return (LDC_SUCCESS);
	}

	ldc_hdl = port->ldc.hdl;

	/*
	 * Check the LDC event.
	 */
	if (event & (LDC_EVT_DOWN | LDC_EVT_RESET)) {

		ASSERT((event & (LDC_EVT_UP | LDC_EVT_READ)) == 0);

		rw_enter(&ds_svcs.rwlock, RW_WRITER);
		mutex_enter(&port->lock);

		rv = ds_ldc_reconnect(port);

		mutex_exit(&port->lock);
		rw_exit(&ds_svcs.rwlock);

		return (rv);
	}

	mutex_enter(&port->lock);

	if (event & LDC_EVT_UP) {
		if ((rv = ldc_status(ldc_hdl, &ldc_state)) != 0) {
			cmn_err(CE_NOTE, "ds@%lx: ds_ldc_cb: ldc_status: %s\n",
			    port->id, ds_errno_to_str(rv, ebuf));
			goto done;
		}
		port->ldc.state = ldc_state;

		/* initiate the handshake */
		ds_send_init_req(port);
	}

	if (event & LDC_EVT_READ) {
		/* dispatch a thread to handle the read event */
		if (DS_DISPATCH(ds_handle_recv, port) == NULL) {
			cmn_err(CE_WARN, "error initiating event handler");
		}
	}

	if (event & LDC_EVT_WRITE) {
		cmn_err(CE_NOTE, "ds@%lx: LDC write event received, not"
		    " supported\n", port->id);
		goto done;
	}

	/* report any unknown LDC events */
	if (event & ~(LDC_EVT_UP | LDC_EVT_READ)) {
		cmn_err(CE_NOTE, "ds@%lx: Unexpected LDC event received: "
		    "0x%lx\n", port->id, event);
	}

done:
	mutex_exit(&port->lock);

	return (LDC_SUCCESS);
}

/*
 * Attempt to read a specified number of bytes from a particular LDC.
 * Returns zero for success or the return code from the LDC read on
 * failure. The actual number of bytes read from the LDC is returned
 * in the size parameter.
 */
static int
ds_recv_msg(ds_port_t *port, caddr_t msgp, size_t *sizep)
{
	int	rv = 0;
	size_t	bytes_req = *sizep;
	size_t	bytes_left = bytes_req;
	size_t	nbytes;
	int	retry_count = 0;
	char	ebuf[DS_EBUFSIZE];

	*sizep = 0;

	DS_DBG_LDC("ds@%lx: attempting to read %ld bytes\n", port->id,
	    bytes_req);

	while (bytes_left > 0) {

		nbytes = bytes_left;

		if ((rv = ldc_read(port->ldc.hdl, msgp, &nbytes)) != 0) {
			if (rv == ECONNRESET) {
				(void) ds_ldc_reconnect(port);
				break;
			} else if (rv != EAGAIN) {
				cmn_err(CE_NOTE, "ds@%lx: ds_recv_msg: %s",
				    port->id, ds_errno_to_str(rv, ebuf));
				break;
			}
		} else {
			if (nbytes != 0) {
				DS_DBG_LDC("ds@%lx: read %ld bytes, %d "
				    "retries\n", port->id, nbytes, retry_count);

				*sizep += nbytes;
				msgp += nbytes;
				bytes_left -= nbytes;

				/* reset counter on a successful read */
				retry_count = 0;
				continue;
			}

			/*
			 * No data was read. Check if this is the
			 * first attempt. If so, just return since
			 * nothing has been read yet.
			 */
			if (bytes_left == bytes_req) {
				DS_DBG_LDC("ds@%lx: read zero bytes, no data "
				    "available\n", port->id);
				break;
			}
		}

		/*
		 * A retry is necessary because the read returned
		 * EAGAIN, or a zero length read occurred after
		 * reading a partial message.
		 */
		if (retry_count++ >= ds_retries) {
			DS_DBG_LDC("ds@%lx: timed out waiting for "
			    "message\n", port->id);
			break;
		}

		drv_usecwait(ds_delay);
	}

	return (rv);
}

static void
ds_handle_recv(void *arg)
{
	ds_port_t	*port = (ds_port_t *)arg;
	char		*hbuf;
	size_t		msglen;
	size_t		read_size;
	boolean_t	hasdata;
	ds_hdr_t	hdr;
	uint8_t		*msg;
	char		*currp;
	int		rv;
	ldc_handle_t	ldc_hdl;
	ds_event_t	*devent;

	DS_DBG("ds@%lx: ds_handle_recv...\n", port->id);

	ldc_hdl = port->ldc.hdl;

	mutex_enter(&port->lock);

	/*
	 * Read messages from the channel until there are none
	 * pending. Valid messages are dispatched to be handled
	 * by a separate thread while any malformed messages are
	 * dropped.
	 */
	while ((rv = ldc_chkq(ldc_hdl, &hasdata)) == 0 && hasdata) {

		DS_DBG("ds@%lx: reading next message\n", port->id);

		/*
		 * Read in the next message.
		 */
		hbuf = (char *)&hdr;
		bzero(hbuf, DS_HDR_SZ);
		read_size = DS_HDR_SZ;
		currp = hbuf;

		/* read in the message header */
		if ((rv = ds_recv_msg(port, currp, &read_size)) != 0) {
			continue;
		}

		if (read_size < DS_HDR_SZ) {
			/*
			 * A zero length read is a valid signal that
			 * there is no data left on the channel.
			 */
			if (read_size != 0) {
				cmn_err(CE_NOTE, "ds@%lx: invalid message "
				    "length, received %ld bytes, expected %ld",
				    port->id, read_size, DS_HDR_SZ);
			}
			continue;
		}

		/* get payload size and allocate a buffer */
		read_size = ((ds_hdr_t *)hbuf)->payload_len;
		msglen = DS_HDR_SZ + read_size;
		msg = kmem_zalloc(msglen, KM_SLEEP);

		/* move message header into buffer */
		bcopy(hbuf, msg, DS_HDR_SZ);
		currp = (char *)(msg) + DS_HDR_SZ;

		/* read in the message body */
		if ((rv = ds_recv_msg(port, currp, &read_size)) != 0) {
			kmem_free(msg, msglen);
			continue;
		}

		/* validate the size of the message */
		if ((DS_HDR_SZ + read_size) != msglen) {
			cmn_err(CE_NOTE, "ds@%lx: invalid message length, "
			    "received %ld bytes, expected %ld", port->id,
			    (DS_HDR_SZ + read_size), msglen);
			kmem_free(msg, msglen);
			continue;
		}

		DS_DUMP_MSG(msg, msglen);

		/*
		 * Send the message for processing, and store it
		 * in the log. The memory is deallocated only when
		 * the message is removed from the log.
		 */

		devent = kmem_zalloc(sizeof (ds_event_t), KM_SLEEP);
		devent->port = port;
		devent->buf = (char *)msg;
		devent->buflen = msglen;

		/* log the message */
		(void) ds_log_add_msg(DS_LOG_IN(port->id), msg, msglen);

		/* send the message off to get processed in a new thread */
		if (DS_DISPATCH(ds_dispatch_event, devent) == NULL) {
			cmn_err(CE_WARN, "error initiating event handler");
			kmem_free(devent, sizeof (ds_event_t));
			continue;
		}

	}

	if (rv == ECONNRESET) {
		(void) ds_ldc_reconnect(port);
	}

	mutex_exit(&port->lock);
}

static void
ds_dispatch_event(void *arg)
{
	ds_event_t	*event = (ds_event_t *)arg;
	ds_hdr_t	*hdr;
	ds_port_t	*port;

	port = event->port;

	hdr = (ds_hdr_t *)event->buf;

	if (!DS_MSG_TYPE_VALID(hdr->msg_type)) {
		cmn_err(CE_NOTE, "ds@%lx: dispatch_event: invalid msg "
		    "type (%d)", port->id, hdr->msg_type);
		goto done;
	}

	DS_DBG("ds@%lx: dispatch_event: msg_type=%d\n", port->id,
	    hdr->msg_type);

	(*ds_msg_handlers[hdr->msg_type])(port, event->buf, event->buflen);

done:
	kmem_free(event->buf, event->buflen);
	kmem_free(event, sizeof (ds_event_t));
}

/*
 * Version negotiation is always initiated by the guest. Any
 * attempt by a remote party to initiate the handshake gets
 * nack'd with a major number equal to zero. This indicates
 * that no version is supported since an init request is not
 * expected.
 */
static void
ds_handle_init_req(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_hdr_t	*hdr;
	ds_init_nack_t	*nack;
	char		*msg;
	size_t		msglen;
	ds_init_req_t	*req;
	size_t		explen = DS_MSG_LEN(ds_init_req_t);

	req = (ds_init_req_t *)(buf + DS_HDR_SZ);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_NOTE, "ds@%lx: <init_req: invalid message length "
		    "(%ld), expected %ld", port->id, len, explen);
	} else {
		DS_DBG("ds@%lx: <init_req: ver=%d.%d\n", port->id,
		    req->major_vers, req->minor_vers);
	}

	DS_DBG("ds@%lx: init_nack>: major=0\n", port->id);

	msglen = DS_MSG_LEN(ds_init_nack_t);
	msg = kmem_zalloc(msglen, KM_SLEEP);

	hdr = (ds_hdr_t *)msg;
	hdr->msg_type = DS_INIT_NACK;
	hdr->payload_len = sizeof (ds_init_nack_t);

	nack = (ds_init_nack_t *)(msg + DS_HDR_SZ);
	nack->major_vers = 0;

	/* send message */
	mutex_enter(&port->lock);
	(void) ds_send_msg(port, msg, msglen);
	mutex_exit(&port->lock);

	kmem_free(msg, msglen);
}

static void
ds_handle_init_ack(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_init_ack_t	*ack;
	ds_ver_t	*ver;
	size_t		explen = DS_MSG_LEN(ds_init_ack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_NOTE, "ds@%lx: <init_ack: invalid message length "
		    "(%ld), expected %ld", port->id, len, explen);
		return;
	}

	ack = (ds_init_ack_t *)(buf + DS_HDR_SZ);

	mutex_enter(&port->lock);

	if (port->state != DS_PORT_INIT_REQ) {
		cmn_err(CE_NOTE, "ds@%lx: <init_ack: invalid state for msg "
		    "(%d)", port->id, port->state);
		mutex_exit(&port->lock);
		return;
	}

	ver = &(ds_vers[port->ver_idx]);

	DS_DBG("ds@%lx: <init_ack: req=v%d.%d, ack=v%d.%d\n", port->id,
	    ver->major, ver->minor, ver->major, ack->minor_vers);

	/* agreed upon a major version */
	port->ver.major = ver->major;

	/*
	 * If the returned minor version is larger than
	 * the requested minor version, use the lower of
	 * the two, i.e. the requested version.
	 */
	if (ack->minor_vers >= ver->minor) {
		/*
		 * Use the minor version specified in the
		 * original request.
		 */
		port->ver.minor = ver->minor;
	} else {
		/*
		 * Use the lower minor version returned in
		 * the ack. By definition, all lower minor
		 * versions must be supported.
		 */
		port->ver.minor = ack->minor_vers;
	}

	port->state = DS_PORT_READY;

	DS_DBG("ds@%lx: <init_ack: port ready v%d.%d\n", port->id,
	    port->ver.major, port->ver.minor);

	mutex_exit(&port->lock);

	/*
	 * The port came up, so update all the services
	 * with this information. Follow that up with an
	 * attempt to register any service that is not
	 * already registered.
	 */
	rw_enter(&ds_svcs.rwlock, RW_WRITER);

	(void) ds_walk_svcs(ds_svc_port_up, port);
	(void) ds_walk_svcs(ds_svc_register, NULL);

	rw_exit(&ds_svcs.rwlock);
}

static void
ds_handle_init_nack(ds_port_t *port, caddr_t buf, size_t len)
{
	int		idx;
	ds_init_nack_t	*nack;
	ds_ver_t	*ver;
	size_t		explen = DS_MSG_LEN(ds_init_nack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_NOTE, "ds@%lx: <init_nack: invalid message length "
		    "(%ld), expected %ld", port->id, len, explen);
		return;
	}

	nack = (ds_init_nack_t *)(buf + DS_HDR_SZ);

	mutex_enter(&port->lock);

	if (port->state != DS_PORT_INIT_REQ) {
		cmn_err(CE_NOTE, "ds@%lx: <init_nack: invalid state for msg "
		    "(%d)", port->id, port->state);
		mutex_exit(&port->lock);
		return;
	}

	ver = &(ds_vers[port->ver_idx]);

	DS_DBG("ds@%lx: <init_nack: req=v%d.%d, nack=v%d.x\n", port->id,
	    ver->major, ver->minor, nack->major_vers);

	if (nack->major_vers == 0) {
		/* no supported protocol version */
		cmn_err(CE_NOTE, "ds@%lx: <init_nack: DS not supported",
		    port->id);
		mutex_exit(&port->lock);
		return;
	}

	/*
	 * Walk the version list, looking for a major version
	 * that is as close to the requested major version as
	 * possible.
	 */
	for (idx = port->ver_idx; idx < DS_NUM_VER; idx++) {
		if (ds_vers[idx].major <= nack->major_vers) {
			/* found a version to try */
			goto done;
		}
	}

	if (idx == DS_NUM_VER) {
		/* no supported version */
		cmn_err(CE_NOTE, "ds@%lx: <init_nack: DS v%d.x not supported",
		    port->id, nack->major_vers);

		mutex_exit(&port->lock);
		return;
	}

done:
	/* start the handshake again */
	port->ver_idx = idx;
	port->state = DS_PORT_LDC_INIT;

	ds_send_init_req(port);

	mutex_exit(&port->lock);
}

static void
ds_handle_reg_req(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_hdr_t	*hdr;
	ds_reg_req_t	*req;
	ds_reg_nack_t	*nack;
	char		*msg;
	size_t		msglen;
	size_t		explen = DS_MSG_LEN(ds_reg_req_t);

	/* the request information */
	req = (ds_reg_req_t *)(buf + DS_HDR_SZ);

	/* sanity check the incoming message */
	if (len < explen) {
		cmn_err(CE_NOTE, "ds@%lx: <reg_req: invalid message length "
		    "(%ld), expected at least %ld", port->id, len, explen);
	} else {
		DS_DBG("ds@%lx: <reg_req: id='%s', ver=%d.%d, hdl=0x%09lx\n",
		    port->id, req->svc_id, req->major_vers, req->minor_vers,
		    req->svc_handle);
	}

	DS_DBG("ds@%lx: reg_nack>: major=0\n", port->id);

	msglen = DS_MSG_LEN(ds_reg_nack_t);
	msg = kmem_zalloc(msglen, KM_SLEEP);

	hdr = (ds_hdr_t *)msg;
	hdr->msg_type = DS_REG_NACK;
	hdr->payload_len = sizeof (ds_reg_nack_t);

	nack = (ds_reg_nack_t *)(msg + DS_HDR_SZ);
	nack->svc_handle = req->svc_handle;
	nack->result = DS_REG_VER_NACK;
	nack->major_vers = 0;

	/* send message */
	mutex_enter(&port->lock);
	(void) ds_send_msg(port, msg, msglen);
	mutex_exit(&port->lock);

	kmem_free(msg, msglen);
}

static void
ds_handle_reg_ack(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_reg_ack_t	*ack;
	ds_ver_t	*ver;
	ds_ver_t	tmpver;
	ds_svc_t	*svc;
	size_t		explen = DS_MSG_LEN(ds_reg_ack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_NOTE, "ds@%lx: <reg_ack: invalid message length "
		    "(%ld), expected %ld", port->id, len, explen);
		return;
	}

	ack = (ds_reg_ack_t *)(buf + DS_HDR_SZ);

	rw_enter(&ds_svcs.rwlock, RW_WRITER);

	/* lookup appropriate client */
	if ((svc = ds_get_svc(ack->svc_handle)) == NULL) {
		cmn_err(CE_NOTE, "ds@%lx: <reg_ack: invalid handle 0x%lx",
		    port->id, ack->svc_handle);
		goto done;
	}

	/* make sure the message makes sense */
	if (svc->state != DS_SVC_REG_PENDING) {
		cmn_err(CE_NOTE, "ds@%lx: <reg_ack: invalid state for message "
		    "(%d)", port->id, svc->state);
		goto done;
	}

	ver = &(svc->cap.vers[svc->ver_idx]);

	DS_DBG("ds@%lx: <reg_ack: hdl=0x%09lx, ack=v%d.%d\n", port->id,
	    ack->svc_handle, ver->major, ack->minor_vers);

	/* major version has been agreed upon */
	svc->ver.major = ver->major;

	if (ack->minor_vers >= ver->minor) {
		/*
		 * Use the minor version specified in the
		 * original request.
		 */
		svc->ver.minor = ver->minor;
	} else {
		/*
		 * Use the lower minor version returned in
		 * the ack. By definition, all lower minor
		 * versions must be supported.
		 */
		svc->ver.minor = ack->minor_vers;
	}

	svc->state = DS_SVC_ACTIVE;

	DS_DBG("ds@%lx: <reg_ack: %s v%d.%d ready, hdl=0x%09lx\n", port->id,
	    svc->cap.svc_id, svc->ver.major, svc->ver.minor, svc->hdl);

	/* notify the client that registration is complete */
	if (svc->ops.ds_reg_cb) {
		/*
		 * Use a temporary version structure so that
		 * the copy in the svc structure cannot be
		 * modified by the client.
		 */
		tmpver.major = svc->ver.major;
		tmpver.minor = svc->ver.minor;

		(*svc->ops.ds_reg_cb)(svc->ops.cb_arg, &tmpver, svc->hdl);
	}

done:
	rw_exit(&ds_svcs.rwlock);
}

static void
ds_handle_reg_nack(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_reg_nack_t	*nack;
	ds_svc_t	*svc;
	int		idx;
	boolean_t	reset_svc = B_FALSE;
	size_t		explen = DS_MSG_LEN(ds_reg_nack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_NOTE, "ds@%lx: <reg_nack: invalid message length "
		    "(%ld), expected %ld", port->id, len, explen);
		return;
	}

	nack = (ds_reg_nack_t *)(buf + DS_HDR_SZ);

	rw_enter(&ds_svcs.rwlock, RW_WRITER);

	/* lookup appropriate client */
	if ((svc = ds_get_svc(nack->svc_handle)) == NULL) {
		cmn_err(CE_NOTE, "ds@%lx: <reg_nack: invalid handle 0x%lx",
		    port->id, nack->svc_handle);
		goto done;
	}

	/* make sure the message makes sense */
	if (svc->state != DS_SVC_REG_PENDING) {
		cmn_err(CE_NOTE, "ds@%lx: <reg_nack: invalid state for message "
		    "(%d)", port->id, svc->state);
		goto done;
	}

	if (nack->result == DS_REG_DUP) {
		cmn_err(CE_NOTE, "ds@%lx: <reg_nack: duplicate registration "
		    "for %s", port->id, svc->cap.svc_id);
		reset_svc = B_TRUE;
		goto done;
	}

	/*
	 * A major version of zero indicates that the
	 * service is not supported at all.
	 */
	if (nack->major_vers == 0) {
		DS_DBG("ds@%lx: <reg_nack: %s not supported\n", port->id,
		    svc->cap.svc_id);
		reset_svc = B_TRUE;
		goto done;
	}

	DS_DBG("ds@%lx: <reg_nack: hdl=0x%09lx, nack=%d.x\n", port->id,
	    nack->svc_handle, nack->major_vers);

	/*
	 * Walk the version list for the service, looking for
	 * a major version that is as close to the requested
	 * major version as possible.
	 */
	for (idx = svc->ver_idx; idx < svc->cap.nvers; idx++) {
		if (svc->cap.vers[idx].major <= nack->major_vers) {
			/* found a version to try */
			break;
		}
	}

	if (idx == svc->cap.nvers) {
		/* no supported version */
		DS_DBG("ds@%lx: <reg_nack: %s v%d.x not supported\n",
		    port->id, svc->cap.svc_id, nack->major_vers);
		reset_svc = B_TRUE;
		goto done;
	}

	/* start the handshake again */
	svc->state = DS_SVC_INACTIVE;
	svc->ver_idx = idx;

	(void) ds_svc_register(svc, NULL);

done:
	if (reset_svc)
		ds_reset_svc(svc, port);

	rw_exit(&ds_svcs.rwlock);
}

static void
ds_handle_unreg_req(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_hdr_t	*hdr;
	ds_unreg_req_t	*req;
	ds_unreg_ack_t	*ack;
	ds_svc_t	*svc;
	char		*msg;
	size_t		msglen;
	size_t		explen = DS_MSG_LEN(ds_unreg_req_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_NOTE, "ds@%lx: <unreg_req: invalid message length "
		    "(%ld), expected %ld", port->id, len, explen);
		return;
	}

	/* the request information */
	req = (ds_unreg_req_t *)(buf + DS_HDR_SZ);

	rw_enter(&ds_svcs.rwlock, RW_WRITER);

	/* lookup appropriate client */
	if ((svc = ds_get_svc(req->svc_handle)) == NULL) {
		cmn_err(CE_NOTE, "ds@%lx: <unreg_req: invalid handle "
		    "0x%lx", port->id, req->svc_handle);
		ds_send_unreg_nack(port, req->svc_handle);
		goto done;
	}

	/* unregister the service */
	(void) ds_svc_unregister(svc, svc->port);

	DS_DBG("ds@%lx: unreg_ack>: hdl=0x%09lx\n", port->id, req->svc_handle);

	msglen = DS_HDR_SZ + sizeof (ds_unreg_ack_t);
	msg = kmem_zalloc(msglen, KM_SLEEP);

	hdr = (ds_hdr_t *)msg;
	hdr->msg_type = DS_UNREG_ACK;
	hdr->payload_len = sizeof (ds_unreg_ack_t);

	ack = (ds_unreg_ack_t *)(msg + DS_HDR_SZ);
	ack->svc_handle = req->svc_handle;

	/* send message */
	mutex_enter(&port->lock);
	(void) ds_send_msg(port, msg, msglen);
	mutex_exit(&port->lock);

	kmem_free(msg, msglen);

done:
	rw_exit(&ds_svcs.rwlock);
}

static void
ds_handle_unreg_ack(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_unreg_ack_t	*ack;
	size_t		explen = DS_MSG_LEN(ds_unreg_ack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_NOTE, "ds@%lx: <unreg_ack: invalid message length "
		    "(%ld), expected %ld", port->id, len, explen);
		return;
	}

	ack = (ds_unreg_ack_t *)(buf + DS_HDR_SZ);

	DS_DBG("ds@%lx: <unreg_ack: hdl=0x%09lx\n", port->id, ack->svc_handle);

	rw_enter(&ds_svcs.rwlock, RW_WRITER);

	/*
	 * Since the unregister request was initiated locally,
	 * the service structure has already been torn down.
	 * Just perform a sanity check to make sure the message
	 * is appropriate.
	 */
	if (ds_get_svc(ack->svc_handle) != NULL) {
		cmn_err(CE_NOTE, "ds@%lx: <unreg_ack: handle 0x%lx still "
		    "in use", port->id, ack->svc_handle);
	}

	rw_exit(&ds_svcs.rwlock);
}

static void
ds_handle_unreg_nack(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_unreg_nack_t	*nack;
	size_t		explen = DS_MSG_LEN(ds_unreg_nack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_NOTE, "ds@%lx: <unreg_nack: invalid message length "
		    "(%ld), expected %ld", port->id, len, explen);
		return;
	}

	nack = (ds_unreg_nack_t *)(buf + DS_HDR_SZ);

	DS_DBG("ds@%lx: <unreg_nack: hdl=0x%09lx\n", port->id,
	    nack->svc_handle);

	rw_enter(&ds_svcs.rwlock, RW_WRITER);

	/*
	 * Since the unregister request was initiated locally,
	 * the service structure has already been torn down.
	 * Just perform a sanity check to make sure the message
	 * is appropriate.
	 */
	if (ds_get_svc(nack->svc_handle) != NULL) {
		cmn_err(CE_NOTE, "ds@%lx: <unreg_nack: handle 0x%lx still "
		    "in use", port->id, nack->svc_handle);
	}

	rw_exit(&ds_svcs.rwlock);
}

static void
ds_handle_data(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_data_handle_t	*data;
	ds_svc_t		*svc;
	char			*msg;
	int			msgsz;
	int			hdrsz;
	size_t			explen = DS_MSG_LEN(ds_data_handle_t);

	/* sanity check the incoming message */
	if (len < explen) {
		cmn_err(CE_NOTE, "ds@%lx: <data: invalid message length "
		    "(%ld), expected at least %ld", port->id, len, explen);
		return;
	}

	data = (ds_data_handle_t *)(buf + DS_HDR_SZ);

	hdrsz = DS_HDR_SZ + sizeof (ds_data_handle_t);
	msgsz = len - hdrsz;

	/* strip off the header for the client */
	msg = (msgsz) ? (buf + hdrsz) : NULL;

	rw_enter(&ds_svcs.rwlock, RW_READER);

	/* lookup appropriate client */
	if ((svc = ds_get_svc(data->svc_handle)) == NULL) {
		cmn_err(CE_NOTE, "ds@%lx: <data: invalid handle 0x%lx",
		    port->id, data->svc_handle);
		ds_send_data_nack(port, data->svc_handle);
		rw_exit(&ds_svcs.rwlock);
		return;
	}

	rw_exit(&ds_svcs.rwlock);

	DS_DBG("ds@%lx: <data: client=%s hdl=0x%09lx\n", port->id,
	    (svc->cap.svc_id) ? svc->cap.svc_id : "NULL", svc->hdl);

	/* dispatch this message to the client */
	(*svc->ops.ds_data_cb)(svc->ops.cb_arg, msg, msgsz);
}

static void
ds_handle_nack(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_svc_t	*svc;
	ds_data_nack_t	*nack;
	size_t		explen = DS_MSG_LEN(ds_data_nack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_NOTE, "ds@%lx: <data_nack: invalid message length "
		    "(%ld), expected %ld", port->id, len, explen);
		return;
	}

	nack = (ds_data_nack_t *)(buf + DS_HDR_SZ);

	DS_DBG("ds@%lx: data_nack: hdl=0x%09lx, result=0x%lx\n", port->id,
	    nack->svc_handle, nack->result);

	if (nack->result == DS_INV_HDL) {

		rw_enter(&ds_svcs.rwlock, RW_WRITER);

		if ((svc = ds_get_svc(nack->svc_handle)) == NULL) {
			rw_exit(&ds_svcs.rwlock);
			return;
		}

		cmn_err(CE_NOTE, "ds@%lx: <data_nack: handle 0x%lx reported "
		    "as invalid", port->id, nack->svc_handle);

		(void) ds_svc_unregister(svc, svc->port);

		rw_exit(&ds_svcs.rwlock);
	}
}

static int
ds_send_msg(ds_port_t *port, caddr_t msg, size_t msglen)
{
	int	rv;
	caddr_t	currp = msg;
	size_t	amt_left = msglen;
	int	loopcnt = 0;
	char	ebuf[DS_EBUFSIZE];

	DS_DUMP_MSG(msg, msglen);

	(void) ds_log_add_msg(DS_LOG_OUT(port->id), (uint8_t *)msg, msglen);

	/*
	 * ensure that no other messages can be sent on this port in case
	 * the write doesn't get sent with one write to guarantee that the
	 * message doesn't become fragmented.
	 */
	ASSERT(MUTEX_HELD(&port->lock));

	/* send the message */
	do {
		if ((rv = ldc_write(port->ldc.hdl, currp, &msglen)) != 0) {
			if (rv == ECONNRESET) {
				(void) ds_ldc_reconnect(port);
				return (rv);
			} else if ((rv == EWOULDBLOCK) &&
			    (loopcnt++ < ds_retries)) {
				drv_usecwait(ds_delay);
			} else {
				cmn_err(CE_WARN, "ds@%lx: ldc_write: %s",
				    port->id, ds_errno_to_str(rv, ebuf));
				return (rv);
			}
		} else {
			amt_left -= msglen;
			currp += msglen;
			msglen = amt_left;
			loopcnt = 0;
		}
	} while (amt_left > 0);

	return (rv);
}

static void
ds_send_init_req(ds_port_t *port)
{
	ds_hdr_t	*hdr;
	ds_init_req_t	*init_req;
	size_t		msglen;
	ds_ver_t	*vers = &ds_vers[port->ver_idx];

	ASSERT(MUTEX_HELD(&port->lock));

	if (port->state != DS_PORT_LDC_INIT) {
		cmn_err(CE_NOTE, "ds@%lx: init_req>: invalid port state (%d)",
		    port->id, port->state);
		return;
	}

	DS_DBG("ds@%lx: init_req>: req=v%d.%d\n", port->id, vers->major,
	    vers->minor);

	msglen = DS_HDR_SZ + sizeof (ds_init_req_t);
	hdr = kmem_zalloc(msglen, KM_SLEEP);

	hdr->msg_type = DS_INIT_REQ;
	hdr->payload_len = sizeof (ds_init_req_t);

	init_req = (ds_init_req_t *)((caddr_t)hdr + DS_HDR_SZ);
	init_req->major_vers = vers->major;
	init_req->minor_vers = vers->minor;

	/* send the message */
	if (ds_send_msg(port, (caddr_t)hdr, msglen) == 0) {
		port->state = DS_PORT_INIT_REQ;
	}

	kmem_free(hdr, msglen);
}

static int
ds_send_reg_req(ds_svc_t *svc)
{
	int		rv = 0;
	ds_port_t	*port = svc->port;
	ds_ver_t	*ver;
	ds_hdr_t	*hdr;
	caddr_t		msg;
	size_t		msglen;
	ds_reg_req_t	*req;
	size_t		idlen;

	/* assumes some checking has already occurred */
	ASSERT(svc->state == DS_SVC_INACTIVE);

	mutex_enter(&port->lock);

	/* check on the LDC to Zeus */
	if (port->ldc.state != LDC_UP) {
		/* can not send message */
		DS_DBG("ds@%lx: reg_req>: channel %ld is not up\n", port->id,
		    port->ldc.id);
		mutex_exit(&port->lock);
		return (-1);
	}

	/* make sure port is ready */
	if (port->state != DS_PORT_READY) {
		/* can not send message */
		DS_DBG("ds@%lx: reg_req>: port is not ready\n", port->id);
		mutex_exit(&port->lock);
		return (-1);
	}

	mutex_exit(&port->lock);

	/* allocate the message buffer */
	idlen = strlen(svc->cap.svc_id);
	msglen = DS_HDR_SZ + sizeof (ds_reg_req_t) + idlen;
	msg = kmem_zalloc(msglen, KM_SLEEP);

	/* copy in the header data */
	hdr = (ds_hdr_t *)msg;
	hdr->msg_type = DS_REG_REQ;
	hdr->payload_len = sizeof (ds_reg_req_t) + idlen;

	req = (ds_reg_req_t *)(msg + DS_HDR_SZ);
	req->svc_handle = svc->hdl;
	ver = &(svc->cap.vers[svc->ver_idx]);
	req->major_vers = ver->major;
	req->minor_vers = ver->minor;

	/* copy in the service id */
	bcopy(svc->cap.svc_id, req->svc_id, idlen + 1);

	/* send the message */
	DS_DBG("ds@%lx: reg_req>: id='%s', ver=%d.%d, hdl=0x%09lx\n", port->id,
	    svc->cap.svc_id, ver->major, ver->minor, svc->hdl);

	mutex_enter(&port->lock);
	if (ds_send_msg(port, msg, msglen) != 0) {
		rv = -1;
	} else {
		svc->state = DS_SVC_REG_PENDING;
	}
	mutex_exit(&port->lock);

	kmem_free(msg, msglen);
	return (rv);
}

static int
ds_send_unreg_req(ds_svc_t *svc)
{
	int		rv = 0;
	caddr_t		msg;
	size_t		msglen;
	ds_hdr_t	*hdr;
	ds_unreg_req_t	*req;
	ds_port_t	*port = svc->port;

	if (port == NULL) {
		DS_DBG("send_unreg_req: service '%s' not associated with "
		    "a port\n", svc->cap.svc_id);
		return (-1);
	}

	mutex_enter(&port->lock);

	/* check on the LDC to Zeus */
	if (port->ldc.state != LDC_UP) {
		/* can not send message */
		cmn_err(CE_NOTE, "ds@%lx: unreg_req>: channel %ld is not up\n",
		    port->id, port->ldc.id);
		mutex_exit(&port->lock);
		return (-1);
	}

	/* make sure port is ready */
	if (port->state != DS_PORT_READY) {
		/* can not send message */
		cmn_err(CE_NOTE, "ds@%lx: unreg_req>: port is not ready\n",
		    port->id);
		mutex_exit(&port->lock);
		return (-1);
	}

	mutex_exit(&port->lock);

	msglen = DS_HDR_SZ + sizeof (ds_unreg_req_t);
	msg = kmem_zalloc(msglen, KM_SLEEP);

	/* copy in the header data */
	hdr = (ds_hdr_t *)msg;
	hdr->msg_type = DS_UNREG;
	hdr->payload_len = sizeof (ds_unreg_req_t);

	req = (ds_unreg_req_t *)(msg + DS_HDR_SZ);
	req->svc_handle = svc->hdl;

	/* send the message */
	DS_DBG("ds@%lx: unreg_req>: id='%s', hdl=0x%09lx\n", port->id,
	    (svc->cap.svc_id) ? svc->cap.svc_id : "NULL", svc->hdl);

	mutex_enter(&port->lock);

	if (ds_send_msg(port, msg, msglen) != 0)
		rv = -1;

	mutex_exit(&port->lock);

	kmem_free(msg, msglen);
	return (rv);
}

static void
ds_send_unreg_nack(ds_port_t *port, ds_svc_hdl_t bad_hdl)
{
	caddr_t		msg;
	size_t		msglen;
	ds_hdr_t	*hdr;
	ds_unreg_nack_t	*nack;

	mutex_enter(&port->lock);

	/* check on the LDC to Zeus */
	if (port->ldc.state != LDC_UP) {
		/* can not send message */
		cmn_err(CE_NOTE, "ds@%lx: unreg_nack>: channel %ld is not up",
		    port->id, port->ldc.id);
		mutex_exit(&port->lock);
		return;
	}

	/* make sure port is ready */
	if (port->state != DS_PORT_READY) {
		/* can not send message */
		cmn_err(CE_NOTE, "ds@%lx: unreg_nack>: port is not ready",
		    port->id);
		mutex_exit(&port->lock);
		return;
	}

	mutex_exit(&port->lock);

	msglen = DS_HDR_SZ + sizeof (ds_unreg_nack_t);
	msg = kmem_zalloc(msglen, KM_SLEEP);

	/* copy in the header data */
	hdr = (ds_hdr_t *)msg;
	hdr->msg_type = DS_UNREG_NACK;
	hdr->payload_len = sizeof (ds_unreg_nack_t);

	nack = (ds_unreg_nack_t *)(msg + DS_HDR_SZ);
	nack->svc_handle = bad_hdl;

	/* send the message */
	DS_DBG("ds@%lx: unreg_nack>: hdl=0x%09lx\n", port->id, bad_hdl);

	mutex_enter(&port->lock);
	(void) ds_send_msg(port, msg, msglen);
	mutex_exit(&port->lock);

	kmem_free(msg, msglen);
}

static void
ds_send_data_nack(ds_port_t *port, ds_svc_hdl_t bad_hdl)
{
	caddr_t		msg;
	size_t		msglen;
	ds_hdr_t	*hdr;
	ds_data_nack_t	*nack;

	mutex_enter(&port->lock);

	/* check on the LDC to Zeus */
	if (port->ldc.state != LDC_UP) {
		/* can not send message */
		cmn_err(CE_NOTE, "ds@%lx: data_nack>: channel %ld is not up",
		    port->id, port->ldc.id);
		mutex_exit(&port->lock);
		return;
	}

	/* make sure port is ready */
	if (port->state != DS_PORT_READY) {
		/* can not send message */
		cmn_err(CE_NOTE, "ds@%lx: data_nack>: port is not ready",
		    port->id);
		mutex_exit(&port->lock);
		return;
	}

	mutex_exit(&port->lock);

	msglen = DS_HDR_SZ + sizeof (ds_data_nack_t);
	msg = kmem_zalloc(msglen, KM_SLEEP);

	/* copy in the header data */
	hdr = (ds_hdr_t *)msg;
	hdr->msg_type = DS_NACK;
	hdr->payload_len = sizeof (ds_data_nack_t);

	nack = (ds_data_nack_t *)(msg + DS_HDR_SZ);
	nack->svc_handle = bad_hdl;
	nack->result = DS_INV_HDL;

	/* send the message */
	DS_DBG("ds@%lx: data_nack>: hdl=0x%09lx\n", port->id, bad_hdl);

	mutex_enter(&port->lock);
	(void) ds_send_msg(port, msg, msglen);
	mutex_exit(&port->lock);

	kmem_free(msg, msglen);
}

#ifdef DEBUG

#define	BYTESPERLINE	8
#define	LINEWIDTH	((BYTESPERLINE * 3) + (BYTESPERLINE + 2) + 1)
#define	ASCIIOFFSET	((BYTESPERLINE * 3) + 2)
#define	ISPRINT(c)	((c >= ' ') && (c <= '~'))

/*
 * Output a buffer formatted with a set number of bytes on
 * each line. Append each line with the ASCII equivalent of
 * each byte if it falls within the printable ASCII range,
 * and '.' otherwise.
 */
static void
ds_dump_msg(void *vbuf, size_t len)
{
	int	i, j;
	char	*curr;
	char	*aoff;
	char	line[LINEWIDTH];
	uint8_t	*buf = vbuf;

	/* abort if not debugging ldc */
	if (!(ds_debug & DS_DBG_FLAG_MSG)) {
		return;
	}

	/* walk the buffer one line at a time */
	for (i = 0; i < len; i += BYTESPERLINE) {

		bzero(line, LINEWIDTH);

		curr = line;
		aoff = line + ASCIIOFFSET;

		/*
		 * Walk the bytes in the current line, storing
		 * the hex value for the byte as well as the
		 * ASCII representation in a temporary buffer.
		 * All ASCII values are placed at the end of
		 * the line.
		 */
		for (j = 0; (j < BYTESPERLINE) && ((i + j) < len); j++) {
			(void) sprintf(curr, " %02x", buf[i + j]);
			*aoff = (ISPRINT(buf[i + j])) ? buf[i + j] : '.';
			curr += 3;
			aoff++;
		}

		/*
		 * Fill in to the start of the ASCII translation
		 * with spaces. This will only be necessary if
		 * this is the last line and there are not enough
		 * bytes to fill the whole line.
		 */
		while (curr != (line + ASCIIOFFSET))
			*curr++ = ' ';

		DS_DBG_MSG("%s\n", line);
	}
}
#endif /* DEBUG */


/*
 * Walk the table of registered services, executing the specified
 * callback function for each service. A non-zero return value from
 * the callback is used to terminate the walk, not to indicate an
 * error. Returns the index of the last service visited.
 */
static int
ds_walk_svcs(svc_cb_t svc_cb, void *arg)
{
	int		idx;
	ds_svc_t	*svc;

	ASSERT(RW_WRITE_HELD(&ds_svcs.rwlock));

	/* walk every table entry */
	for (idx = 0; idx < ds_svcs.maxsvcs; idx++) {

		svc = ds_svcs.tbl[idx];

		/* execute the callback */
		if ((*svc_cb)(svc, arg) != 0)
			break;
	}

	return (idx);
}

static int
ds_svc_isfree(ds_svc_t *svc, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	/*
	 * Looking for a free service. This may be a NULL entry
	 * in the table, or an unused structure that could be
	 * reused.
	 */

	if (DS_SVC_ISFREE(svc)) {
		/* yes, it is free */
		return (1);
	}

	/* not a candidate */
	return (0);
}

static int
ds_svc_ismatch(ds_svc_t *svc, void *arg)
{
	if (DS_SVC_ISFREE(svc)) {
		return (0);
	}

	if (strcmp(svc->cap.svc_id, arg) == 0) {
		/* found a match */
		return (1);
	}

	return (0);
}

static int
ds_svc_free(ds_svc_t *svc, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	if (svc == NULL) {
		return (0);
	}

	if (svc->cap.svc_id) {
		kmem_free(svc->cap.svc_id, strlen(svc->cap.svc_id) + 1);
		svc->cap.svc_id = NULL;
	}

	if (svc->cap.vers) {
		kmem_free(svc->cap.vers, svc->cap.nvers * sizeof (ds_ver_t));
		svc->cap.vers = NULL;
	}

	kmem_free(svc, sizeof (ds_svc_t));

	return (0);
}

static int
ds_svc_register(ds_svc_t *svc, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	int	idx;

	ASSERT(RW_WRITE_HELD(&ds_svcs.rwlock));

	/* check the state of the service */
	if (DS_SVC_ISFREE(svc) || (svc->state != DS_SVC_INACTIVE))
		return (0);

	/* check if there are any ports to try */
	if (DS_PORTSET_ISNULL(svc->avail))
		return (0);

	/*
	 * Attempt to register the service. Start with the lowest
	 * numbered port and continue until a registration message
	 * is sent successfully, or there are no ports left to try.
	 */
	for (idx = 0; idx < DS_MAX_PORTS; idx++) {

		/*
		 * If the port is not in the available list,
		 * it is not a candidate for registration.
		 */
		if (!DS_PORT_IN_SET(svc->avail, idx)) {
			continue;
		}

		svc->port = &ds_ports[idx];
		if (ds_send_reg_req(svc) == 0) {
			/* register sent successfully */
			break;
		}

		/* reset the service to try the next port */
		ds_reset_svc(svc, svc->port);
	}

	return (0);
}

static int
ds_svc_unregister(ds_svc_t *svc, void *arg)
{
	ds_port_t *port = (ds_port_t *)arg;

	ASSERT(RW_WRITE_HELD(&ds_svcs.rwlock));

	if (DS_SVC_ISFREE(svc)) {
		return (0);
	}

	/* make sure the service is using this port */
	if (svc->port != port) {
		return (0);
	}

	DS_DBG("ds@%lx: svc_unreg: id='%s', ver=%d.%d, hdl=0x%09lx\n", port->id,
	    svc->cap.svc_id, svc->ver.major, svc->ver.minor, svc->hdl);

	/* reset the service structure */
	ds_reset_svc(svc, port);

	/* increment the count in the handle to prevent reuse */
	svc->hdl = DS_ALLOC_HDL(DS_HDL2IDX(svc->hdl), DS_HDL2COUNT(svc->hdl));

	/* call the client unregister callback */
	if (svc->ops.ds_unreg_cb)
		(*svc->ops.ds_unreg_cb)(svc->ops.cb_arg);

	/* try to initiate a new registration */
	(void) ds_svc_register(svc, NULL);

	return (0);
}

static int
ds_svc_port_up(ds_svc_t *svc, void *arg)
{
	ds_port_t *port = (ds_port_t *)arg;

	if (DS_SVC_ISFREE(svc)) {
		/* nothing to do */
		return (0);
	}

	DS_PORTSET_ADD(svc->avail, port->id);

	return (0);
}

static ds_svc_t *
ds_alloc_svc(void)
{
	int		idx;
	uint_t		newmaxsvcs;
	ds_svc_t	**newtbl;
	ds_svc_t	*newsvc;

	ASSERT(RW_WRITE_HELD(&ds_svcs.rwlock));

	idx = ds_walk_svcs(ds_svc_isfree, NULL);

	if (idx != ds_svcs.maxsvcs) {
		goto found;
	}

	/*
	 * There was no free space in the table. Grow
	 * the table to double its current size.
	 */
	newmaxsvcs = ds_svcs.maxsvcs * 2;
	newtbl = kmem_zalloc(newmaxsvcs * sizeof (ds_svc_t *), KM_SLEEP);

	/* copy old table data to the new table */
	for (idx = 0; idx < ds_svcs.maxsvcs; idx++) {
		newtbl[idx] = ds_svcs.tbl[idx];
	}

	/* clean up the old table */
	kmem_free(ds_svcs.tbl, ds_svcs.maxsvcs * sizeof (ds_svc_t *));
	ds_svcs.tbl = newtbl;
	ds_svcs.maxsvcs = newmaxsvcs;

	/* search for a free space again */
	idx = ds_walk_svcs(ds_svc_isfree, NULL);

	/* the table is locked so should find a free slot */
	ASSERT(idx != ds_svcs.maxsvcs);

found:
	/* allocate a new svc structure if necessary */
	if ((newsvc = ds_svcs.tbl[idx]) == NULL) {
		/* allocate a new service */
		newsvc = kmem_zalloc(sizeof (ds_svc_t), KM_SLEEP);
		ds_svcs.tbl[idx] = newsvc;
	}

	/* fill in the handle */
	newsvc->hdl = DS_ALLOC_HDL(idx, DS_HDL2COUNT(newsvc->hdl));

	return (newsvc);
}

static void
ds_reset_svc(ds_svc_t *svc, ds_port_t *port)
{
	ASSERT(RW_WRITE_HELD(&ds_svcs.rwlock));

	svc->state = DS_SVC_INACTIVE;
	svc->ver_idx = 0;
	svc->ver.major = 0;
	svc->ver.minor = 0;
	svc->port = NULL;
	DS_PORTSET_DEL(svc->avail, port->id);
}

static ds_svc_t *
ds_get_svc(ds_svc_hdl_t hdl)
{
	int		idx;
	ds_svc_t	*svc;

	ASSERT(RW_LOCK_HELD(&ds_svcs.rwlock));

	if (hdl == DS_INVALID_HDL)
		return (NULL);

	idx = DS_HDL2IDX(hdl);

	/* check if index is out of bounds */
	if ((idx < 0) || (idx >= ds_svcs.maxsvcs))
		return (NULL);

	svc = ds_svcs.tbl[idx];

	/* check for a valid service */
	if (DS_SVC_ISFREE(svc))
		return (NULL);

	/* make sure the handle is an exact match */
	if (svc->hdl != hdl)
		return (NULL);

	return (svc);
}

static int
ds_port_add(md_t *mdp, mde_cookie_t port, mde_cookie_t chan)
{
	ds_port_t	*newport;
	uint64_t	port_id;
	uint64_t	ldc_id;

	/* get the ID for this port */
	if (md_get_prop_val(mdp, port, "id", &port_id) != 0) {
		cmn_err(CE_NOTE, "ds_port_add: port 'id' property not found");
		return (-1);
	}

	/* sanity check the port id */
	if (port_id > DS_MAX_PORT_ID) {
		cmn_err(CE_WARN, "ds_port_add: port ID %ld out of range",
		    port_id);
		return (-1);
	}

	DS_DBG("ds_port_add: adding port ds@%ld\n", port_id);

	/* get the channel ID for this port */
	if (md_get_prop_val(mdp, chan, "id", &ldc_id) != 0) {
		cmn_err(CE_NOTE, "ds@%lx: add_port: no channel 'id' property",
		    port_id);
		return (-1);
	}

	/* get the port structure from the array of ports */
	newport = &ds_ports[port_id];

	/* check for a duplicate port in the MD */
	if (newport->state != DS_PORT_FREE) {
		cmn_err(CE_NOTE, "ds@%lx: add_port: port already exists",
		    port_id);
		return (-1);
	}

	/* initialize the port lock */
	mutex_init(&newport->lock, NULL, MUTEX_DRIVER, NULL);

	/* initialize the port */
	newport->id = port_id;
	newport->state = DS_PORT_INIT;
	newport->ldc.id = ldc_id;

	/* add the port to the set of all ports */
	DS_PORTSET_ADD(ds_allports, port_id);

	return (0);
}

static void
ds_port_reset(ds_port_t *port)
{
	ASSERT(RW_WRITE_HELD(&ds_svcs.rwlock));
	ASSERT(MUTEX_HELD(&port->lock));

	/* connection went down, mark everything inactive */
	(void) ds_walk_svcs(ds_svc_unregister, port);

	port->ver_idx = 0;
	port->ver.major = 0;
	port->ver.minor = 0;
	port->state = DS_PORT_LDC_INIT;
}

/*
 * Verify that a version array is sorted as expected for the
 * version negotiation to work correctly.
 */
static ds_vers_check_t
ds_vers_isvalid(ds_ver_t *vers, int nvers)
{
	uint16_t	curr_major;
	uint16_t	curr_minor;
	int		idx;

	curr_major = vers[0].major;
	curr_minor = vers[0].minor;

	/*
	 * Walk the version array, verifying correct ordering.
	 * The array must be sorted from highest supported
	 * version to lowest supported version.
	 */
	for (idx = 0; idx < nvers; idx++) {
		if (vers[idx].major > curr_major) {
			DS_DBG("vers_isvalid: version array has increasing "
			    "major versions\n");
			return (DS_VERS_INCREASING_MAJOR_ERR);
		}

		if (vers[idx].major < curr_major) {
			curr_major = vers[idx].major;
			curr_minor = vers[idx].minor;
			continue;
		}

		if (vers[idx].minor > curr_minor) {
			DS_DBG("vers_isvalid: version array has increasing "
			    "minor versions\n");
			return (DS_VERS_INCREASING_MINOR_ERR);
		}

		curr_minor = vers[idx].minor;
	}

	return (DS_VERS_OK);
}

/*
 * Logging Support
 */
static void
ds_log_init(void)
{
	ds_log_entry_t	*new;

	/* initialize global lock */
	mutex_init(&ds_log.lock, NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&ds_log.lock);

	/* initialize the log */
	ds_log.head = NULL;
	ds_log.size = 0;
	ds_log.nentry = 0;

	/* initialize the free list */
	for (new = ds_log_entry_pool; new < DS_LOG_POOL_END; new++) {
		new->next = ds_log.freelist;
		ds_log.freelist = new;
	}

	mutex_exit(&ds_log.lock);

	DS_DBG_LOG("ds_log initialized: size=%d bytes, limit=%d bytes, "
	    "ninit=%ld\n", ds_log_sz, DS_LOG_LIMIT, DS_LOG_NPOOL);
}

static void
ds_log_fini(void)
{
	ds_log_entry_t	*next;

	mutex_enter(&ds_log.lock);

	/* clear out the log */
	while (ds_log.nentry > 0)
		(void) ds_log_remove();

	/*
	 * Now all the entries are on the free list.
	 * Clear out the free list, deallocating any
	 * entry that was dynamically allocated.
	 */
	while (ds_log.freelist != NULL) {
		next = ds_log.freelist->next;

		if (!DS_IS_POOL_ENTRY(ds_log.freelist)) {
			kmem_free(ds_log.freelist, sizeof (ds_log_entry_t));
		}

		ds_log.freelist = next;
	}

	mutex_exit(&ds_log.lock);

	mutex_destroy(&ds_log.lock);
}

static ds_log_entry_t *
ds_log_entry_alloc(void)
{
	ds_log_entry_t	*new = NULL;

	ASSERT(MUTEX_HELD(&ds_log.lock));

	if (ds_log.freelist != NULL) {
		new = ds_log.freelist;
		ds_log.freelist = ds_log.freelist->next;
	}

	if (new == NULL) {
		/* free list was empty */
		new = kmem_zalloc(sizeof (ds_log_entry_t), KM_SLEEP);
	}

	ASSERT(new);

	return (new);
}

static void
ds_log_entry_free(ds_log_entry_t *entry)
{
	ASSERT(MUTEX_HELD(&ds_log.lock));

	if (entry == NULL)
		return;

	if (entry->data != NULL) {
		kmem_free(entry->data, entry->datasz);
		entry->data = NULL;
	}

	/* place entry on the free list */
	entry->next = ds_log.freelist;
	ds_log.freelist = entry;
}

/*
 * Add a message to the end of the log
 */
static int
ds_log_add(ds_log_entry_t *new)
{
	ASSERT(MUTEX_HELD(&ds_log.lock));

	if (ds_log.head == NULL) {

		new->prev = new;
		new->next = new;

		ds_log.head = new;
	} else {
		ds_log_entry_t	*head = ds_log.head;
		ds_log_entry_t	*tail = ds_log.head->prev;

		new->next = head;
		new->prev = tail;
		tail->next = new;
		head->prev = new;
	}

	/* increase the log size, including the metadata size */
	ds_log.size += DS_LOG_ENTRY_SZ(new);
	ds_log.nentry++;

	DS_DBG_LOG("ds_log: added %ld data bytes, %ld total bytes\n",
	    new->datasz, DS_LOG_ENTRY_SZ(new));

	return (0);
}

/*
 * Remove an entry from the head of the log
 */
static int
ds_log_remove(void)
{
	ds_log_entry_t	*head;

	ASSERT(MUTEX_HELD(&ds_log.lock));

	head = ds_log.head;

	/* empty list */
	if (head == NULL)
		return (0);

	if (head->next == ds_log.head) {
		/* one element list */
		ds_log.head = NULL;
	} else {
		head->next->prev = head->prev;
		head->prev->next = head->next;
		ds_log.head = head->next;
	}

	DS_DBG_LOG("ds_log: removed %ld data bytes, %ld total bytes\n",
	    head->datasz, DS_LOG_ENTRY_SZ(head));

	ds_log.size -= DS_LOG_ENTRY_SZ(head);
	ds_log.nentry--;

	ds_log_entry_free(head);

	return (0);
}

/*
 * Replace the data in the entry at the front of the list with then
 * new data. This has the effect of removing the oldest entry and
 * adding the new entry.
 */
static int
ds_log_replace(int32_t dest, uint8_t *msg, size_t sz)
{
	ds_log_entry_t	*head;

	ASSERT(MUTEX_HELD(&ds_log.lock));

	head = ds_log.head;

	DS_DBG_LOG("ds_log: replaced %ld data bytes (%ld total) with %ld data "
	    "bytes (%ld total)\n", head->datasz, DS_LOG_ENTRY_SZ(head),
	    sz, sz + sizeof (ds_log_entry_t));

	ds_log.size -= DS_LOG_ENTRY_SZ(head);

	kmem_free(head->data, head->datasz);

	head->data = msg;
	head->datasz = sz;
	head->timestamp = ddi_get_time();
	head->dest = dest;

	ds_log.size += DS_LOG_ENTRY_SZ(head);

	ds_log.head = head->next;

	return (0);
}

static void
ds_log_purge(void *arg)
{
	_NOTE(ARGUNUSED(arg))

	mutex_enter(&ds_log.lock);

	DS_DBG_LOG("ds_log: purging oldest log entries\n");

	while ((ds_log.nentry) && (ds_log.size >= ds_log_sz)) {
		(void) ds_log_remove();
	}

	mutex_exit(&ds_log.lock);
}

static int
ds_log_add_msg(int32_t dest, uint8_t *msg, size_t sz)
{
	int	rv = 0;
	void	*data;

	mutex_enter(&ds_log.lock);

	/* allocate a local copy of the data */
	data = kmem_alloc(sz, KM_SLEEP);
	bcopy(msg, data, sz);

	/* check if the log is larger than the soft limit */
	if ((ds_log.nentry) && ((ds_log.size + sz) >= ds_log_sz)) {
		/*
		 * The log is larger than the soft limit.
		 * Swap the oldest entry for the newest.
		 */
		DS_DBG_LOG("ds_log: replacing oldest entry with new entry\n");
		(void) ds_log_replace(dest, data, sz);
	} else {
		/*
		 * Still have headroom under the soft limit.
		 * Add the new entry to the log.
		 */
		ds_log_entry_t	*new;

		new = ds_log_entry_alloc();

		/* fill in message data */
		new->data = data;
		new->datasz = sz;
		new->timestamp = ddi_get_time();
		new->dest = dest;

		rv = ds_log_add(new);
	}

	/* check if the log is larger than the hard limit */
	if ((ds_log.nentry > 1) && (ds_log.size >= DS_LOG_LIMIT)) {
		/*
		 * Wakeup the thread to remove entries
		 * from the log until it is smaller than
		 * the soft limit.
		 */
		DS_DBG_LOG("ds_log: log exceeded %d bytes, scheduling a "
		    "purge...\n", DS_LOG_LIMIT);

		if (DS_DISPATCH(ds_log_purge, NULL) == NULL) {
			cmn_err(CE_NOTE, "ds_log: purge thread failed to "
			    "start");
		}
	}

	mutex_exit(&ds_log.lock);

	return (rv);
}

/*
 * Client Interface
 */

int
ds_cap_init(ds_capability_t *cap, ds_clnt_ops_t *ops)
{
	int		idx;
	ds_vers_check_t	status;
	ds_svc_t	*svc;

	/* sanity check the args */
	if ((cap == NULL) || (ops == NULL)) {
		cmn_err(CE_NOTE, "ds_cap_init: invalid arguments");
		return (EINVAL);
	}

	/* sanity check the capability specifier */
	if ((cap->svc_id == NULL) || (cap->vers == NULL) || (cap->nvers == 0)) {
		cmn_err(CE_NOTE, "ds_cap_init: invalid capability specifier");
		return (EINVAL);
	}

	/* sanity check the version array */
	if ((status = ds_vers_isvalid(cap->vers, cap->nvers)) != DS_VERS_OK) {
		cmn_err(CE_NOTE, "ds_cap_init: invalid capability "
		    "version array for %s service: %s", cap->svc_id,
		    (status == DS_VERS_INCREASING_MAJOR_ERR) ?
		    "increasing major versions" :
		    "increasing minor versions");
		return (EINVAL);
	}

	/* data and register callbacks are required */
	if ((ops->ds_data_cb == NULL) || (ops->ds_reg_cb == NULL)) {
		cmn_err(CE_NOTE, "ds_cap_init: invalid ops specifier for "
		    "%s service", cap->svc_id);
		return (EINVAL);
	}

	DS_DBG("ds_cap_init: svc_id='%s', data_cb=0x%lx, cb_arg=0x%lx\n",
	    cap->svc_id, (uint64_t)ops->ds_data_cb, (uint64_t)ops->cb_arg);

	rw_enter(&ds_svcs.rwlock, RW_WRITER);

	/* check if the service is already registered */
	idx = ds_walk_svcs(ds_svc_ismatch, cap->svc_id);
	if (idx != ds_svcs.maxsvcs) {
		/* already registered */
		cmn_err(CE_NOTE, "service '%s' already registered",
		    cap->svc_id);
		rw_exit(&ds_svcs.rwlock);
		return (EALREADY);
	}

	svc = ds_alloc_svc();

	/* copy over all the client information */
	bcopy(cap, &svc->cap, sizeof (ds_capability_t));

	/* make a copy of the service name */
	svc->cap.svc_id = kmem_zalloc(strlen(cap->svc_id) + 1, KM_SLEEP);
	(void) strncpy(svc->cap.svc_id, cap->svc_id, strlen(cap->svc_id));

	/* make a copy of the version array */
	svc->cap.vers = kmem_zalloc(cap->nvers * sizeof (ds_ver_t), KM_SLEEP);
	bcopy(cap->vers, svc->cap.vers, cap->nvers * sizeof (ds_ver_t));

	/* copy the client ops vector */
	bcopy(ops, &svc->ops, sizeof (ds_clnt_ops_t));

	svc->state = DS_SVC_INACTIVE;
	svc->ver_idx = 0;
	DS_PORTSET_DUP(svc->avail, ds_allports);

	ds_svcs.nsvcs++;

	/* attempt to register the service */
	(void) ds_svc_register(svc, NULL);

	rw_exit(&ds_svcs.rwlock);

	DS_DBG("ds_cap_init: service '%s' assigned handle 0x%09lx\n",
	    svc->cap.svc_id, svc->hdl);

	return (0);
}

int
ds_cap_fini(ds_capability_t *cap)
{
	int		idx;
	ds_svc_t	*svc;
	ds_svc_hdl_t	tmp_hdl;

	rw_enter(&ds_svcs.rwlock, RW_WRITER);

	/* make sure the service is registered */
	idx = ds_walk_svcs(ds_svc_ismatch, cap->svc_id);
	if (idx == ds_svcs.maxsvcs) {
		/* service is not registered */
		cmn_err(CE_NOTE, "ds_cap_fini: unknown service '%s'",
		    cap->svc_id);
		rw_exit(&ds_svcs.rwlock);
		return (EINVAL);
	}

	svc = ds_svcs.tbl[idx];

	DS_DBG("ds_cap_fini: svcid='%s', hdl=0x%09lx\n", svc->cap.svc_id,
	    svc->hdl);

	/*
	 * Attempt to send an unregister notification. Even
	 * if sending the message fails, the local unregister
	 * request must be honored, since this indicates that
	 * the client will no longer handle incoming requests.
	 */
	(void) ds_send_unreg_req(svc);

	/*
	 * Clear out the structure, but do not deallocate the
	 * memory. It can be reused for the next registration.
	 */
	kmem_free(svc->cap.svc_id, strlen(svc->cap.svc_id) + 1);
	kmem_free(svc->cap.vers, svc->cap.nvers * sizeof (ds_ver_t));

	/* save the handle to prevent reuse */
	tmp_hdl = svc->hdl;
	bzero(svc, sizeof (ds_svc_t));

	/* initialize for next use */
	svc->hdl = tmp_hdl;
	svc->state = DS_SVC_FREE;

	ds_svcs.nsvcs--;

	rw_exit(&ds_svcs.rwlock);

	return (0);
}

int
ds_cap_send(ds_svc_hdl_t hdl, void *buf, size_t len)
{
	int		rv;
	ds_hdr_t	*hdr;
	caddr_t		msg;
	size_t		msglen;
	size_t		hdrlen;
	caddr_t		payload;
	ds_svc_t	*svc;
	ds_port_t	*port;
	ds_data_handle_t *data;

	rw_enter(&ds_svcs.rwlock, RW_READER);

	if ((hdl == DS_INVALID_HDL) || (svc = ds_get_svc(hdl)) == NULL) {
		cmn_err(CE_NOTE, "ds_cap_send: invalid handle 0x%09lx", hdl);
		rw_exit(&ds_svcs.rwlock);
		return (EINVAL);
	}

	if ((port = svc->port) == NULL) {
		cmn_err(CE_NOTE, "ds_cap_send: service '%s' not associated "
		    "with a port", svc->cap.svc_id);
		rw_exit(&ds_svcs.rwlock);
		return (ECONNRESET);
	}

	mutex_enter(&port->lock);

	/* check that the LDC channel is ready */
	if (port->ldc.state != LDC_UP) {
		cmn_err(CE_NOTE, "ds_cap_send: LDC channel is not up");
		mutex_exit(&port->lock);
		rw_exit(&ds_svcs.rwlock);
		return (ECONNRESET);
	}


	if (svc->state != DS_SVC_ACTIVE) {
		/* channel is up, but svc is not registered */
		cmn_err(CE_NOTE, "ds_cap_send: invalid service state 0x%x",
		    svc->state);
		mutex_exit(&port->lock);
		rw_exit(&ds_svcs.rwlock);
		return (EINVAL);
	}

	hdrlen = DS_HDR_SZ + sizeof (ds_data_handle_t);

	msg = kmem_zalloc(len + hdrlen, KM_SLEEP);
	hdr = (ds_hdr_t *)msg;
	payload = msg + hdrlen;
	msglen = len + hdrlen;

	hdr->payload_len = len + sizeof (ds_data_handle_t);
	hdr->msg_type = DS_DATA;

	data = (ds_data_handle_t *)(msg + DS_HDR_SZ);
	data->svc_handle = hdl;

	if ((buf != NULL) && (len != 0)) {
		bcopy(buf, payload, len);
	}

	DS_DBG("ds@%lx: data>: hdl=0x%09lx, len=%ld, payload_len=%d\n",
	    port->id, svc->hdl, msglen, hdr->payload_len);

	if ((rv = ds_send_msg(port, msg, msglen)) != 0) {
		rv = (rv == EIO) ? ECONNRESET : rv;
	}

	kmem_free(msg, msglen);

	mutex_exit(&port->lock);
	rw_exit(&ds_svcs.rwlock);

	return (rv);
}

/*
 * Specific errno's that are used by ds.c and ldc.c
 */
static struct {
	int errno;
	char *estr;
} ds_errno_to_str_tab[] = {
	EIO,		"I/O error",
	EAGAIN,		"Resource temporarily unavailable",
	ENOMEM,		"Not enough space",
	EACCES,		"Permission denied",
	EFAULT,		"Bad address",
	EBUSY,		"Device busy",
	EINVAL,		"Invalid argument",
	ENOSPC,		"No space left on device",
	ECHRNG,		"Channel number out of range",
	ENOTSUP,	"Operation not supported",
	EMSGSIZE,	"Message too long",
	EADDRINUSE,	"Address already in use",
	ECONNRESET,	"Connection reset by peer",
	ENOBUFS,	"No buffer space available",
	ECONNREFUSED,	"Connection refused",
	EALREADY,	"Operation already in progress",
	0,
};

static char *
ds_errno_to_str(int errno, char *ebuf)
{
	int i, en;

	for (i = 0; (en = ds_errno_to_str_tab[i].errno) != 0; i++) {
		if (en == errno) {
			(void) strcpy(ebuf, ds_errno_to_str_tab[i].estr);
			return (ebuf);
		}
	}

	(void) sprintf(ebuf, "errno (%d)", errno);
	return (ebuf);
}
