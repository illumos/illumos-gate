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


/*
 * Domain Services Module System Specific Code.
 *
 * The Domain Services (DS) module is responsible for communication
 * with external service entities. It provides a kernel API for clients to
 * publish capabilities and handles the low level communication and
 * version negotiation required to export those capabilities to any
 * interested service entity. Once a capability has been successfully
 * registered with a service entity, the DS module facilitates all
 * data transfers between the service entity and the client providing
 * that particular capability.
 *
 * This file provides the system interfaces that are required for
 * the ds.c module, which is common to both Solaris and VBSC (linux).
 */

#include <sys/modctl.h>
#include <sys/ksynch.h>
#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/cmn_err.h>
#include <sys/note.h>
#include <sys/mach_descrip.h>
#include <sys/mdesc.h>
#include <sys/mdeg.h>
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
ds_port_t	ds_ports[DS_MAX_PORTS];
ds_portset_t	ds_allports;	/* all DS ports in the system */

/*
 * Table of registered services
 *
 * Locking: Accesses to the table of services are synchronized using
 *   a mutex lock. The reader lock must be held when looking up service
 *   information in the table. The writer lock must be held when any
 *   service information is being modified.
 */
ds_svcs_t	ds_svcs;

/*
 * Taskq for internal task processing
 */
static taskq_t *ds_taskq;

/*
 * The actual required number of parallel threads is not expected
 * to be very large. Use the maximum number of CPUs in the system
 * as a rough upper bound.
 */
#define	DS_MAX_TASKQ_THR	NCPU
#define	DS_DISPATCH(fn, arg)	taskq_dispatch(ds_taskq, fn, arg, TQ_SLEEP)

ds_domain_hdl_t ds_my_domain_hdl = DS_DHDL_INVALID;
char *ds_my_domain_name = NULL;

#ifdef DEBUG
/*
 * Debug Flag
 */
uint_t ds_debug = 0;
#endif	/* DEBUG */

/* initialization functions */
static void ds_init(void);
static void ds_fini(void);
static int ds_ports_init(void);
static int ds_ports_fini(void);

/* port utilities */
static int ds_port_add(md_t *mdp, mde_cookie_t port, mde_cookie_t chan);

/* log functions */
static void ds_log_init(void);
static void ds_log_fini(void);
static int ds_log_remove(void);
static void ds_log_purge(void *arg);

static struct modlmisc modlmisc = {
	&mod_miscops,
	"Domain Services 1.9"
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
ds_fini(void)
{
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
	mutex_enter(&ds_svcs.lock);
	(void) ds_walk_svcs(ds_svc_free, NULL);
	mutex_exit(&ds_svcs.lock);

	/* destroy the table itself */
	DS_FREE(ds_svcs.tbl, ds_svcs.maxsvcs * sizeof (ds_svc_t *));
	mutex_destroy(&ds_svcs.lock);
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

	if ((mdp = md_get_handle()) == NULL) {
		cmn_err(CE_WARN, "Unable to initialize machine description");
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
		DS_DBG_MD(CE_NOTE, "No '%s' node in MD", DS_MD_ROOT_NAME);
		goto done;
	}

	/* expecting only one DS node */
	if (nport != 1) {
		DS_DBG_MD(CE_NOTE, "Expected one '%s' node in the MD, found %d",
		    DS_MD_ROOT_NAME, nport);
	}

	dsnode = portp[0];

	/* find all the DS ports in the MD */
	nport = md_scan_dag(mdp, dsnode, md_find_name(mdp, DS_MD_PORT_NAME),
	    md_find_name(mdp, "fwd"), portp);

	if (nport <= 0) {
		DS_DBG_MD(CE_NOTE, "No '%s' nodes in MD", DS_MD_PORT_NAME);
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
			cmn_err(CE_WARN, "No '%s' node for DS port",
			    DS_MD_CHAN_NAME);
			rv = -1;
			goto done;
		}

		/* expecting only one channel */
		if (nchan != 1) {
			DS_DBG_MD(CE_NOTE, "Expected one '%s' node for DS "
			    " port,  found %d", DS_MD_CHAN_NAME, nchan);
		}

		if (ds_port_add(mdp, portp[idx], chanp[0]) != 0) {
			rv = -1;
			goto done;
		}
	}

done:
	if (rv != 0)
		(void) ds_ports_fini();

	DS_FREE(portp, listsz);
	DS_FREE(chanp, listsz);

	(void) md_fini_handle(mdp);

	return (rv);
}

static int
ds_ports_fini(void)
{
	int		idx;

	/*
	 * Tear down each initialized port.
	 */
	for (idx = 0; idx < DS_MAX_PORTS; idx++) {
		if (DS_PORT_IN_SET(ds_allports, idx)) {
			(void) ds_remove_port(idx, 1);
		}
	}

	return (0);
}

static int
ds_port_add(md_t *mdp, mde_cookie_t port, mde_cookie_t chan)
{
	uint64_t	port_id;
	uint64_t	ldc_id;
	uint8_t		*ldcidsp;
	int		len;

	/* get the ID for this port */
	if (md_get_prop_val(mdp, port, "id", &port_id) != 0) {
		cmn_err(CE_WARN, "%s: port 'id' property not found",
		    __func__);
		return (-1);
	}

	/* sanity check the port id */
	if (port_id > DS_MAX_PORT_ID) {
		cmn_err(CE_WARN, "%s: port ID %ld out of range",
		    __func__, port_id);
		return (-1);
	}

	/* get the channel ID for this port */
	if (md_get_prop_val(mdp, chan, "id", &ldc_id) != 0) {
		cmn_err(CE_WARN, "ds@%lx: %s: no channel 'id' property",
		    port_id, __func__);
		return (-1);
	}

	if (ds_add_port(port_id, ldc_id, DS_DHDL_INVALID, NULL, 1) != 0)
		return (-1);

	/*
	 * Identify the SP Port.  The SP port is the only one with
	 * the "ldc-ids" property, and is only on the primary domain.
	 */
	if (ds_sp_port_id == DS_PORTID_INVALID &&
	    md_get_prop_data(mdp, port, "ldc-ids", &ldcidsp, &len) == 0) {
		ds_sp_port_id = port_id;
	}

	return (0);
}

void
ds_set_my_dom_hdl_name(ds_domain_hdl_t dhdl, char *name)
{
	ds_my_domain_hdl = dhdl;
	if (ds_my_domain_name != NULL) {
		DS_FREE(ds_my_domain_name, strlen(ds_my_domain_name)+1);
		ds_my_domain_name = NULL;
	}
	if (name != NULL) {
		ds_my_domain_name = ds_strdup(name);
	}
}

void
ds_init()
{
	ds_common_init();

	/*
	 * Create taskq for internal processing threads. This
	 * includes processing incoming request messages and
	 * sending out of band registration messages.
	 */
	ds_taskq = taskq_create("ds_taskq", 1, minclsyspri, 1,
	    DS_MAX_TASKQ_THR, TASKQ_PREPOPULATE | TASKQ_DYNAMIC);

	/*
	 * Initialize the message log.
	 */
	ds_log_init();
}

int
ds_sys_dispatch_func(void (func)(void *), void *arg)
{
	return (DS_DISPATCH(func, arg) == TASKQID_INVALID);
}

/*
 * Drain event queue, if necessary.
 */
void
ds_sys_drain_events(ds_port_t *port)
{
	_NOTE(ARGUNUSED(port))
}

/*
 * System specific port initalization.
 */
void
ds_sys_port_init(ds_port_t *port)
{
	_NOTE(ARGUNUSED(port))
}

/*
 * System specific port teardown.
 */
void
ds_sys_port_fini(ds_port_t *port)
{
	_NOTE(ARGUNUSED(port))
}

/*
 * System specific LDC channel initialization.
 */
void
ds_sys_ldc_init(ds_port_t *port)
{
	int	rv;
	char	ebuf[DS_EBUFSIZE];

	ASSERT(MUTEX_HELD(&port->lock));

	if ((rv = ldc_open(port->ldc.hdl)) != 0) {
		cmn_err(CE_WARN, "ds@%lx: %s: ldc_open: %s",
		    PORTID(port), __func__, ds_errno_to_str(rv, ebuf));
		return;
	}

	(void) ldc_up(port->ldc.hdl);

	(void) ldc_status(port->ldc.hdl, &port->ldc.state);

	DS_DBG_LDC(CE_NOTE, "ds@%lx: %s: initial LDC state 0x%x",
	    PORTID(port), __func__, port->ldc.state);

	port->state = DS_PORT_LDC_INIT;
}

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

	DS_DBG_LOG(CE_NOTE, "ds_log initialized: size=%d bytes, "
	    " limit=%d bytes, ninit=%ld", ds_log_sz, DS_LOG_LIMIT,
	    DS_LOG_NPOOL);
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

	DS_DBG_LOG(CE_NOTE, "ds_log: added %ld data bytes, %ld total bytes",
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

	DS_DBG_LOG(CE_NOTE, "ds_log: removed %ld data bytes, %ld total bytes",
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

	DS_DBG_LOG(CE_NOTE, "ds_log: replaced %ld data bytes (%ld total) with "
	    " %ld data bytes (%ld total)", head->datasz,
	    DS_LOG_ENTRY_SZ(head), sz, sz + sizeof (ds_log_entry_t));

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

	DS_DBG_LOG(CE_NOTE, "ds_log: purging oldest log entries");

	while ((ds_log.nentry) && (ds_log.size >= ds_log_sz)) {
		(void) ds_log_remove();
	}

	mutex_exit(&ds_log.lock);
}

int
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
		DS_DBG_LOG(CE_NOTE, "%s: replacing oldest entry with new entry",
		    __func__);
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
		DS_DBG_LOG(CE_NOTE, "%s: log exceeded %d bytes, scheduling"
		    " a purge...", __func__, DS_LOG_LIMIT);

		if (DS_DISPATCH(ds_log_purge, NULL) == TASKQID_INVALID) {
			cmn_err(CE_NOTE, "%s: purge thread failed to start",
			    __func__);
		}
	}

	mutex_exit(&ds_log.lock);

	return (rv);
}

int
ds_add_port(uint64_t port_id, uint64_t ldc_id, ds_domain_hdl_t dhdl,
    char *dom_name, int verbose)
{
	ds_port_t	*newport;

	/* sanity check the port id */
	if (port_id > DS_MAX_PORT_ID) {
		cmn_err(CE_WARN, "%s: port ID %ld out of range",
		    __func__, port_id);
		return (EINVAL);
	}

	DS_DBG_MD(CE_NOTE, "%s: adding port ds@%ld, LDC: 0x%lx, dhdl: 0x%lx "
	    "name: '%s'", __func__, port_id, ldc_id, dhdl,
	    dom_name == NULL ? "NULL" : dom_name);

	/* get the port structure from the array of ports */
	newport = &ds_ports[port_id];

	/* check for a duplicate port in the MD */
	if (newport->state != DS_PORT_FREE) {
		if (verbose) {
			cmn_err(CE_WARN, "ds@%lx: %s: port already exists",
			    port_id, __func__);
		}
		if (newport->domain_hdl == DS_DHDL_INVALID) {
			newport->domain_hdl = dhdl;
		}
		if (newport->domain_name == NULL && dom_name != NULL) {
			newport->domain_name = ds_strdup(dom_name);
		}
		return (EBUSY);
	}

	/* initialize the port */
	newport->id = port_id;
	newport->ldc.id = ldc_id;
	newport->domain_hdl = dhdl;
	if (dom_name) {
		newport->domain_name = ds_strdup(dom_name);
	} else
		newport->domain_name = NULL;
	ds_port_common_init(newport);

	return (0);
}

/* ARGSUSED */
int
ds_remove_port(uint64_t port_id, int is_fini)
{
	ds_port_t *port;

	if (port_id >= DS_MAX_PORTS || !DS_PORT_IN_SET(ds_allports, port_id)) {
		DS_DBG_MD(CE_NOTE, "%s: invalid port %lx", __func__,
		    port_id);
		return (EINVAL);
	}

	DS_DBG_MD(CE_NOTE, "%s: removing port ds@%lx", __func__, port_id);

	port = &ds_ports[port_id];

	mutex_enter(&port->lock);

	if (port->state >= DS_PORT_LDC_INIT) {
		/* shut down the LDC for this port */
		(void) ds_ldc_fini(port);
	}

	if (port->domain_name) {
		DS_FREE(port->domain_name, strlen(port->domain_name) + 1);
		port->domain_name = NULL;
	}
	port->domain_hdl = DS_DHDL_INVALID;

	/* clean up the port structure */
	ds_port_common_fini(port);

	mutex_exit(&port->lock);
	return (0);
}

/*
 * Interface for ds_service_lookup in lds driver.
 */
int
ds_service_lookup(ds_svc_hdl_t hdl, char **servicep, uint_t *is_client)
{
	ds_svc_t	*svc;

	mutex_enter(&ds_svcs.lock);
	if ((svc = ds_get_svc(hdl)) == NULL) {
		mutex_exit(&ds_svcs.lock);
		DS_DBG(CE_NOTE, "%s: handle 0x%llx not found", __func__,
		    (u_longlong_t)hdl);
		return (ENXIO);
	}
	*servicep = svc->cap.svc_id;
	*is_client = svc->flags & DSSF_ISCLIENT;
	mutex_exit(&ds_svcs.lock);
	return (0);
}

/*
 * Interface for ds_domain_lookup in lds driver.
 */
int
ds_domain_lookup(ds_svc_hdl_t hdl, ds_domain_hdl_t *dhdlp)
{
	ds_svc_t	*svc;

	mutex_enter(&ds_svcs.lock);
	if ((svc = ds_get_svc(hdl)) == NULL) {
		mutex_exit(&ds_svcs.lock);
		DS_DBG(CE_NOTE, "%s: handle 0x%llx not found", __func__,
		    (u_longlong_t)hdl);
		return (ENXIO);
	}
	if (svc->port == NULL)
		*dhdlp = ds_my_domain_hdl;
	else
		*dhdlp = svc->port->domain_hdl;
	mutex_exit(&ds_svcs.lock);
	return (0);
}

/*
 * Interface for ds_hdl_isready in lds driver.
 */
int
ds_hdl_isready(ds_svc_hdl_t hdl, uint_t *is_ready)
{
	ds_svc_t	*svc;

	mutex_enter(&ds_svcs.lock);
	if ((svc = ds_get_svc(hdl)) == NULL) {
		mutex_exit(&ds_svcs.lock);
		DS_DBG(CE_NOTE, "%s: handle 0x%llx not found", __func__,
		    (u_longlong_t)hdl);
		return (ENXIO);
	}
	*is_ready = (svc->state == DS_SVC_ACTIVE);
	mutex_exit(&ds_svcs.lock);
	return (0);
}

/*
 * Interface for ds_dom_name_to_hdl in lds driver.
 */
int
ds_dom_name_to_hdl(char *domain_name, ds_domain_hdl_t *dhdlp)
{
	int i;
	ds_port_t *port;

	if (domain_name == NULL) {
		return (ENXIO);
	}
	if (ds_my_domain_name != NULL &&
	    strcmp(ds_my_domain_name, domain_name) == 0) {
		*dhdlp = ds_my_domain_hdl;
		return (0);
	}
	for (i = 0, port = ds_ports; i < DS_MAX_PORTS; i++, port++) {
		if (port->state != DS_PORT_FREE &&
		    port->domain_name != NULL &&
		    strcmp(port->domain_name, domain_name) == 0) {
			*dhdlp = port->domain_hdl;
			return (0);
		}
	}
	return (ENXIO);
}

/*
 * Interface for ds_dom_hdl_to_name in lds driver.
 */
int
ds_dom_hdl_to_name(ds_domain_hdl_t dhdl, char **domain_namep)
{
	int i;
	ds_port_t *port;

	if (dhdl == ds_my_domain_hdl) {
		if (ds_my_domain_name != NULL) {
			*domain_namep = ds_my_domain_name;
			return (0);
		}
		return (ENXIO);
	}
	for (i = 0, port = ds_ports; i < DS_MAX_PORTS; i++, port++) {
		if (port->state != DS_PORT_FREE &&
		    port->domain_hdl == dhdl) {
			*domain_namep = port->domain_name;
			return (0);
		}
	}
	return (ENXIO);
}

/*
 * Unregister all handles related to device open instance.
 */
void
ds_unreg_all(int instance)
{
	int		idx;
	ds_svc_t	*svc;
	ds_svc_hdl_t	hdl;

	DS_DBG_USR(CE_NOTE, "%s: entered", __func__);

	/* walk every table entry */
	mutex_enter(&ds_svcs.lock);
	for (idx = 0; idx < ds_svcs.maxsvcs; idx++) {
		svc = ds_svcs.tbl[idx];
		if (DS_SVC_ISFREE(svc))
			continue;
		if ((svc->flags & DSSF_ISUSER) != 0 && svc->drvi == instance) {
			hdl = svc->hdl;
			mutex_exit(&ds_svcs.lock);
			(void) ds_unreg_hdl(hdl);
			mutex_enter(&ds_svcs.lock);
			DS_DBG_USR(CE_NOTE, "%s: ds_unreg_hdl(0x%llx):",
			    __func__, (u_longlong_t)hdl);
		}
	}
	mutex_exit(&ds_svcs.lock);
}

/*
 * Special callbacks to allow the lds module revision-independent access
 * to service structure data in the callback routines.  This assumes that
 * we put a special "cookie" in the arg argument passed to those
 * routines (for now, a ptr to the svc structure, but it could be a svc
 * table index or something that we could get back to the svc table entry).
 */
void
ds_cbarg_get_hdl(ds_cb_arg_t arg, ds_svc_hdl_t *hdlp)
{
	ds_svc_t *svc = (ds_svc_t *)arg;

	ASSERT(svc == (ds_svc_t *)svc->ops.cb_arg);
	*hdlp = svc->hdl;
}

void
ds_cbarg_get_flags(ds_cb_arg_t arg, uint32_t *flagsp)
{
	ds_svc_t *svc = (ds_svc_t *)arg;

	ASSERT(svc == (ds_svc_t *)svc->ops.cb_arg);
	*flagsp = svc->flags;
}

void
ds_cbarg_get_drv_info(ds_cb_arg_t arg, int *drvip)
{
	ds_svc_t *svc = (ds_svc_t *)arg;

	ASSERT(svc == (ds_svc_t *)svc->ops.cb_arg);
	*drvip = svc->drvi;
}

void
ds_cbarg_get_drv_per_svc_ptr(ds_cb_arg_t arg, void **dpspp)
{
	ds_svc_t *svc = (ds_svc_t *)arg;

	ASSERT(svc == (ds_svc_t *)svc->ops.cb_arg);
	*dpspp = svc->drv_psp;
}

void
ds_cbarg_get_domain(ds_cb_arg_t arg, ds_domain_hdl_t *dhdlp)
{
	ds_svc_t *svc = (ds_svc_t *)arg;

	ASSERT(svc == (ds_svc_t *)svc->ops.cb_arg);
	if (svc->port == NULL)
		*dhdlp = ds_my_domain_hdl;
	else
		*dhdlp = svc->port->domain_hdl;
}

void
ds_cbarg_get_service_id(ds_cb_arg_t arg, char **servicep)
{
	ds_svc_t *svc = (ds_svc_t *)arg;

	ASSERT(svc == (ds_svc_t *)svc->ops.cb_arg);
	*servicep = svc->cap.svc_id;
}

void
ds_cbarg_set_drv_per_svc_ptr(ds_cb_arg_t arg, void *dpsp)
{
	ds_svc_t *svc = (ds_svc_t *)arg;

	ASSERT(svc == (ds_svc_t *)svc->ops.cb_arg);
	svc->drv_psp = dpsp;
}

void
ds_cbarg_set_cookie(ds_svc_t *svc)
{
	svc->ops.cb_arg = (ds_cb_arg_t)(svc);
}

int
ds_hdl_get_cbarg(ds_svc_hdl_t hdl, ds_cb_arg_t *cbargp)
{
	ds_svc_t *svc;

	mutex_enter(&ds_svcs.lock);
	if ((svc = ds_get_svc(hdl)) != NULL &&
	    (svc->flags & DSSF_ISUSER) != 0) {
		ASSERT(svc == (ds_svc_t *)svc->ops.cb_arg);
		*cbargp = svc->ops.cb_arg;
		mutex_exit(&ds_svcs.lock);
		return (0);
	}
	mutex_exit(&ds_svcs.lock);
	return (ENXIO);
}

int
ds_is_my_hdl(ds_svc_hdl_t hdl, int instance)
{
	ds_svc_t *svc;
	int rv = 0;

	mutex_enter(&ds_svcs.lock);
	if ((svc = ds_get_svc(hdl)) == NULL) {
		DS_DBG_USR(CE_NOTE, "%s: invalid hdl: 0x%llx\n", __func__,
		    (u_longlong_t)hdl);
		rv = ENXIO;
	} else if (instance == DS_INVALID_INSTANCE) {
		if ((svc->flags & DSSF_ISUSER) != 0) {
			DS_DBG_USR(CE_NOTE, "%s: unowned hdl: 0x%llx\n",
			    __func__, (u_longlong_t)hdl);
			rv = EACCES;
		}
	} else if ((svc->flags & DSSF_ISUSER) == 0 || svc->drvi != instance) {
		DS_DBG_USR(CE_NOTE, "%s: unowned hdl: 0x%llx\n", __func__,
		    (u_longlong_t)hdl);
		rv = EACCES;
	}
	mutex_exit(&ds_svcs.lock);
	return (rv);
}
