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
 * hot-plug services module
 */

#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/disp.h>
#include <sys/stat.h>
#include <sys/hotplug/hpcsvc.h>
#include <sys/callb.h>

/*
 * debug macros:
 */
#if defined(DEBUG)

int hpcsvc_debug = 0;

static void debug(char *, uintptr_t, uintptr_t, uintptr_t,
	uintptr_t, uintptr_t);

#define	DEBUG0(fmt)	\
	debug(fmt, 0, 0, 0, 0, 0);
#define	DEBUG1(fmt, a1)	\
	debug(fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	DEBUG2(fmt, a1, a2)	\
	debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	DEBUG3(fmt, a1, a2, a3)	\
	debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), (uintptr_t)(a3), 0, 0);
#else
#define	DEBUG0(fmt)
#define	DEBUG1(fmt, a1)
#define	DEBUG2(fmt, a1, a2)
#define	DEBUG3(fmt, a1, a2, a3)
#endif

/*
 * Definitions for the bus node registration list:
 *
 * The hot-plug service module maintains a linked list of items
 * representing the device bus nodes that have been registered via
 * hpc_nexus_register, or identified as candidates for registration
 * by the bus argument to hpc_slot_register.
 *
 * The head of the linked listed is stored in hpc_bus_list_head. Insertions
 * and removals from the list should be locked with mutex hpc_bus_mutex.
 *
 * Items in the list are allocated/freed with the macros hpc_alloc_bus_entry()
 * and hpc_free_bus_entry().
 *
 * Each item in the list contains the following fields:
 *
 *	bus_dip - pointer to devinfo node of the registering bus
 *
 *	bus_name - device path name of the bus (ie /pci@1f,4000)
 *
 *	bus_callback - bus nexus driver callback function registered
 *		with the bus
 *
 *	bus_registered - a boolean value which is true if the bus has
 *		been registered with hpc_nexus_register, false otherwise
 *
 *	bus_mutex - mutex lock to be held while updating this list entry
 *
 *	bus_slot_list - linked list of the slots registered for this
 *		bus node (see slot list details below)
 *
 *	bus_thread - kernel thread for running slot event handlers for
 *		slots associated with this bus
 *
 *	bus_thread_cv - condition variable for synchronization between
 *		the service routines and the thread for running slot
 *		event handlers
 *
 *	bus_thread_exit - a boolean value used to instruct the thread
 *		for invoking the slot event handlers to exit
 *
 *	bus_slot_event_list_head - the head of the linked list of instances
 *		of slot event handlers to be run
 *		handlers to be invoked
 *
 *	bus_next - pointer to next list entry
 */

typedef struct hpc_bus_entry hpc_bus_entry_t;
typedef struct hpc_slot_entry hpc_slot_entry_t;
typedef struct hpc_event_entry hpc_event_entry_t;

struct hpc_event_entry {
	hpc_slot_entry_t *slotp;
	int event;
	hpc_event_entry_t *next;
};

#define	hpc_alloc_event_entry()	\
	(hpc_event_entry_t *)kmem_zalloc(sizeof (hpc_event_entry_t), KM_SLEEP)

#define	hpc_free_event_entry(a)	\
	kmem_free((a), sizeof (hpc_event_entry_t))

struct hpc_bus_entry {
	dev_info_t *bus_dip;
	char bus_name[MAXPATHLEN + 1];
	boolean_t bus_registered;
	kmutex_t bus_mutex;
	int (* bus_callback)(dev_info_t *dip, hpc_slot_t hdl,
		hpc_slot_info_t *slot_info, int slot_state);
	hpc_slot_entry_t *bus_slot_list;
	kthread_t *bus_thread;
	kcondvar_t bus_thread_cv;
	boolean_t bus_thread_exit;
	hpc_event_entry_t *bus_slot_event_list_head;
	hpc_bus_entry_t *bus_next;
};

#define	hpc_alloc_bus_entry()	\
	(hpc_bus_entry_t *)kmem_zalloc(sizeof (hpc_bus_entry_t), KM_SLEEP)

#define	hpc_free_bus_entry(a)	\
	kmem_free((a), sizeof (hpc_bus_entry_t))


/*
 * Definitions for the per-bus node slot registration list:
 *
 * For each bus node in the bus list, the hot-plug service module maintains
 * a doubly linked link list of items representing the slots that have been
 * registered (by hot-plug controllers) for that bus.
 *
 * The head of the linked listed is stored in bus_slot_list field of the bus
 * node.  Insertions and removals from this list should locked with the mutex
 * in the bus_mutex field of the bus node.
 *
 * Items in the list are allocated/freed with the macros hpc_alloc_slot_entry()
 * and hpc_free_slot_entry().
 *
 * Each item in the list contains the following fields:
 *
 *	slot_handle - handle for slot (hpc_slot_t)
 *
 *	slot_info - information registered with the slot (hpc_slot_info_t)
 *
 *	slot_ops - ops vector registered with the slot (hpc_slot_ops_t)
 *
 *	slot_ops_arg - argument to be passed to ops routines (caddr_t)
 *
 *	slot_event_handler - handler registered for slot events
 *
 *	slot_event_handler_arg - argument to be passed to event handler
 *
 *	slot_event_mask - the set of events for which the event handler
 *		gets invoked
 *
 *	slot_bus - pointer to bus node for the slot
 *
 *	slot_hpc_dip  -  devinfo node pointer to the HPC driver instance
 *			 that controls this slot
 *
 *	slot_{prev,next} - point to {previous,next} node in the list
 */

struct hpc_slot_entry {
	hpc_slot_t slot_handle;
	hpc_slot_info_t slot_info;	/* should be static & copied */
	hpc_slot_ops_t slot_ops;
	caddr_t slot_ops_arg;
	int (* slot_event_handler)(caddr_t, uint_t);
	caddr_t slot_event_handler_arg;
	uint_t slot_event_mask;
	hpc_bus_entry_t *slot_bus;
	dev_info_t *slot_hpc_dip;
	hpc_slot_entry_t *slot_next, *slot_prev;
};

#define	hpc_alloc_slot_entry()	\
	(hpc_slot_entry_t *)kmem_zalloc(sizeof (hpc_slot_entry_t), KM_SLEEP)

#define	hpc_free_slot_entry(a)	\
	kmem_free((a), sizeof (hpc_slot_entry_t))


/*
 * Definitions for slot registration callback table.
 */

typedef struct hpc_callback_entry hpc_callback_entry_t;

struct hpc_callback_entry {
	int (* callback)(dev_info_t *dip, hpc_slot_t hdl,
		hpc_slot_info_t *slot_info, int slot_state);
	dev_info_t *dip;
	hpc_slot_t hdl;
	hpc_slot_info_t *slot_info;
	int slot_state;
	hpc_callback_entry_t *next;
};

#define	hpc_alloc_callback_entry()	\
	(hpc_callback_entry_t *)	\
		kmem_zalloc(sizeof (hpc_callback_entry_t), KM_SLEEP)

#define	hpc_free_callback_entry(a)	\
	kmem_free((a), sizeof (hpc_callback_entry_t))



/*
 * Mutex lock for bus registration table and table head.
 */
static kmutex_t hpc_bus_mutex;
static hpc_bus_entry_t *hpc_bus_list_head;


/*
 * Forward function declarations.
 */
static hpc_bus_entry_t *hpc_find_bus_by_name(char *name);
static void hpc_slot_event_dispatcher(hpc_bus_entry_t *busp);


/*
 * loadable module definitions:
 */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,	/* Type of module */
	"hot-plug controller services"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	int e;

	mutex_init(&hpc_bus_mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Install the module.
	 */
	e = mod_install(&modlinkage);
	if (e != 0) {
		mutex_destroy(&hpc_bus_mutex);
	}
	return (e);
}

int
_fini(void)
{
	int e;

	e = mod_remove(&modlinkage);
	if (e == 0) {
		mutex_destroy(&hpc_bus_mutex);
	}
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}



hpc_slot_ops_t *
hpc_alloc_slot_ops(int flag)
{
	hpc_slot_ops_t *ops;

	ops = (hpc_slot_ops_t *)kmem_zalloc(sizeof (hpc_slot_ops_t), flag);
	return (ops);
}


void
hpc_free_slot_ops(hpc_slot_ops_t *ops)
{
	kmem_free((void *)ops, sizeof (hpc_slot_ops_t));
}


/*ARGSUSED2*/
int
hpc_nexus_register_bus(dev_info_t *dip,
	int (* callback)(dev_info_t *dip, hpc_slot_t hdl,
	hpc_slot_info_t *slot_info, int slot_state), uint_t flags)
{
	hpc_bus_entry_t *busp;
	hpc_slot_entry_t *slotp;
	char bus_path[MAXPATHLEN + 1];

	DEBUG2("hpc_nexus_register_bus: %s%d",
	    ddi_node_name(dip), ddi_get_instance(dip));
	mutex_enter(&hpc_bus_mutex);
	(void) ddi_pathname(dip, bus_path);
	busp = hpc_find_bus_by_name(bus_path);
	if (busp == NULL) {

		/*
		 * Initialize the new bus node and link it at the head
		 * of the bus list.
		 */
		DEBUG0("hpc_nexus_register_bus: not in bus list");
		busp = hpc_alloc_bus_entry();
		busp->bus_dip = dip;
		busp->bus_registered = B_TRUE;
		(void) strcpy(busp->bus_name, bus_path);
		mutex_init(&busp->bus_mutex, NULL, MUTEX_DRIVER, NULL);
		busp->bus_callback = callback;
		busp->bus_slot_list = NULL;
		busp->bus_next = hpc_bus_list_head;
		hpc_bus_list_head = busp;

	} else {

		/*
		 * The bus is in the bus list but isn't registered yet.
		 * Mark it as registered, and run the registration callbacks
		 * for it slots.
		 */
		DEBUG0("hpc_nexus_register_bus: in list, but not registered");
		mutex_enter(&busp->bus_mutex);
		if (busp->bus_registered == B_TRUE) {
			mutex_exit(&busp->bus_mutex);
			mutex_exit(&hpc_bus_mutex);
			return (HPC_ERR_BUS_DUPLICATE);
		}
		busp->bus_dip = dip;
		busp->bus_callback = callback;
		busp->bus_registered = B_TRUE;

		mutex_exit(&busp->bus_mutex);
		mutex_exit(&hpc_bus_mutex);
		if (callback) {
			DEBUG0("hpc_nexus_register_bus: running callbacks");
			for (slotp = busp->bus_slot_list; slotp;
			    slotp = slotp->slot_next) {
				(void) callback(dip, slotp, &slotp->slot_info,
				    HPC_SLOT_ONLINE);
			}
		}
		return (HPC_SUCCESS);
	}
	mutex_exit(&hpc_bus_mutex);
	return (HPC_SUCCESS);
}


int
hpc_nexus_unregister_bus(dev_info_t *dip)
{
	hpc_bus_entry_t *busp, *busp_prev;
	hpc_slot_entry_t *slotp;

	/*
	 * Search the list for the bus node and remove it.
	 */
	DEBUG2("hpc_nexus_unregister_bus: %s%d",
	    ddi_node_name(dip), ddi_get_instance(dip));
	mutex_enter(&hpc_bus_mutex);
	for (busp = hpc_bus_list_head; busp != NULL; busp_prev = busp,
	    busp = busp->bus_next) {
		if (busp->bus_dip == dip)
			break;
	}
	if (busp == NULL) {
		mutex_exit(&hpc_bus_mutex);
		return (HPC_ERR_BUS_NOTREGISTERED);
	}

	/*
	 * If the bus has slots, mark the bus as unregistered, otherwise
	 * remove the bus entry from the list.
	 */
	mutex_enter(&busp->bus_mutex);
	if (busp->bus_slot_list == NULL) {
		if (busp == hpc_bus_list_head)
			hpc_bus_list_head = busp->bus_next;
		else
			busp_prev->bus_next = busp->bus_next;
		mutex_exit(&busp->bus_mutex);
		mutex_destroy(&busp->bus_mutex);
		hpc_free_bus_entry(busp);
		mutex_exit(&hpc_bus_mutex);
		return (HPC_SUCCESS);
	}

	/*
	 * unregister event handlers for all the slots on this bus.
	 */
	for (slotp = busp->bus_slot_list; slotp != NULL;
		slotp = slotp->slot_next) {
		slotp->slot_event_handler = NULL;
		slotp->slot_event_handler_arg = NULL;
	}
	busp->bus_registered = B_FALSE;
	mutex_exit(&busp->bus_mutex);
	mutex_exit(&hpc_bus_mutex);
	return (HPC_SUCCESS);
}


/*ARGSUSED5*/
int
hpc_slot_register(dev_info_t *hpc_dip, char *bus, hpc_slot_info_t *infop,
	hpc_slot_t *handlep, hpc_slot_ops_t *opsp,
	caddr_t ops_arg, uint_t flags)
{
	hpc_bus_entry_t *busp;
	hpc_slot_entry_t *slotp, *slot_list_head;
	boolean_t run_callback = B_FALSE;
	int (* callback)(dev_info_t *dip, hpc_slot_t hdl,
		hpc_slot_info_t *slot_info, int slot_state);
	dev_info_t *dip;
	kthread_t *t;

	/*
	 * Validate the arguments.
	 */
	DEBUG1("hpc_slot_register: %s", bus);
	if (handlep == NULL || infop == NULL || opsp == NULL || hpc_dip == NULL)
		return (HPC_ERR_INVALID);

	/*
	 * The bus for the slot may or may not be in the bus list.  If it's
	 * not, we create a node for the bus in the bus list and mark it as
	 * not registered.
	 */
	mutex_enter(&hpc_bus_mutex);
	busp = hpc_find_bus_by_name(bus);
	if (busp == NULL) {

		/*
		 * Initialize the new bus node and link it at the
		 * head of the bus list.
		 */
		DEBUG1("hpc_slot_register: %s not in bus list", bus);
		busp = hpc_alloc_bus_entry();
		busp->bus_registered = B_FALSE;
		(void) strcpy(busp->bus_name, bus);
		mutex_init(&busp->bus_mutex, NULL, MUTEX_DRIVER, NULL);
		busp->bus_slot_list = NULL;
		busp->bus_next = hpc_bus_list_head;
		hpc_bus_list_head = busp;

	} else {
		if (busp->bus_registered == B_TRUE) {
			run_callback = B_TRUE;
			callback = busp->bus_callback;
			dip = busp->bus_dip;
		}
	}

	mutex_enter(&busp->bus_mutex);
	slot_list_head = busp->bus_slot_list;
	if (slot_list_head == NULL) {

		/*
		 * The slot list was empty, so this is the first slot
		 * registered for the bus.  Create a per-bus thread
		 * for running the slot event handlers.
		 */
		DEBUG0("hpc_slot_register: creating event callback thread");
		cv_init(&busp->bus_thread_cv, NULL, CV_DRIVER, NULL);
		busp->bus_thread_exit = B_FALSE;
		t = thread_create(NULL, 0, hpc_slot_event_dispatcher,
		    (caddr_t)busp, 0, &p0, TS_RUN, minclsyspri);
		busp->bus_thread = t;
	}

	/*
	 * Create and initialize a new entry in the slot list for the bus.
	 */
	slotp = hpc_alloc_slot_entry();
	slotp->slot_handle = (hpc_slot_t)slotp;
	slotp->slot_info = *infop;
	slotp->slot_ops = *opsp;
	slotp->slot_ops_arg = ops_arg;
	slotp->slot_bus = busp;
	slotp->slot_hpc_dip = hpc_dip;
	slotp->slot_prev = NULL;
	busp->bus_slot_list = slotp;
	slotp->slot_next = slot_list_head;
	if (slot_list_head != NULL)
		slot_list_head->slot_prev = slotp;
	mutex_exit(&busp->bus_mutex);
	mutex_exit(&hpc_bus_mutex);

	/*
	 * Return the handle to the caller prior to return to avoid recursion.
	 */
	*handlep = (hpc_slot_t)slotp;

	/*
	 * If the bus was registered, we run the callback registered by
	 * the bus node.
	 */
	if (run_callback) {
		DEBUG0("hpc_slot_register: running callback");

		(void) callback(dip, slotp, infop, HPC_SLOT_ONLINE);
	}

	/*
	 * Keep hpc driver in memory
	 */
	(void) ndi_hold_driver(hpc_dip);

	return (HPC_SUCCESS);
}


int
hpc_slot_unregister(hpc_slot_t *handlep)
{
	hpc_slot_entry_t *slotp;
	hpc_bus_entry_t *busp, *busp_prev;
	boolean_t run_callback;
	int (* callback)(dev_info_t *dip, hpc_slot_t hdl,
		hpc_slot_info_t *slot_info, int slot_state);
	int r;
	dev_info_t *dip;
	char *bus_name;

	DEBUG0("hpc_slot_unregister:");

	ASSERT(handlep != NULL);

	/* validate the handle */
	slotp = (hpc_slot_entry_t *)*handlep;
	if ((slotp == NULL) || slotp->slot_handle != *handlep)
		return (HPC_ERR_INVALID);

	/*
	 * Get the bus list entry from the slot to grap the mutex for
	 * the slot list of the bus.
	 */
	mutex_enter(&hpc_bus_mutex);
	busp = slotp->slot_bus;
	DEBUG2("hpc_slot_unregister: handlep=%x, slotp=%x", handlep, slotp);
	if (busp == NULL) {
		mutex_exit(&hpc_bus_mutex);
		return (HPC_ERR_SLOT_NOTREGISTERED);
	}

	/*
	 * Determine if we need to run the slot offline callback and
	 * save the data necessary to do so.
	 */
	callback = busp->bus_callback;
	run_callback = (busp->bus_registered == B_TRUE) && (callback != NULL);
	dip = busp->bus_dip;
	bus_name = busp->bus_name;

	/*
	 * Run the slot offline callback if necessary.
	 */
	if (run_callback) {
		mutex_exit(&hpc_bus_mutex);
		DEBUG0("hpc_slot_unregister: running callback");
		r = callback(dip, (hpc_slot_t)slotp, &slotp->slot_info,
		    HPC_SLOT_OFFLINE);
		DEBUG1("hpc_slot_unregister: callback returned %x", r);
		if (r != HPC_SUCCESS)
			return (HPC_ERR_FAILED);
		mutex_enter(&hpc_bus_mutex);
	}

	/*
	 * Remove the slot from list and free the memory associated with it.
	 */
	mutex_enter(&busp->bus_mutex);
	DEBUG1("hpc_slot_unregister: freeing slot, bus_slot_list=%x",
		busp->bus_slot_list);
	if (slotp->slot_prev != NULL)
		slotp->slot_prev->slot_next = slotp->slot_next;
	if (slotp->slot_next != NULL)
		slotp->slot_next->slot_prev = slotp->slot_prev;
	if (slotp == busp->bus_slot_list)
		busp->bus_slot_list = slotp->slot_next;

	/*
	 * Release hold from slot registration
	 */
	ndi_rele_driver(slotp->slot_hpc_dip);

	/* Free the memory associated with the slot entry structure */
	hpc_free_slot_entry(slotp);

	/*
	 * If the slot list is empty then stop the event handler thread.
	 */
	if (busp->bus_slot_list == NULL) {
		DEBUG0("hpc_slot_unregister: stopping thread");
		busp->bus_thread_exit = B_TRUE;
		cv_signal(&busp->bus_thread_cv);
		DEBUG0("hpc_slot_unregister: waiting for thread to exit");
		cv_wait(&busp->bus_thread_cv, &busp->bus_mutex);
		DEBUG0("hpc_slot_unregister: thread exit");
		cv_destroy(&busp->bus_thread_cv);
	}

	/*
	 * If the bus is unregistered and this is the last slot for this bus
	 * then remove the entry from the bus list.
	 */
	if (busp->bus_registered == B_FALSE && busp->bus_slot_list == NULL) {
		/* locate the previous entry in the bus list */
		for (busp = hpc_bus_list_head; busp != NULL; busp_prev = busp,
		    busp = busp->bus_next)
			if (strcmp(bus_name, busp->bus_name) == 0)
				break;

		if (busp == hpc_bus_list_head)
			hpc_bus_list_head = busp->bus_next;
		else
			busp_prev->bus_next = busp->bus_next;

		mutex_exit(&busp->bus_mutex);
		mutex_destroy(&busp->bus_mutex);
		hpc_free_bus_entry(busp);
	} else
		mutex_exit(&busp->bus_mutex);
	mutex_exit(&hpc_bus_mutex);

	/*
	 * reset the slot handle.
	 */
	*handlep = NULL;
	return (HPC_SUCCESS);
}


int
hpc_install_event_handler(hpc_slot_t handle, uint_t event_mask,
	int (*event_handler)(caddr_t, uint_t), caddr_t arg)
{
	hpc_slot_entry_t *slotp;
	hpc_bus_entry_t *busp;

	DEBUG3("hpc_install_event_handler: handle=%x, mask=%x, arg=%x",
		handle, event_mask, arg);
	ASSERT((handle != NULL) && (event_handler != NULL));
	slotp = (hpc_slot_entry_t *)handle;
	busp = slotp->slot_bus;
	ASSERT(slotp == slotp->slot_handle);
	mutex_enter(&busp->bus_mutex);
	slotp->slot_event_mask = event_mask;
	slotp->slot_event_handler = event_handler;
	slotp->slot_event_handler_arg = arg;
	mutex_exit(&busp->bus_mutex);
	return (HPC_SUCCESS);
}


int
hpc_remove_event_handler(hpc_slot_t handle)
{
	hpc_slot_entry_t *slotp;
	hpc_bus_entry_t *busp;

	DEBUG1("hpc_remove_event_handler: handle=%x", handle);
	ASSERT(handle != NULL);
	slotp = (hpc_slot_entry_t *)handle;
	ASSERT(slotp == slotp->slot_handle);
	busp = slotp->slot_bus;
	mutex_enter(&busp->bus_mutex);
	slotp->slot_event_mask = 0;
	slotp->slot_event_handler = NULL;
	slotp->slot_event_handler_arg = NULL;
	mutex_exit(&busp->bus_mutex);
	return (HPC_SUCCESS);
}


/*ARGSUSED2*/
int
hpc_slot_event_notify(hpc_slot_t handle, uint_t event, uint_t flags)
{
	hpc_slot_entry_t *slotp;
	hpc_bus_entry_t *busp;
	hpc_event_entry_t *eventp;

	DEBUG2("hpc_slot_event_notify: handle=%x event=%x", handle, event);
	ASSERT(handle != NULL);
	slotp = (hpc_slot_entry_t *)handle;
	ASSERT(slotp == slotp->slot_handle);

	if (slotp->slot_event_handler == NULL)
		return (HPC_EVENT_UNCLAIMED);

	/*
	 * If the request is to handle the event synchronously, then call
	 * the event handler without queuing the event.
	 */
	if (flags == HPC_EVENT_SYNCHRONOUS) {
		caddr_t arg;
		int (* func)(caddr_t, uint_t);

		func = slotp->slot_event_handler;
		arg = slotp->slot_event_handler_arg;
		return (func(arg, event));
	}
	/*
	 * Insert the event into the bus slot event handler list and
	 * signal the bus slot event handler dispatch thread.
	 */
	busp = slotp->slot_bus;
	mutex_enter(&busp->bus_mutex);

	if (busp->bus_slot_event_list_head == NULL) {
		eventp = busp->bus_slot_event_list_head =
		    hpc_alloc_event_entry();
	} else {
		for (eventp = busp->bus_slot_event_list_head;
			    eventp->next != NULL; eventp = eventp->next)
			;
		eventp->next = hpc_alloc_event_entry();
		eventp = eventp->next;
	}
	eventp->slotp = slotp;
	eventp->event = event;
	eventp->next = NULL;
	DEBUG2("hpc_slot_event_notify: busp=%x event=%x", busp, event);
	cv_signal(&busp->bus_thread_cv);
	mutex_exit(&busp->bus_mutex);
	return (HPC_EVENT_CLAIMED);
}


int
hpc_nexus_connect(hpc_slot_t handle, void *data, uint_t flags)
{
	hpc_slot_entry_t *slotp;

	ASSERT(handle != NULL);
	slotp = (hpc_slot_entry_t *)handle;
	if (slotp->slot_ops.hpc_op_connect)
		return (slotp->slot_ops.hpc_op_connect(slotp->slot_ops_arg,
			handle, data, flags));
	return (HPC_ERR_FAILED);
}


int
hpc_nexus_disconnect(hpc_slot_t handle, void *data, uint_t flags)
{
	hpc_slot_entry_t *slotp;

	ASSERT(handle != NULL);
	slotp = (hpc_slot_entry_t *)handle;
	if (slotp->slot_ops.hpc_op_disconnect)
		return (slotp->slot_ops.hpc_op_disconnect(slotp->slot_ops_arg,
			handle, data, flags));
	return (HPC_ERR_FAILED);
}


int
hpc_nexus_insert(hpc_slot_t handle, void *data, uint_t flags)
{
	hpc_slot_entry_t *slotp;

	ASSERT(handle != NULL);
	slotp = (hpc_slot_entry_t *)handle;
	if (slotp->slot_ops.hpc_op_insert)
		return (slotp->slot_ops.hpc_op_insert(slotp->slot_ops_arg,
			handle, data, flags));
	return (HPC_ERR_FAILED);
}


int
hpc_nexus_remove(hpc_slot_t handle, void *data, uint_t flags)
{
	hpc_slot_entry_t *slotp;

	ASSERT(handle != NULL);
	slotp = (hpc_slot_entry_t *)handle;
	if (slotp->slot_ops.hpc_op_remove)
		return (slotp->slot_ops.hpc_op_remove(slotp->slot_ops_arg,
			handle, data, flags));
	return (HPC_ERR_FAILED);
}


int
hpc_nexus_control(hpc_slot_t handle, int request, caddr_t arg)
{
	hpc_slot_entry_t *slotp;

	ASSERT(handle != NULL);
	slotp = (hpc_slot_entry_t *)handle;
	if (slotp->slot_ops.hpc_op_control)
		return (slotp->slot_ops.hpc_op_control(slotp->slot_ops_arg,
			handle, request, arg));
	return (HPC_ERR_FAILED);
}

/*
 * The following function is run from the bus entries slot event handling
 * thread.
 */
static void
hpc_slot_event_dispatcher(hpc_bus_entry_t *busp)
{
	hpc_event_entry_t *eventp;
	hpc_slot_entry_t *slotp;
	int event;
	caddr_t arg;
	int (* func)(caddr_t, uint_t);
	callb_cpr_t cprinfo;

	/*
	 * The creator of this thread is waiting to be signaled that
	 * the thread has been started.
	 */
	DEBUG1("hpc_slot_event_dispatcher: busp=%x", busp);

	CALLB_CPR_INIT(&cprinfo, &busp->bus_mutex, callb_generic_cpr,
	    "hpc_slot_event_dispatcher");

	mutex_enter(&busp->bus_mutex);
	/*
	 * Wait for events to queue and then process them.
	 */
	for (;;) {

		/*
		 * Note we only hold the mutex while determining
		 * the number of entries that have been added to
		 * the event list, while updating the event list
		 * after processing the event list entries.
		 */
		if (busp->bus_slot_event_list_head == NULL) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&busp->bus_thread_cv, &busp->bus_mutex);
			CALLB_CPR_SAFE_END(&cprinfo, &busp->bus_mutex);
			if (busp->bus_thread_exit)
				break;
			continue;
		}

		/*
		 * We have an event handler instance in the list to
		 * process.  Remove the head of the list, saving the
		 * information required to run the event handler.
		 * Then run the event handler while the bus mutex
		 * is released.
		 */
		eventp = busp->bus_slot_event_list_head;
		slotp = eventp->slotp;
		event = eventp->event;
		func = slotp->slot_event_handler;
		arg = slotp->slot_event_handler_arg;
		busp->bus_slot_event_list_head = eventp->next;
		hpc_free_event_entry(eventp);
		mutex_exit(&busp->bus_mutex);
		func(arg, event);
		mutex_enter(&busp->bus_mutex);

		if (busp->bus_thread_exit)
			break;
	}

	DEBUG0("hpc_slot_event_dispatcher: thread_exit");
	cv_signal(&busp->bus_thread_cv);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}


static hpc_bus_entry_t *
hpc_find_bus_by_name(char *path)
{
	hpc_bus_entry_t *busp;

	for (busp = hpc_bus_list_head; busp != NULL; busp = busp->bus_next) {
		if (strcmp(path, busp->bus_name) == 0)
			break;
	}
	return (busp);
}

boolean_t
hpc_bus_registered(hpc_slot_t slot_hdl)
{
	hpc_slot_entry_t *slotp;
	hpc_bus_entry_t *busp;

	slotp = (hpc_slot_entry_t *)slot_hdl;
	busp = slotp->slot_bus;
	return (busp->bus_registered);
}


#ifdef DEBUG

extern void prom_printf(const char *, ...);

static void
debug(char *fmt, uintptr_t a1, uintptr_t a2, uintptr_t a3,
    uintptr_t a4, uintptr_t a5)
{
	if (hpcsvc_debug != 0) {
		cmn_err(CE_CONT, "hpcsvc: ");
		cmn_err(CE_CONT, fmt, a1, a2, a3, a4, a5);
		cmn_err(CE_CONT, "\n");
	}
}
#endif
