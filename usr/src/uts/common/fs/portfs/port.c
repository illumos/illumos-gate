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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/modctl.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/kstat.h>
#include <sys/port_impl.h>
#include <sys/task.h>
#include <sys/project.h>

/*
 * Event Ports can be shared across threads or across processes.
 * Every thread/process can use an own event port or a group of them
 * can use a single port. A major request was also to get the ability
 * to submit user-defined events to a port. The idea of the
 * user-defined events is to use the event ports for communication between
 * threads/processes (like message queues). User defined-events are queued
 * in a port with the same priority as other event types.
 *
 * Events are delivered only once. The thread/process which is waiting
 * for events with the "highest priority" (priority here is related to the
 * internal strategy to wakeup waiting threads) will retrieve the event,
 * all other threads/processes will not be notified. There is also
 * the requirement to have events which should be submitted immediately
 * to all "waiting" threads. That is the main task of the alert event.
 * The alert event is submitted by the application to a port. The port
 * changes from a standard mode to the alert mode. Now all waiting threads
 * will be awaken immediately and they will return with the alert event.
 * Threads trying to retrieve events from a port in alert mode will
 * return immediately with the alert event.
 *
 *
 * An event port is like a kernel queue, which accept events submitted from
 * user level as well as events submitted from kernel sub-systems. Sub-systems
 * able to submit events to a port are the so-called "event sources".
 * Current event sources:
 * PORT_SOURCE_AIO	 : events submitted per transaction completion from
 *			   POSIX-I/O framework.
 * PORT_SOURCE_TIMER	 : events submitted when a timer fires
 *			   (see timer_create(3RT)).
 * PORT_SOURCE_FD	 : events submitted per file descriptor (see poll(2)).
 * PORT_SOURCE_ALERT	 : events submitted from user. This is not really a
 *			   single event, this is actually a port mode
 *			   (see port_alert(3c)).
 * PORT_SOURCE_USER	 : events submitted by applications with
 *			   port_send(3c) or port_sendn(3c).
 * PORT_SOURCE_FILE	 : events submitted per file being watched for file
 *			   change events  (see port_create(3c).
 *
 * There is a user API implemented in the libc library as well as a
 * kernel API implemented in port_subr.c in genunix.
 * The available user API functions are:
 * port_create() : create a port as a file descriptor of portfs file system
 *		   The standard close(2) function closes a port.
 * port_associate() : associate a file descriptor with a port to be able to
 *		      retrieve events from that file descriptor.
 * port_dissociate(): remove the association of a file descriptor with a port.
 * port_alert()	 : set/unset a port in alert mode
 * port_send()	 : send an event of type PORT_SOURCE_USER to a port
 * port_sendn()	 : send an event of type PORT_SOURCE_USER to a list of ports
 * port_get()	 : retrieve a single event from a port
 * port_getn()	 : retrieve a list of events from a port
 *
 * The available kernel API functions are:
 * port_allocate_event(): allocate an event slot/structure of/from a port
 * port_init_event()    : set event data in the event structure
 * port_send_event()    : send event to a port
 * port_free_event()    : deliver allocated slot/structure back to a port
 * port_associate_ksource(): associate a kernel event source with a port
 * port_dissociate_ksource(): dissociate a kernel event source from a port
 *
 * The libc implementation consists of small functions which pass the
 * arguments to the kernel using the "portfs" system call. It means, all the
 * synchronisation work is being done in the kernel. The "portfs" system
 * call loads the portfs file system into the kernel.
 *
 * PORT CREATION
 * The first function to be used is port_create() which internally creates
 * a vnode and a portfs node. The portfs node is represented by the port_t
 * structure, which again includes all the data necessary to control a port.
 * port_create() returns a file descriptor, which needs to be used in almost
 * all other event port functions.
 * The maximum number of ports per system is controlled by the resource
 * control: project:port-max-ids.
 *
 * EVENT GENERATION
 * The second step is the triggering of events, which could be sent to a port.
 * Every event source implements an own method to generate events for a port:
 * PORT_SOURCE_AIO:
 * 	The sigevent structure of the standard POSIX-IO functions
 * 	was extended by an additional notification type.
 * 	Standard notification types:
 * 	SIGEV_NONE, SIGEV_SIGNAL and SIGEV_THREAD
 * 	Event ports introduced now SIGEV_PORT.
 * 	The notification type SIGEV_PORT specifies that a structure
 * 	of type port_notify_t has to be attached to the sigev_value.
 * 	The port_notify_t structure contains the event port file
 * 	descriptor and a user-defined pointer.
 * 	Internally the AIO implementation will use the kernel API
 * 	functions to allocate an event port slot per transaction (aiocb)
 * 	and sent the event to the port as soon as the transaction completes.
 * 	All the events submitted per transaction are of type
 * 	PORT_SOURCE_AIO.
 * PORT_SOURCE_TIMER:
 * 	The timer_create() function uses the same method as the
 * 	PORT_SOURCE_AIO event source. It also uses the sigevent structure
 * 	to deliver the port information.
 * 	Internally the timer code will allocate a single event slot/struct
 * 	per timer and it will send the timer event as soon as the timer
 * 	fires. If the timer-fired event is not delivered to the application
 * 	before the next period elapsed, then an overrun counter will be
 * 	incremented. The timer event source uses a callback function to
 * 	detect the delivery of the event to the application. At that time
 * 	the timer callback function will update the event overrun counter.
 * PORT_SOURCE_FD:
 * 	This event source uses the port_associate() function to allocate
 * 	an event slot/struct from a port. The application defines in the
 * 	events argument of port_associate() the type of events which it is
 * 	interested on.
 * 	The internal pollwakeup() function is used by all the file
 * 	systems --which are supporting the VOP_POLL() interface- to notify
 * 	the upper layer (poll(2), devpoll(7d) and now event ports) about
 * 	the event triggered (see valid events in poll(2)).
 * 	The pollwakeup() function forwards the event to the layer registered
 * 	to receive the current event.
 * 	The port_dissociate() function can be used to free the allocated
 * 	event slot from the port. Anyway, file descriptors deliver events
 * 	only one time and remain deactivated until the application
 * 	reactivates the association of a file descriptor with port_associate().
 * 	If an associated file descriptor is closed then the file descriptor
 * 	will be dissociated automatically from the port.
 *
 * PORT_SOURCE_ALERT:
 * 	This event type is generated when the port was previously set in
 * 	alert mode using the port_alert() function.
 * 	A single alert event is delivered to every thread which tries to
 * 	retrieve events from a port.
 * PORT_SOURCE_USER:
 * 	This type of event is generated from user level using the port_send()
 * 	function to send a user event to a port or the port_sendn() function
 * 	to send an event to a list of ports.
 * PORT_SOURCE_FILE:
 *	This event source uses the port_associate() interface to register
 *	a file to be monitored for changes. The file name that needs to be
 *	monitored is specified in the file_obj_t structure, a pointer to which
 *	is passed as an argument. The event types to be monitored are specified
 *	in the events argument.
 *	A file events monitor is represented internal per port per object
 *	address(the file_obj_t pointer). Which means there can be multiple
 *	watches registered on the same file using different file_obj_t
 *	structure pointer. With the help of the	FEM(File Event Monitoring)
 *	hooks, the file's vnode ops are intercepted and relevant events
 *	delivered. The port_dissociate() function is used to de-register a
 *	file events monitor on a file. When the specified file is
 *	removed/renamed, the file events watch/monitor is automatically
 *	removed.
 *
 * EVENT DELIVERY / RETRIEVING EVENTS
 * Events remain in the port queue until:
 * - the application uses port_get() or port_getn() to retrieve events,
 * - the event source cancel the event,
 * - the event port is closed or
 * - the process exits.
 * The maximal number of events in a port queue is the maximal number
 * of event slots/structures which can be allocated by event sources.
 * The allocation of event slots/structures is controlled by the resource
 * control: process.port-max-events.
 * The port_get() function retrieves a single event and the port_getn()
 * function retrieves a list of events.
 * Events are classified as shareable and non-shareable events across processes.
 * Non-shareable events are invisible for the port_get(n)() functions of
 * processes other than the owner of the event.
 *    Shareable event types are:
 *    PORT_SOURCE_USER events
 * 	This type of event is unconditionally shareable and without
 * 	limitations. If the parent process sends a user event and closes
 * 	the port afterwards, the event remains in the port and the child
 * 	process will still be able to retrieve the user event.
 *    PORT_SOURCE_ALERT events
 * 	This type of event is shareable between processes.
 * 	Limitation:	The alert mode of the port is removed if the owner
 * 			(process which set the port in alert mode) of the
 * 			alert event closes the port.
 *    PORT_SOURCE_FD events
 * 	This type of event is conditional shareable between processes.
 * 	After fork(2) all forked file descriptors are shareable between
 * 	the processes. The child process is allowed to retrieve events
 * 	from the associated file descriptors and it can also re-associate
 * 	the fd with the port.
 * 	Limitations:	The child process is not allowed to dissociate
 * 			the file descriptor from the port. Only the
 * 			owner (process) of the association is allowed to
 * 			dissociate the file descriptor from the port.
 * 			If the owner of the association closes the port
 * 			the association will be removed.
 *    PORT_SOURCE_AIO events
 * 	This type of event is not shareable between processes.
 *    PORT_SOURCE_TIMER events
 * 	This type of event is not shareable between processes.
 *    PORT_SOURCE_FILE events
 * 	This type of event is not shareable between processes.
 *
 * FORK BEHAVIOUR
 * On fork(2) the child process inherits all opened file descriptors from
 * the parent process. This is also valid for port file descriptors.
 * Associated file descriptors with a port maintain the association across the
 * fork(2). It means, the child process gets full access to the port and
 * it can retrieve events from all common associated file descriptors.
 * Events of file descriptors created and associated with a port after the
 * fork(2) are non-shareable and can only be retrieved by the same process.
 *
 * If the parent or the child process closes an exported port (using fork(2)
 * or I_SENDFD) all the file descriptors associated with the port by the
 * process will be dissociated from the port. Events of dissociated file
 * descriptors as well as all non-shareable events will be discarded.
 * The other process can continue working with the port as usual.
 *
 * CLOSING A PORT
 * close(2) has to be used to close a port. See FORK BEHAVIOUR for details.
 *
 * PORT EVENT STRUCTURES
 * The global control structure of the event ports framework is port_control_t.
 * port_control_t keeps track of the number of created ports in the system.
 * The cache of the port event structures is also located in port_control_t.
 *
 * On port_create() the vnode and the portfs node is also created.
 * The portfs node is represented by the port_t structure.
 * The port_t structure manages all port specific tasks:
 * - management of resource control values
 * - port VOP_POLL interface
 * - creation time
 * - uid and gid of the port
 *
 * The port_t structure contains the port_queue_t structure.
 * The port_queue_t structure contains all the data necessary for the
 * queue management:
 * - locking
 * - condition variables
 * - event counters
 * - submitted events	(represented by port_kevent_t structures)
 * - threads waiting for event delivery (check portget_t structure)
 * - PORT_SOURCE_FD cache	(managed by the port_fdcache_t structure)
 * - event source management (managed by the port_source_t structure)
 * - alert mode management	(check port_alert_t structure)
 *
 * EVENT MANAGEMENT
 * The event port file system creates a kmem_cache for internal allocation of
 * event port structures.
 *
 * 1. Event source association with a port:
 * The first step to do for event sources is to get associated with a port
 * using the port_associate_ksource() function or adding an entry to the
 * port_ksource_tab[]. An event source can get dissociated from a port
 * using the port_dissociate_ksource() function. An entry in the
 * port_ksource_tab[] implies that the source will be associated
 * automatically with every new created port.
 * The event source can deliver a callback function, which is used by the
 * port to notify the event source about close(2). The idea is that
 * in such a case the event source should free all allocated resources
 * and it must return to the port all allocated slots/structures.
 * The port_close() function will wait until all allocated event
 * structures/slots are returned to the port.
 * The callback function is not necessary when the event source does not
 * maintain local resources, a second condition is that the event source
 * can guarantee that allocated event slots will be returned without
 * delay to the port (it will not block and sleep somewhere).
 *
 * 2. Reservation of an event slot / event structure
 * The event port reliability is based on the reservation of an event "slot"
 * (allocation of an event structure) by the event source as part of the
 * application call. If the maximal number of event slots is exhausted then
 * the event source can return a corresponding error code to the application.
 *
 * The port_alloc_event() function has to be used by event sources to
 * allocate an event slot (reserve an event structure). The port_alloc_event()
 * doesn not block and it will return a 0 value on success or an error code
 * if it fails.
 * An argument of port_alloc_event() is a flag which determines the behavior
 * of the event after it was delivered to the application:
 * PORT_ALLOC_DEFAULT	: event slot becomes free after delivery to the
 *			  application.
 * PORT_ALLOC_PRIVATE	: event slot remains under the control of the event
 *			  source. This kind of slots can not be used for
 *			  event delivery and should only be used internally
 *			  by the event source.
 * PORT_KEV_CACHED	: event slot remains under the control of an event
 *			  port cache. It does not become free after delivery
 *			  to the application.
 * PORT_ALLOC_SCACHED	: event slot remains under the control of the event
 *			  source. The event source takes the control over
 *			  the slot after the event is delivered to the
 *			  application.
 *
 * 3. Delivery of events to the event port
 * Earlier allocated event structure/slot has to be used to deliver
 * event data to the port. Event source has to use the function
 * port_send_event(). The single argument is a pointer to the previously
 * reserved event structure/slot.
 * The portkev_events field of the port_kevent_t structure can be updated/set
 * in two ways:
 * 1. using the port_set_event() function, or
 * 2. updating the portkev_events field out of the callback function:
 *    The event source can deliver a callback function to the port as an
 *    argument of port_init_event().
 *    One of the arguments of the callback function is a pointer to the
 *    events field, which will be delivered to the application.
 *    (see Delivery of events to the application).
 * Event structures/slots can be delivered to the event port only one time,
 * they remain blocked until the data is delivered to the application and the
 * slot becomes free or it is delivered back to the event source
 * (PORT_ALLOC_SCACHED). The activation of the callback function mentioned above
 * is at the same time the indicator for the event source that the event
 * structure/slot is free for reuse.
 *
 * 4. Delivery of events to the application
 * The events structures/slots delivered by event sources remain in the
 * port queue until they are retrieved by the application or the port
 * is closed (exit(2) also closes all opened file descriptors)..
 * The application uses port_get() or port_getn() to retrieve events from
 * a port. port_get() retrieves a single event structure/slot and port_getn()
 * retrieves a list of event structures/slots.
 * Both functions are able to poll for events and return immediately or they
 * can specify a timeout value.
 * Before the events are delivered to the application they are moved to a
 * second temporary internal queue. The idea is to avoid lock collisions or
 * contentions of the global queue lock.
 * The global queue lock is used every time when an event source delivers
 * new events to the port.
 * The port_get() and port_getn() functions
 * a) retrieve single events from the temporary queue,
 * b) prepare the data to be passed to the application memory,
 * c) activate the callback function of the event sources:
 *    - to get the latest event data,
 *    - the event source can free all allocated resources associated with the
 *      current event,
 *    - the event source can re-use the current event slot/structure
 *    - the event source can deny the delivery of the event to the application
 *      (e.g. because of the wrong process).
 * d) put the event back to the temporary queue if the event delivery was denied
 * e) repeat a) until d) as long as there are events in the queue and
 *    there is enough user space available.
 *
 * The loop described above could block for a very long time the global mutex,
 * to avoid that a second mutex was introduced to synchronized concurrent
 * threads accessing the temporary queue.
 */

static int64_t portfs(int, uintptr_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t);

static struct sysent port_sysent = {
	6,
	SE_ARGC | SE_64RVAL | SE_NOUNLOAD,
	(int (*)())portfs,
};

static struct modlsys modlsys = {
	&mod_syscallops, "event ports", &port_sysent
};

#ifdef _SYSCALL32_IMPL

static int64_t
portfs32(uint32_t arg1, int32_t arg2, uint32_t arg3, uint32_t arg4,
    uint32_t arg5, uint32_t arg6);

static struct sysent port_sysent32 = {
	6,
	SE_ARGC | SE_64RVAL | SE_NOUNLOAD,
	(int (*)())portfs32,
};

static struct modlsys modlsys32 = {
	&mod_syscallops32,
	"32-bit event ports syscalls",
	&port_sysent32
};
#endif	/* _SYSCALL32_IMPL */

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsys,
#ifdef _SYSCALL32_IMPL
	&modlsys32,
#endif
	NULL
};

port_kstat_t port_kstat = {
	{ "ports",	KSTAT_DATA_UINT32 }
};

dev_t	portdev;
struct	vnodeops *port_vnodeops;
struct	vfs port_vfs;

extern	rctl_hndl_t rc_process_portev;
extern	rctl_hndl_t rc_project_portids;
extern	void aio_close_port(void *, int, pid_t, int);

/*
 * This table contains a list of event sources which need a static
 * association with a port (every port).
 * The last NULL entry in the table is required to detect "end of table".
 */
struct port_ksource port_ksource_tab[] = {
	{PORT_SOURCE_AIO, aio_close_port, NULL, NULL},
	{0, NULL, NULL, NULL}
};

/* local functions */
static int port_getn(port_t *, port_event_t *, uint_t, uint_t *,
    port_gettimer_t *);
static int port_sendn(int [], int [], uint_t, int, void *, uint_t *);
static int port_alert(port_t *, int, int, void *);
static int port_dispatch_event(port_t *, int, int, int, uintptr_t, void *);
static int port_send(port_t *, int, int, void *);
static int port_create(int *);
static int port_get_alert(port_alert_t *, port_event_t *);
static int port_copy_event(port_event_t *, port_kevent_t *, list_t *);
static int *port_errorn(int *, int, int, int);
static int port_noshare(void *, int *, pid_t, int, void *);
static int port_get_timeout(timespec_t *, timespec_t *, timespec_t **, int *,
    int);
static void port_init(port_t *);
static void port_remove_alert(port_queue_t *);
static void port_add_ksource_local(port_t *, port_ksource_t *);
static void port_check_return_cond(port_queue_t *);
static void port_dequeue_thread(port_queue_t *, portget_t *);
static portget_t *port_queue_thread(port_queue_t *, uint_t);
static void port_kstat_init(void);

#ifdef	_SYSCALL32_IMPL
static int port_copy_event32(port_event32_t *, port_kevent_t *, list_t *);
#endif

int
_init(void)
{
	static const fs_operation_def_t port_vfsops_template[] = {
		NULL, NULL
	};
	extern const	fs_operation_def_t port_vnodeops_template[];
	vfsops_t	*port_vfsops;
	int		error;
	major_t 	major;

	if ((major = getudev()) == (major_t)-1)
		return (ENXIO);
	portdev = makedevice(major, 0);

	/* Create a dummy vfs */
	error = vfs_makefsops(port_vfsops_template, &port_vfsops);
	if (error) {
		cmn_err(CE_WARN, "port init: bad vfs ops");
		return (error);
	}
	vfs_setops(&port_vfs, port_vfsops);
	port_vfs.vfs_flag = VFS_RDONLY;
	port_vfs.vfs_dev = portdev;
	vfs_make_fsid(&(port_vfs.vfs_fsid), portdev, 0);

	error = vn_make_ops("portfs", port_vnodeops_template, &port_vnodeops);
	if (error) {
		vfs_freevfsops(port_vfsops);
		cmn_err(CE_WARN, "port init: bad vnode ops");
		return (error);
	}

	mutex_init(&port_control.pc_mutex, NULL, MUTEX_DEFAULT, NULL);
	port_control.pc_nents = 0;	/* number of active ports */

	/* create kmem_cache for port event structures */
	port_control.pc_cache = kmem_cache_create("port_cache",
	    sizeof (port_kevent_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	port_kstat_init();		/* init port kstats */
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * System call wrapper for all port related system calls from 32-bit programs.
 */
#ifdef _SYSCALL32_IMPL
static int64_t
portfs32(uint32_t opcode, int32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
    uint32_t a4)
{
	int64_t	error;

	switch (opcode & PORT_CODE_MASK) {
	case PORT_GET:
		error = portfs(PORT_GET, a0, a1, (int)a2, (int)a3, a4);
		break;
	case PORT_SENDN:
		error = portfs(opcode, (uint32_t)a0, a1, a2, a3, a4);
		break;
	default:
		error = portfs(opcode, a0, a1, a2, a3, a4);
		break;
	}
	return (error);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * System entry point for port functions.
 * a0 is a port file descriptor (except for PORT_SENDN and PORT_CREATE).
 * The libc uses PORT_SYS_NOPORT in functions which do not deliver a
 * port file descriptor as first argument.
 */
static int64_t
portfs(int opcode, uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3,
    uintptr_t a4)
{
	rval_t		r;
	port_t		*pp;
	int 		error = 0;
	uint_t		nget;
	file_t		*fp;
	port_gettimer_t	port_timer;

	r.r_vals = 0;
	if (opcode & PORT_SYS_NOPORT) {
		opcode &= PORT_CODE_MASK;
		if (opcode == PORT_SENDN) {
			error = port_sendn((int *)a0, (int *)a1, (uint_t)a2,
			    (int)a3, (void *)a4, (uint_t *)&r.r_val1);
			if (error && (error != EIO))
				return ((int64_t)set_errno(error));
			return (r.r_vals);
		}

		if (opcode == PORT_CREATE) {
			error = port_create(&r.r_val1);
			if (error)
				return ((int64_t)set_errno(error));
			return (r.r_vals);
		}
	}

	/* opcodes using port as first argument (a0) */

	if ((fp = getf((int)a0)) == NULL)
		return ((uintptr_t)set_errno(EBADF));

	if (fp->f_vnode->v_type != VPORT) {
		releasef((int)a0);
		return ((uintptr_t)set_errno(EBADFD));
	}

	pp = VTOEP(fp->f_vnode);

	switch (opcode & PORT_CODE_MASK) {
	case	PORT_GET:
	{
		/* see PORT_GETN description */
		struct	timespec timeout;

		port_timer.pgt_flags = PORTGET_ONE;
		port_timer.pgt_loop = 0;
		port_timer.pgt_rqtp = NULL;
		if (a4 != NULL) {
			port_timer.pgt_timeout = &timeout;
			timeout.tv_sec = (time_t)a2;
			timeout.tv_nsec = (long)a3;
		} else {
			port_timer.pgt_timeout = NULL;
		}
		do {
			nget = 1;
			error = port_getn(pp, (port_event_t *)a1, 1,
			    (uint_t *)&nget, &port_timer);
		} while (nget == 0 && error == 0 && port_timer.pgt_loop);
		break;
	}
	case	PORT_GETN:
	{
		/*
		 * port_getn() can only retrieve own or shareable events from
		 * other processes. The port_getn() function remains in the
		 * kernel until own or shareable events are available or the
		 * timeout elapses.
		 */
		port_timer.pgt_flags = 0;
		port_timer.pgt_loop = 0;
		port_timer.pgt_rqtp = NULL;
		port_timer.pgt_timeout = (struct timespec *)a4;
		do {
			nget = a3;
			error = port_getn(pp, (port_event_t *)a1, (uint_t)a2,
			    (uint_t *)&nget, &port_timer);
		} while (nget == 0 && error == 0 && port_timer.pgt_loop);
		r.r_val1 = nget;
		r.r_val2 = error;
		releasef((int)a0);
		if (error && error != ETIME)
			return ((int64_t)set_errno(error));
		return (r.r_vals);
	}
	case	PORT_ASSOCIATE:
	{
		switch ((int)a1) {
		case PORT_SOURCE_FD:
			error = port_associate_fd(pp, (int)a1, (uintptr_t)a2,
			    (int)a3, (void *)a4);
			break;
		case PORT_SOURCE_FILE:
			error = port_associate_fop(pp, (int)a1, (uintptr_t)a2,
			    (int)a3, (void *)a4);
			break;
		default:
			error = EINVAL;
			break;
		}
		break;
	}
	case	PORT_SEND:
	{
		/* user-defined events */
		error = port_send(pp, PORT_SOURCE_USER, (int)a1, (void *)a2);
		break;
	}
	case	PORT_DISPATCH:
	{
		/*
		 * library events, blocking
		 * Only events of type PORT_SOURCE_AIO or PORT_SOURCE_MQ
		 * are currently allowed.
		 */
		if ((int)a1 != PORT_SOURCE_AIO && (int)a1 != PORT_SOURCE_MQ) {
			error = EINVAL;
			break;
		}
		error = port_dispatch_event(pp, (int)opcode, (int)a1, (int)a2,
		    (uintptr_t)a3, (void *)a4);
		break;
	}
	case	PORT_DISSOCIATE:
	{
		switch ((int)a1) {
		case PORT_SOURCE_FD:
			error = port_dissociate_fd(pp, (uintptr_t)a2);
			break;
		case PORT_SOURCE_FILE:
			error = port_dissociate_fop(pp, (uintptr_t)a2);
			break;
		default:
			error = EINVAL;
			break;
		}
		break;
	}
	case	PORT_ALERT:
	{
		if ((int)a2)	/* a2 = events */
			error = port_alert(pp, (int)a1, (int)a2, (void *)a3);
		else
			port_remove_alert(&pp->port_queue);
		break;
	}
	default:
		error = EINVAL;
		break;
	}

	releasef((int)a0);
	if (error)
		return ((int64_t)set_errno(error));
	return (r.r_vals);
}

/*
 * System call to create a port.
 *
 * The port_create() function creates a vnode of type VPORT per port.
 * The port control data is associated with the vnode as vnode private data.
 * The port_create() function returns an event port file descriptor.
 */
static int
port_create(int *fdp)
{
	port_t		*pp;
	vnode_t		*vp;
	struct file	*fp;
	proc_t		*p = curproc;

	/* initialize vnode and port private data */
	pp = kmem_zalloc(sizeof (port_t), KM_SLEEP);

	pp->port_vnode = vn_alloc(KM_SLEEP);
	vp = EPTOV(pp);
	vn_setops(vp, port_vnodeops);
	vp->v_type = VPORT;
	vp->v_vfsp = &port_vfs;
	vp->v_data = (caddr_t)pp;

	mutex_enter(&port_control.pc_mutex);
	/*
	 * Retrieve the maximal number of event ports allowed per system from
	 * the resource control: project.port-max-ids.
	 */
	mutex_enter(&p->p_lock);
	if (rctl_test(rc_project_portids, p->p_task->tk_proj->kpj_rctls, p,
	    port_control.pc_nents + 1, RCA_SAFE) & RCT_DENY) {
		mutex_exit(&p->p_lock);
		vn_free(vp);
		kmem_free(pp, sizeof (port_t));
		mutex_exit(&port_control.pc_mutex);
		return (EAGAIN);
	}

	/*
	 * Retrieve the maximal number of events allowed per port from
	 * the resource control: process.port-max-events.
	 */
	pp->port_max_events = rctl_enforced_value(rc_process_portev,
	    p->p_rctls, p);
	mutex_exit(&p->p_lock);

	/* allocate a new user file descriptor and a file structure */
	if (falloc(vp, 0, &fp, fdp)) {
		/*
		 * If the file table is full, free allocated resources.
		 */
		vn_free(vp);
		kmem_free(pp, sizeof (port_t));
		mutex_exit(&port_control.pc_mutex);
		return (EMFILE);
	}

	mutex_exit(&fp->f_tlock);

	pp->port_fd = *fdp;
	port_control.pc_nents++;
	p->p_portcnt++;
	port_kstat.pks_ports.value.ui32++;
	mutex_exit(&port_control.pc_mutex);

	/* initializes port private data */
	port_init(pp);
	/* set user file pointer */
	setf(*fdp, fp);
	return (0);
}

/*
 * port_init() initializes event port specific data
 */
static void
port_init(port_t *pp)
{
	port_queue_t	*portq;
	port_ksource_t	*pks;

	mutex_init(&pp->port_mutex, NULL, MUTEX_DEFAULT, NULL);
	portq = &pp->port_queue;
	mutex_init(&portq->portq_mutex, NULL, MUTEX_DEFAULT, NULL);
	pp->port_flags |= PORT_INIT;

	/*
	 * If it is not enough memory available to satisfy a user
	 * request using a single port_getn() call then port_getn()
	 * will reduce the size of the list to PORT_MAX_LIST.
	 */
	pp->port_max_list = port_max_list;

	/* Set timestamp entries required for fstat(2) requests */
	gethrestime(&pp->port_ctime);
	pp->port_uid = crgetuid(curproc->p_cred);
	pp->port_gid = crgetgid(curproc->p_cred);

	/* initialize port queue structs */
	list_create(&portq->portq_list, sizeof (port_kevent_t),
	    offsetof(port_kevent_t, portkev_node));
	list_create(&portq->portq_get_list, sizeof (port_kevent_t),
	    offsetof(port_kevent_t, portkev_node));
	portq->portq_flags = 0;
	pp->port_pid = curproc->p_pid;

	/* Allocate cache skeleton for PORT_SOURCE_FD events */
	portq->portq_pcp = kmem_zalloc(sizeof (port_fdcache_t), KM_SLEEP);
	mutex_init(&portq->portq_pcp->pc_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Allocate cache skeleton for association of event sources.
	 */
	mutex_init(&portq->portq_source_mutex, NULL, MUTEX_DEFAULT, NULL);
	portq->portq_scache = kmem_zalloc(
	    PORT_SCACHE_SIZE * sizeof (port_source_t *), KM_SLEEP);

	/*
	 * pre-associate some kernel sources with this port.
	 * The pre-association is required to create port_source_t
	 * structures for object association.
	 * Some sources can not get associated with a port before the first
	 * object association is requested. Another reason to pre_associate
	 * a particular source with a port is because of performance.
	 */

	for (pks = port_ksource_tab; pks->pks_source != 0; pks++)
		port_add_ksource_local(pp, pks);
}

/*
 * The port_add_ksource_local() function is being used to associate
 * event sources with every new port.
 * The event sources need to be added to port_ksource_tab[].
 */
static void
port_add_ksource_local(port_t *pp, port_ksource_t *pks)
{
	port_source_t	*pse;
	port_source_t	**ps;

	mutex_enter(&pp->port_queue.portq_source_mutex);
	ps = &pp->port_queue.portq_scache[PORT_SHASH(pks->pks_source)];
	for (pse = *ps; pse != NULL; pse = pse->portsrc_next) {
		if (pse->portsrc_source == pks->pks_source)
			break;
	}

	if (pse == NULL) {
		/* associate new source with the port */
		pse = kmem_zalloc(sizeof (port_source_t), KM_SLEEP);
		pse->portsrc_source = pks->pks_source;
		pse->portsrc_close = pks->pks_close;
		pse->portsrc_closearg = pks->pks_closearg;
		pse->portsrc_cnt = 1;

		pks->pks_portsrc = pse;
		if (*ps != NULL)
			pse->portsrc_next = (*ps)->portsrc_next;
		*ps = pse;
	}
	mutex_exit(&pp->port_queue.portq_source_mutex);
}

/*
 * The port_send() function sends an event of type "source" to a
 * port. This function is non-blocking. An event can be sent to
 * a port as long as the number of events per port does not achieve the
 * maximal allowed number of events. The max. number of events per port is
 * defined by the resource control process.max-port-events.
 * This function is used by the port library function port_send()
 * and port_dispatch(). The port_send(3c) function is part of the
 * event ports API and submits events of type PORT_SOURCE_USER. The
 * port_dispatch() function is project private and it is used by library
 * functions to submit events of other types than PORT_SOURCE_USER
 * (e.g. PORT_SOURCE_AIO).
 */
static int
port_send(port_t *pp, int source, int events, void *user)
{
	port_kevent_t	*pev;
	int		error;

	error = port_alloc_event_local(pp, source, PORT_ALLOC_DEFAULT, &pev);
	if (error)
		return (error);

	pev->portkev_object = 0;
	pev->portkev_events = events;
	pev->portkev_user = user;
	pev->portkev_callback = NULL;
	pev->portkev_arg = NULL;
	pev->portkev_flags = 0;

	port_send_event(pev);
	return (0);
}

/*
 * The port_noshare() function returns 0 if the current event was generated
 * by the same process. Otherwise is returns a value other than 0 and the
 * event should not be delivered to the current processe.
 * The port_noshare() function is normally used by the port_dispatch()
 * function. The port_dispatch() function is project private and can only be
 * used within the event port project.
 * Currently the libaio uses the port_dispatch() function to deliver events
 * of types PORT_SOURCE_AIO.
 */
/* ARGSUSED */
static int
port_noshare(void *arg, int *events, pid_t pid, int flag, void *evp)
{
	if (flag == PORT_CALLBACK_DEFAULT && curproc->p_pid != pid)
		return (1);
	return (0);
}

/*
 * The port_dispatch_event() function is project private and it is used by
 * libraries involved in the project to deliver events to the port.
 * port_dispatch will sleep and wait for enough resources to satisfy the
 * request, if necessary.
 * The library can specify if the delivered event is shareable with other
 * processes (see PORT_SYS_NOSHARE flag).
 */
static int
port_dispatch_event(port_t *pp, int opcode, int source, int events,
    uintptr_t object, void *user)
{
	port_kevent_t	*pev;
	int		error;

	error = port_alloc_event_block(pp, source, PORT_ALLOC_DEFAULT, &pev);
	if (error)
		return (error);

	pev->portkev_object = object;
	pev->portkev_events = events;
	pev->portkev_user = user;
	pev->portkev_arg = NULL;
	if (opcode & PORT_SYS_NOSHARE) {
		pev->portkev_flags = PORT_KEV_NOSHARE;
		pev->portkev_callback = port_noshare;
	} else {
		pev->portkev_flags = 0;
		pev->portkev_callback = NULL;
	}

	port_send_event(pev);
	return (0);
}


/*
 * The port_sendn() function is the kernel implementation of the event
 * port API function port_sendn(3c).
 * This function is able to send an event to a list of event ports.
 */
static int
port_sendn(int ports[], int errors[], uint_t nent, int events, void *user,
    uint_t *nget)
{
	port_kevent_t	*pev;
	int		errorcnt = 0;
	int		error = 0;
	int		count;
	int		port;
	int		*plist;
	int		*elist = NULL;
	file_t		*fp;
	port_t		*pp;

	if (nent == 0 || nent > port_max_list)
		return (EINVAL);

	plist = kmem_alloc(nent * sizeof (int), KM_SLEEP);
	if (copyin((void *)ports, plist, nent * sizeof (int))) {
		kmem_free(plist, nent * sizeof (int));
		return (EFAULT);
	}

	/*
	 * Scan the list for event port file descriptors and send the
	 * attached user event data embedded in a event of type
	 * PORT_SOURCE_USER to every event port in the list.
	 * If a list entry is not a valid event port then the corresponding
	 * error code will be stored in the errors[] list with the same
	 * list offset as in the ports[] list.
	 */

	for (count = 0; count < nent; count++) {
		port = plist[count];
		if ((fp = getf(port)) == NULL) {
			elist = port_errorn(elist, nent, EBADF, count);
			errorcnt++;
			continue;
		}

		pp = VTOEP(fp->f_vnode);
		if (fp->f_vnode->v_type != VPORT) {
			releasef(port);
			elist = port_errorn(elist, nent, EBADFD, count);
			errorcnt++;
			continue;
		}

		error = port_alloc_event_local(pp, PORT_SOURCE_USER,
		    PORT_ALLOC_DEFAULT, &pev);
		if (error) {
			releasef(port);
			elist = port_errorn(elist, nent, error, count);
			errorcnt++;
			continue;
		}

		pev->portkev_object = 0;
		pev->portkev_events = events;
		pev->portkev_user = user;
		pev->portkev_callback = NULL;
		pev->portkev_arg = NULL;
		pev->portkev_flags = 0;

		port_send_event(pev);
		releasef(port);
	}
	if (errorcnt) {
		error = EIO;
		if (copyout(elist, (void *)errors, nent * sizeof (int)))
			error = EFAULT;
		kmem_free(elist, nent * sizeof (int));
	}
	*nget = nent - errorcnt;
	kmem_free(plist, nent * sizeof (int));
	return (error);
}

static int *
port_errorn(int *elist, int nent, int error, int index)
{
	if (elist == NULL)
		elist = kmem_zalloc(nent * sizeof (int), KM_SLEEP);
	elist[index] = error;
	return (elist);
}

/*
 * port_alert()
 * The port_alert() funcion is a high priority event and it is always set
 * on top of the queue. It is also delivered as single event.
 * flags:
 *	- SET	:overwrite current alert data
 *	- UPDATE:set alert data or return EBUSY if alert mode is already set
 *
 * - set the ALERT flag
 * - wakeup all sleeping threads
 */
static int
port_alert(port_t *pp, int flags, int events, void *user)
{
	port_queue_t	*portq;
	portget_t	*pgetp;
	port_alert_t	*pa;

	if ((flags & PORT_ALERT_INVALID) == PORT_ALERT_INVALID)
		return (EINVAL);

	portq = &pp->port_queue;
	pa = &portq->portq_alert;
	mutex_enter(&portq->portq_mutex);

	/* check alert conditions */
	if (flags == PORT_ALERT_UPDATE) {
		if (portq->portq_flags & PORTQ_ALERT) {
			mutex_exit(&portq->portq_mutex);
			return (EBUSY);
		}
	}

	/*
	 * Store alert data in the port to be delivered to threads
	 * which are using port_get(n) to retrieve events.
	 */

	portq->portq_flags |= PORTQ_ALERT;
	pa->portal_events = events;		/* alert info */
	pa->portal_pid = curproc->p_pid;	/* process owner */
	pa->portal_object = 0;			/* no object */
	pa->portal_user = user;			/* user alert data */

	/* alert and deliver alert data to waiting threads */
	pgetp = portq->portq_thread;
	if (pgetp == NULL) {
		/* no threads waiting for events */
		mutex_exit(&portq->portq_mutex);
		return (0);
	}

	/*
	 * Set waiting threads in alert mode (PORTGET_ALERT)..
	 * Every thread waiting for events already allocated a portget_t
	 * structure to sleep on.
	 * The port alert arguments are stored in the portget_t structure.
	 * The PORTGET_ALERT flag is set to indicate the thread to return
	 * immediately with the alert event.
	 */
	do {
		if ((pgetp->portget_state & PORTGET_ALERT) == 0) {
			pa = &pgetp->portget_alert;
			pa->portal_events = events;
			pa->portal_object = 0;
			pa->portal_user = user;
			pgetp->portget_state |= PORTGET_ALERT;
			cv_signal(&pgetp->portget_cv);
		}
	} while ((pgetp = pgetp->portget_next) != portq->portq_thread);
	mutex_exit(&portq->portq_mutex);
	return (0);
}

/*
 * Clear alert state of the port
 */
static void
port_remove_alert(port_queue_t *portq)
{
	mutex_enter(&portq->portq_mutex);
	portq->portq_flags &= ~PORTQ_ALERT;
	mutex_exit(&portq->portq_mutex);
}

/*
 * The port_getn() function is used to retrieve events from a port.
 *
 * The port_getn() function returns immediately if there are enough events
 * available in the port to satisfy the request or if the port is in alert
 * mode (see port_alert(3c)).
 * The timeout argument of port_getn(3c) -which is embedded in the
 * port_gettimer_t structure- specifies if the system call should block or if it
 * should return immediately depending on the number of events available.
 * This function is internally used by port_getn(3c) as well as by
 * port_get(3c).
 */
static int
port_getn(port_t *pp, port_event_t *uevp, uint_t max, uint_t *nget,
    port_gettimer_t *pgt)
{
	port_queue_t	*portq;
	port_kevent_t 	*pev;
	port_kevent_t 	*lev;
	int		error = 0;
	uint_t		nmax;
	uint_t		nevents;
	uint_t		eventsz;
	port_event_t	*kevp;
	list_t		*glist;
	uint_t		tnent;
	int		rval;
	int		blocking = -1;
	int		timecheck;
	int		flag;
	timespec_t	rqtime;
	timespec_t	*rqtp = NULL;
	portget_t	*pgetp;
	void		*results;
	model_t		model = get_udatamodel();

	flag = pgt->pgt_flags;

	if (*nget > max && max > 0)
		return (EINVAL);

	portq = &pp->port_queue;
	mutex_enter(&portq->portq_mutex);
	if (max == 0) {
		/*
		 * Return number of objects with events.
		 * The port_block() call is required to synchronize this
		 * thread with another possible thread, which could be
		 * retrieving events from the port queue.
		 */
		port_block(portq);
		/*
		 * Check if a second thread is currently retrieving events
		 * and it is using the temporary event queue.
		 */
		if (portq->portq_tnent) {
			/* put remaining events back to the port queue */
			port_push_eventq(portq);
		}
		*nget = portq->portq_nent;
		port_unblock(portq);
		mutex_exit(&portq->portq_mutex);
		return (0);
	}

	if (uevp == NULL) {
		mutex_exit(&portq->portq_mutex);
		return (EFAULT);
	}
	if (*nget == 0) {		/* no events required */
		mutex_exit(&portq->portq_mutex);
		return (0);
	}

	/* port is being closed ... */
	if (portq->portq_flags & PORTQ_CLOSE) {
		mutex_exit(&portq->portq_mutex);
		return (EBADFD);
	}

	/* return immediately if port in alert mode */
	if (portq->portq_flags & PORTQ_ALERT) {
		error = port_get_alert(&portq->portq_alert, uevp);
		if (error == 0)
			*nget = 1;
		mutex_exit(&portq->portq_mutex);
		return (error);
	}

	portq->portq_thrcnt++;

	/*
	 * Now check if the completed events satisfy the
	 * "wait" requirements of the current thread:
	 */

	if (pgt->pgt_loop) {
		/*
		 * loop entry of same thread
		 * pgt_loop is set when the current thread returns
		 * prematurely from this function. That could happen
		 * when a port is being shared between processes and
		 * this thread could not find events to return.
		 * It is not allowed to a thread to retrieve non-shareable
		 * events generated in other processes.
		 * PORTQ_WAIT_EVENTS is set when a thread already
		 * checked the current event queue and no new events
		 * are added to the queue.
		 */
		if (((portq->portq_flags & PORTQ_WAIT_EVENTS) == 0) &&
		    (portq->portq_nent >= *nget)) {
			/* some new events arrived ...check them */
			goto portnowait;
		}
		rqtp = pgt->pgt_rqtp;
		timecheck = pgt->pgt_timecheck;
		pgt->pgt_flags |= PORTGET_WAIT_EVENTS;
	} else {
		/* check if enough events are available ... */
		if (portq->portq_nent >= *nget)
			goto portnowait;
		/*
		 * There are not enough events available to satisfy
		 * the request, check timeout value and wait for
		 * incoming events.
		 */
		error = port_get_timeout(pgt->pgt_timeout, &rqtime, &rqtp,
		    &blocking, flag);
		if (error) {
			port_check_return_cond(portq);
			mutex_exit(&portq->portq_mutex);
			return (error);
		}

		if (blocking == 0) /* don't block, check fired events */
			goto portnowait;

		if (rqtp != NULL) {
			timespec_t	now;
			timecheck = timechanged;
			gethrestime(&now);
			timespecadd(rqtp, &now);
		}
	}

	/* enqueue thread in the list of waiting threads */
	pgetp = port_queue_thread(portq, *nget);


	/* Wait here until return conditions met */
	for (;;) {
		if (pgetp->portget_state & PORTGET_ALERT) {
			/* reap alert event and return */
			error = port_get_alert(&pgetp->portget_alert, uevp);
			if (error)
				*nget = 0;
			else
				*nget = 1;
			port_dequeue_thread(&pp->port_queue, pgetp);
			portq->portq_thrcnt--;
			mutex_exit(&portq->portq_mutex);
			return (error);
		}

		/*
		 * Check if some other thread is already retrieving
		 * events (portq_getn > 0).
		 */

		if ((portq->portq_getn  == 0) &&
		    ((portq)->portq_nent >= *nget) &&
		    (!((pgt)->pgt_flags & PORTGET_WAIT_EVENTS) ||
		    !((portq)->portq_flags & PORTQ_WAIT_EVENTS)))
			break;

		if (portq->portq_flags & PORTQ_CLOSE) {
			error = EBADFD;
			break;
		}

		rval = cv_waituntil_sig(&pgetp->portget_cv, &portq->portq_mutex,
		    rqtp, timecheck);

		if (rval <= 0) {
			error = (rval == 0) ? EINTR : ETIME;
			break;
		}
	}

	/* take thread out of the wait queue */
	port_dequeue_thread(portq, pgetp);

	if (error != 0 && (error == EINTR || error == EBADFD ||
	    (error == ETIME && flag))) {
		/* return without events */
		port_check_return_cond(portq);
		mutex_exit(&portq->portq_mutex);
		return (error);
	}

portnowait:
	/*
	 * Move port event queue to a temporary event queue .
	 * New incoming events will be continue be posted to the event queue
	 * and they will not be considered by the current thread.
	 * The idea is to avoid lock contentions or an often locking/unlocking
	 * of the port queue mutex. The contention and performance degradation
	 * could happen because:
	 * a) incoming events use the port queue mutex to enqueue new events and
	 * b) before the event can be delivered to the application it is
	 *    necessary to notify the event sources about the event delivery.
	 *    Sometimes the event sources can require a long time to return and
	 *    the queue mutex would block incoming events.
	 * During this time incoming events (port_send_event()) do not need
	 * to awake threads waiting for events. Before the current thread
	 * returns it will check the conditions to awake other waiting threads.
	 */
	portq->portq_getn++;	/* number of threads retrieving events */
	port_block(portq);	/* block other threads here */
	nmax = max < portq->portq_nent ? max : portq->portq_nent;

	if (portq->portq_tnent) {
		/*
		 * Move remaining events from previous thread back to the
		 * port event queue.
		 */
		port_push_eventq(portq);
	}
	/* move port event queue to a temporary queue */
	list_move_tail(&portq->portq_get_list, &portq->portq_list);
	glist = &portq->portq_get_list;	/* use temporary event queue */
	tnent = portq->portq_nent;	/* get current number of events */
	portq->portq_nent = 0;		/* no events in the port event queue */
	portq->portq_flags |= PORTQ_WAIT_EVENTS; /* detect incoming events */
	mutex_exit(&portq->portq_mutex);    /* event queue can be reused now */

	if (model == DATAMODEL_NATIVE) {
		eventsz = sizeof (port_event_t);
		kevp = kmem_alloc(eventsz * nmax, KM_NOSLEEP);
		if (kevp == NULL) {
			if (nmax > pp->port_max_list)
				nmax = pp->port_max_list;
			kevp = kmem_alloc(eventsz * nmax, KM_SLEEP);
		}
		results = kevp;
		lev = NULL;	/* start with first event in the queue */
		for (nevents = 0; nevents < nmax; ) {
			pev = port_get_kevent(glist, lev);
			if (pev == NULL)	/* no more events available */
				break;
			if (pev->portkev_flags & PORT_KEV_FREE) {
				/* Just discard event */
				list_remove(glist, pev);
				pev->portkev_flags &= ~(PORT_CLEANUP_DONE);
				if (PORT_FREE_EVENT(pev))
					port_free_event_local(pev, 0);
				tnent--;
				continue;
			}

			/* move event data to copyout list */
			if (port_copy_event(&kevp[nevents], pev, glist)) {
				/*
				 * Event can not be delivered to the
				 * current process.
				 */
				if (lev != NULL)
					list_insert_after(glist, lev, pev);
				else
					list_insert_head(glist, pev);
				lev = pev;  /* last checked event */
			} else {
				nevents++;	/* # of events ready */
			}
		}
#ifdef	_SYSCALL32_IMPL
	} else {
		port_event32_t	*kevp32;

		eventsz = sizeof (port_event32_t);
		kevp32 = kmem_alloc(eventsz * nmax, KM_NOSLEEP);
		if (kevp32 == NULL) {
			if (nmax > pp->port_max_list)
				nmax = pp->port_max_list;
			kevp32 = kmem_alloc(eventsz * nmax, KM_SLEEP);
		}
		results = kevp32;
		lev = NULL;	/* start with first event in the queue */
		for (nevents = 0; nevents < nmax; ) {
			pev = port_get_kevent(glist, lev);
			if (pev == NULL)	/* no more events available */
				break;
			if (pev->portkev_flags & PORT_KEV_FREE) {
				/* Just discard event */
				list_remove(glist, pev);
				pev->portkev_flags &= ~(PORT_CLEANUP_DONE);
				if (PORT_FREE_EVENT(pev))
					port_free_event_local(pev, 0);
				tnent--;
				continue;
			}

			/* move event data to copyout list */
			if (port_copy_event32(&kevp32[nevents], pev, glist)) {
				/*
				 * Event can not be delivered to the
				 * current process.
				 */
				if (lev != NULL)
					list_insert_after(glist, lev, pev);
				else
					list_insert_head(glist, pev);
				lev = pev;  /* last checked event */
			} else {
				nevents++;	/* # of events ready */
			}
		}
#endif	/* _SYSCALL32_IMPL */
	}

	/*
	 *  Remember number of remaining events in the temporary event queue.
	 */
	portq->portq_tnent = tnent - nevents;

	/*
	 * Work to do before return :
	 * - push list of remaining events back to the top of the standard
	 *   port queue.
	 * - if this is the last thread calling port_get(n) then wakeup the
	 *   thread waiting on close(2).
	 * - check for a deferred cv_signal from port_send_event() and wakeup
	 *   the sleeping thread.
	 */

	mutex_enter(&portq->portq_mutex);
	port_unblock(portq);
	if (portq->portq_tnent) {
		/*
		 * move remaining events in the temporary event queue back
		 * to the port event queue
		 */
		port_push_eventq(portq);
	}
	portq->portq_getn--;	/* update # of threads retrieving events */
	if (--portq->portq_thrcnt == 0) { /* # of threads waiting ... */
		/* Last thread => check close(2) conditions ... */
		if (portq->portq_flags & PORTQ_CLOSE) {
			cv_signal(&portq->portq_closecv);
			mutex_exit(&portq->portq_mutex);
			kmem_free(results, eventsz * nmax);
			/* do not copyout events */
			*nget = 0;
			return (EBADFD);
		}
	} else if (portq->portq_getn == 0) {
		/*
		 * no other threads retrieving events ...
		 * check wakeup conditions of sleeping threads
		 */
		if ((portq->portq_thread != NULL) &&
		    (portq->portq_nent >= portq->portq_nget))
			cv_signal(&portq->portq_thread->portget_cv);
	}

	/*
	 * Check PORTQ_POLLIN here because the current thread set temporarily
	 * the number of events in the queue to zero.
	 */
	if (portq->portq_flags & PORTQ_POLLIN) {
		portq->portq_flags &= ~PORTQ_POLLIN;
		mutex_exit(&portq->portq_mutex);
		pollwakeup(&pp->port_pollhd, POLLIN);
	} else {
		mutex_exit(&portq->portq_mutex);
	}

	/* now copyout list of user event structures to user space */
	if (nevents) {
		if (copyout(results, uevp, nevents * eventsz))
			error = EFAULT;
	}
	kmem_free(results, eventsz * nmax);

	if (nevents == 0 && error == 0 && pgt->pgt_loop == 0 && blocking != 0) {
		/* no events retrieved: check loop conditions */
		if (blocking == -1) {
			/* no timeout checked */
			error = port_get_timeout(pgt->pgt_timeout,
			    &pgt->pgt_rqtime, &rqtp, &blocking, flag);
			if (error) {
				*nget = nevents;
				return (error);
			}
			if (rqtp != NULL) {
				timespec_t	now;
				pgt->pgt_timecheck = timechanged;
				gethrestime(&now);
				timespecadd(&pgt->pgt_rqtime, &now);
			}
			pgt->pgt_rqtp = rqtp;
		} else {
			/* timeout already checked -> remember values */
			pgt->pgt_rqtp = rqtp;
			if (rqtp != NULL) {
				pgt->pgt_timecheck = timecheck;
				pgt->pgt_rqtime = *rqtp;
			}
		}
		if (blocking)
			/* timeout remaining */
			pgt->pgt_loop = 1;
	}

	/* set number of user event structures completed */
	*nget = nevents;
	return (error);
}

/*
 * 1. copy kernel event structure to user event structure.
 * 2. PORT_KEV_WIRED event structures will be reused by the "source"
 * 3. Remove PORT_KEV_DONEQ flag (event removed from the event queue)
 * 4. Other types of event structures can be delivered back to the port cache
 *    (port_free_event_local()).
 * 5. The event source callback function is the last opportunity for the
 *    event source to update events, to free local resources associated with
 *    the event or to deny the delivery of the event.
 */
static int
port_copy_event(port_event_t *puevp, port_kevent_t *pkevp, list_t *list)
{
	int	free_event = 0;
	int	flags;
	int	error;

	puevp->portev_source = pkevp->portkev_source;
	puevp->portev_object = pkevp->portkev_object;
	puevp->portev_user = pkevp->portkev_user;
	puevp->portev_events = pkevp->portkev_events;

	/* remove event from the queue */
	list_remove(list, pkevp);

	/*
	 * Events of type PORT_KEV_WIRED remain allocated by the
	 * event source.
	 */
	flags = pkevp->portkev_flags;
	if (pkevp->portkev_flags & PORT_KEV_WIRED)
		pkevp->portkev_flags &= ~PORT_KEV_DONEQ;
	else
		free_event = 1;

	if (pkevp->portkev_callback) {
		error = (*pkevp->portkev_callback)(pkevp->portkev_arg,
		    &puevp->portev_events, pkevp->portkev_pid,
		    PORT_CALLBACK_DEFAULT, pkevp);

		if (error) {
			/*
			 * Event can not be delivered.
			 * Caller must reinsert the event into the queue.
			 */
			pkevp->portkev_flags = flags;
			return (error);
		}
	}
	if (free_event)
		port_free_event_local(pkevp, 0);
	return (0);
}

#ifdef	_SYSCALL32_IMPL
/*
 * 1. copy kernel event structure to user event structure.
 * 2. PORT_KEV_WIRED event structures will be reused by the "source"
 * 3. Remove PORT_KEV_DONEQ flag (event removed from the event queue)
 * 4. Other types of event structures can be delivered back to the port cache
 *    (port_free_event_local()).
 * 5. The event source callback function is the last opportunity for the
 *    event source to update events, to free local resources associated with
 *    the event or to deny the delivery of the event.
 */
static int
port_copy_event32(port_event32_t *puevp, port_kevent_t *pkevp, list_t *list)
{
	int	free_event = 0;
	int	error;
	int	flags;

	puevp->portev_source = pkevp->portkev_source;
	puevp->portev_object = (daddr32_t)pkevp->portkev_object;
	puevp->portev_user = (caddr32_t)(uintptr_t)pkevp->portkev_user;
	puevp->portev_events = pkevp->portkev_events;

	/* remove event from the queue */
	list_remove(list, pkevp);

	/*
	 * Events if type PORT_KEV_WIRED remain allocated by the
	 * sub-system (source).
	 */

	flags = pkevp->portkev_flags;
	if (pkevp->portkev_flags & PORT_KEV_WIRED)
		pkevp->portkev_flags &= ~PORT_KEV_DONEQ;
	else
		free_event = 1;

	if (pkevp->portkev_callback != NULL) {
		error = (*pkevp->portkev_callback)(pkevp->portkev_arg,
		    &puevp->portev_events, pkevp->portkev_pid,
		    PORT_CALLBACK_DEFAULT, pkevp);
		if (error) {
			/*
			 * Event can not be delivered.
			 * Caller must reinsert the event into the queue.
			 */
			pkevp->portkev_flags = flags;
			return (error);
		}
	}
	if (free_event)
		port_free_event_local(pkevp, 0);
	return (0);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * copyout alert event.
 */
static int
port_get_alert(port_alert_t *pa, port_event_t *uevp)
{
	model_t	model = get_udatamodel();

	/* copyout alert event structures to user space */
	if (model == DATAMODEL_NATIVE) {
		port_event_t	uev;
		uev.portev_source = PORT_SOURCE_ALERT;
		uev.portev_object = pa->portal_object;
		uev.portev_events = pa->portal_events;
		uev.portev_user = pa->portal_user;
		if (copyout(&uev, uevp, sizeof (port_event_t)))
			return (EFAULT);
#ifdef	_SYSCALL32_IMPL
	} else {
		port_event32_t	uev32;
		uev32.portev_source = PORT_SOURCE_ALERT;
		uev32.portev_object = (daddr32_t)pa->portal_object;
		uev32.portev_events = pa->portal_events;
		uev32.portev_user = (daddr32_t)(uintptr_t)pa->portal_user;
		if (copyout(&uev32, uevp, sizeof (port_event32_t)))
			return (EFAULT);
#endif	/* _SYSCALL32_IMPL */
	}
	return (0);
}

/*
 * Check return conditions :
 * - pending port close(2)
 * - threads waiting for events
 */
static void
port_check_return_cond(port_queue_t *portq)
{
	ASSERT(MUTEX_HELD(&portq->portq_mutex));
	portq->portq_thrcnt--;
	if (portq->portq_flags & PORTQ_CLOSE) {
		if (portq->portq_thrcnt == 0)
			cv_signal(&portq->portq_closecv);
		else
			cv_signal(&portq->portq_thread->portget_cv);
	}
}

/*
 * The port_get_kevent() function returns
 * - the event located at the head of the queue if 'last' pointer is NULL
 * - the next event after the event pointed by 'last'
 * The caller of this function is responsible for the integrity of the queue
 * in use:
 * - port_getn() is using a temporary queue protected with port_block().
 * - port_close_events() is working on the global event queue and protects
 *   the queue with portq->portq_mutex.
 */
port_kevent_t *
port_get_kevent(list_t *list, port_kevent_t *last)
{
	if (last == NULL)
		return (list_head(list));
	else
		return (list_next(list, last));
}

/*
 * The port_get_timeout() function gets the timeout data from user space
 * and converts that info into a corresponding internal representation.
 * The kerneldata flag means that the timeout data is already loaded.
 */
static int
port_get_timeout(timespec_t *timeout, timespec_t *rqtime, timespec_t **rqtp,
    int *blocking, int kerneldata)
{
	model_t	model = get_udatamodel();

	*rqtp = NULL;
	if (timeout == NULL) {
		*blocking = 1;
		return (0);
	}

	if (kerneldata) {
		*rqtime = *timeout;
	} else {
		if (model == DATAMODEL_NATIVE) {
			if (copyin(timeout, rqtime, sizeof (*rqtime)))
				return (EFAULT);
#ifdef	_SYSCALL32_IMPL
		} else {
			timespec32_t 	wait_time_32;
			if (copyin(timeout, &wait_time_32,
			    sizeof (wait_time_32)))
				return (EFAULT);
			TIMESPEC32_TO_TIMESPEC(rqtime, &wait_time_32);
#endif  /* _SYSCALL32_IMPL */
		}
	}

	if (rqtime->tv_sec == 0 && rqtime->tv_nsec == 0) {
		*blocking = 0;
		return (0);
	}

	if (rqtime->tv_sec < 0 ||
	    rqtime->tv_nsec < 0 || rqtime->tv_nsec >= NANOSEC)
		return (EINVAL);

	*rqtp = rqtime;
	*blocking = 1;
	return (0);
}

/*
 * port_queue_thread()
 * Threads requiring more events than available will be put in a wait queue.
 * There is a "thread wait queue" per port.
 * Threads requiring less events get a higher priority than others and they
 * will be awoken first.
 */
static portget_t *
port_queue_thread(port_queue_t *portq, uint_t nget)
{
	portget_t	*pgetp;
	portget_t	*ttp;
	portget_t	*htp;

	pgetp = kmem_zalloc(sizeof (portget_t), KM_SLEEP);
	pgetp->portget_nget = nget;
	pgetp->portget_pid = curproc->p_pid;
	if (portq->portq_thread == NULL) {
		/* first waiting thread */
		portq->portq_thread = pgetp;
		portq->portq_nget = nget;
		pgetp->portget_prev = pgetp;
		pgetp->portget_next = pgetp;
		return (pgetp);
	}

	/*
	 * thread waiting for less events will be set on top of the queue.
	 */
	ttp = portq->portq_thread;
	htp = ttp;
	for (;;) {
		if (nget <= ttp->portget_nget)
			break;
		if (htp == ttp->portget_next)
			break;	/* last event */
		ttp = ttp->portget_next;
	}

	/* add thread to the queue */
	pgetp->portget_next = ttp;
	pgetp->portget_prev = ttp->portget_prev;
	ttp->portget_prev->portget_next = pgetp;
	ttp->portget_prev = pgetp;
	if (portq->portq_thread == ttp)
		portq->portq_thread = pgetp;
	portq->portq_nget = portq->portq_thread->portget_nget;
	return (pgetp);
}

/*
 * Take thread out of the queue.
 */
static void
port_dequeue_thread(port_queue_t *portq, portget_t *pgetp)
{
	if (pgetp->portget_next == pgetp) {
		/* last (single) waiting thread */
		portq->portq_thread = NULL;
		portq->portq_nget = 0;
	} else {
		pgetp->portget_prev->portget_next = pgetp->portget_next;
		pgetp->portget_next->portget_prev = pgetp->portget_prev;
		if (portq->portq_thread == pgetp)
			portq->portq_thread = pgetp->portget_next;
		portq->portq_nget = portq->portq_thread->portget_nget;
	}
	kmem_free(pgetp, sizeof (portget_t));
}

/*
 * Set up event port kstats.
 */
static void
port_kstat_init()
{
	kstat_t	*ksp;
	uint_t	ndata;

	ndata = sizeof (port_kstat) / sizeof (kstat_named_t);
	ksp = kstat_create("portfs", 0, "Event Ports", "misc",
	    KSTAT_TYPE_NAMED, ndata, KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = &port_kstat;
		kstat_install(ksp);
	}
}
