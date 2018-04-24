/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PCMCIA Card Services
 *	The PCMCIA Card Services is a loadable module which
 *	presents the Card Services interface to client device
 *	drivers.
 *
 *	Card Services uses Socket Services-like calls into the
 *	PCMCIA nexus driver to manipulate socket and adapter
 *	resources.
 *
 * Note that a bunch of comments are not indented correctly with the
 *	code that they are commenting on. This is because cstyle is
 *	is inflexible concerning 4-column indenting.
 */

#if defined(DEBUG)
#define	CS_DEBUG
#endif

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/autoconf.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/varargs.h>
#include <sys/var.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/utsname.h>
#include <sys/vtrace.h>
#include <sys/kstat.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/callb.h>
#include <sys/time.h>

#include <sys/pctypes.h>
#include <pcmcia/sys/cs_types.h>
#include <sys/pcmcia.h>
#include <sys/sservice.h>
#include <pcmcia/sys/cis.h>
#include <pcmcia/sys/cis_handlers.h>
#include <pcmcia/sys/cs.h>
#include <pcmcia/sys/cs_priv.h>
#include <pcmcia/sys/cs_stubs.h>

/*
 * The cs_strings header file is where all of the major strings that
 *	Card Services uses are located.
 */
#include <pcmcia/sys/cs_strings.h>


/*
 * Function declarations
 *
 * The main Card Services entry point
 */
int CardServices(int function, ...);

/*
 * functions and globals used by Socket Services
 *
 * WAS: void *(*cis_parser)(int, ...) = NULL;
 */
void *(*cis_parser)(int, ...) = NULL;
csfunction_t *cs_socket_services = NULL;

/*
 * event handling functions
 */
static event_t ss_to_cs_events(cs_socket_t *, event_t);
static event_t cs_cse2sbm(event_t);
static void cs_event_thread(uint32_t);
static int cs_card_insertion(cs_socket_t *, event_t);
static int cs_card_removal(cs_socket_t *);
static void cs_ss_thread(uint32_t);
void cs_ready_timeout(void *);
static int cs_card_for_client(client_t *);
static int cs_request_socket_mask(client_handle_t, request_socket_mask_t *);
static int cs_release_socket_mask(client_handle_t, release_socket_mask_t *);
static int cs_get_event_mask(client_handle_t, sockevent_t *);
static int cs_set_event_mask(client_handle_t, sockevent_t *);
static int cs_event2text(event2text_t *, int);
static int cs_read_event_status(cs_socket_t *, client_t *, event_t *,
						get_ss_status_t *, int);
uint32_t cs_socket_event_softintr(caddr_t);
void cs_event_softintr_timeout(void *);
static int cs_get_status(client_handle_t, get_status_t *);
static uint32_t cs_sbm2cse(uint32_t);
static unsigned cs_merge_event_masks(cs_socket_t *, client_t *);
static int cs_set_socket_event_mask(cs_socket_t *, unsigned);

/*
 * SS<->CS communication and internal socket and window  handling functions
 */
static uint32_t cs_add_socket(uint32_t);
static uint32_t cs_drop_socket(uint32_t);
static cs_socket_t *cs_get_sp(uint32_t);
static cs_socket_t *cs_find_sp(uint32_t);
static cs_window_t *cs_get_wp(uint32_t);
static cs_window_t *cs_find_wp(uint32_t);
static int cs_add_windows(int, uint32_t);
static uint32_t cs_ss_init();
static void cs_set_acc_attributes(set_window_t *, uint32_t);

/*
 * CIS handling functions
 */
cistpl_callout_t *cis_cistpl_std_callout;
static int cs_parse_tuple(client_handle_t,  tuple_t *, cisparse_t *, cisdata_t);
static int cs_get_tuple_data(client_handle_t, tuple_t *);
static int cs_validate_cis(client_handle_t, cisinfo_t *);
static int cs_get_firstnext_tuple(client_handle_t, tuple_t *, uint32_t);
static int cs_create_cis(cs_socket_t *);
static int cs_destroy_cis(cs_socket_t *);

/*
 * client handling functions
 */
unsigned cs_create_next_client_minor(unsigned, unsigned);
static client_t *cs_find_client(client_handle_t, int *);
static client_handle_t cs_create_client_handle(unsigned, client_t *);
static int cs_destroy_client_handle(client_handle_t);
static int cs_register_client(client_handle_t *, client_reg_t *);
static int cs_deregister_client(client_handle_t);
static int cs_deregister_mtd(client_handle_t);
static void cs_clear_superclient_lock(int);
static int cs_add_client_to_socket(unsigned, client_handle_t *,
						client_reg_t *, int);
static int cs_get_client_info(client_handle_t, client_info_t *);
static int cs_get_firstnext_client(get_firstnext_client_t *, uint32_t);

/*
 * window handling functions
 */
static int cs_request_window(client_handle_t, window_handle_t *, win_req_t *);
static int cs_release_window(window_handle_t);
static int cs_modify_window(window_handle_t, modify_win_t *);
static int cs_modify_mem_window(window_handle_t, modify_win_t *, win_req_t *,
									int);
static int cs_map_mem_page(window_handle_t, map_mem_page_t *);
static int cs_find_mem_window(uint32_t, win_req_t *, uint32_t *);
static int cs_memwin_space_and_map_ok(inquire_window_t *, win_req_t *);
static int cs_valid_window_speed(inquire_window_t *, uint32_t);
static window_handle_t cs_create_window_handle(uint32_t);
static cs_window_t *cs_find_window(window_handle_t);
static int cs_find_io_win(uint32_t, iowin_char_t *, uint32_t *, uint32_t *);

/*
 * IO, IRQ and configuration handling functions
 */
static int cs_request_io(client_handle_t, io_req_t *);
static int cs_release_io(client_handle_t, io_req_t *);
static int cs_allocate_io_win(uint32_t, uint32_t, uint32_t *);
static int cs_setup_io_win(uint32_t, uint32_t, baseaddru_t *,
					uint32_t *, uint32_t, uint32_t);
static int cs_request_irq(client_handle_t, irq_req_t *);
static int cs_release_irq(client_handle_t, irq_req_t *);
static int cs_request_configuration(client_handle_t, config_req_t *);
static int cs_release_configuration(client_handle_t, release_config_t *);
static int cs_modify_configuration(client_handle_t, modify_config_t *);
static int cs_access_configuration_register(client_handle_t,
						access_config_reg_t *);

/*
 * RESET and general info functions
 */
static int cs_reset_function(client_handle_t, reset_function_t *);
static int cs_get_configuration_info(client_handle_t *,
						get_configuration_info_t *);
static int cs_get_cardservices_info(client_handle_t,
						get_cardservices_info_t *);
static int cs_get_physical_adapter_info(client_handle_t,
						get_physical_adapter_info_t *);

/*
 * general functions
 */
static uint32_t cs_get_socket(client_handle_t, uint32_t *, uint32_t *,
					cs_socket_t **, client_t **);
static int cs_convert_speed(convert_speed_t *);
static int cs_convert_size(convert_size_t *);
static char *cs_error2text(int, int);
static int cs_map_log_socket(client_handle_t, map_log_socket_t *);
static int cs_convert_powerlevel(uint32_t, uint32_t, uint32_t, unsigned *);
static int cs_make_device_node(client_handle_t, make_device_node_t *);
static int cs_remove_device_node(client_handle_t, remove_device_node_t *);
static int cs_ddi_info(cs_ddi_info_t *);
static int cs_init_cis_window(cs_socket_t *, uint32_t *, acc_handle_t *,
				uint32_t);
static int cs_sys_ctl(cs_sys_ctl_t *);

/*
 * global variables
 */
static int cs_max_client_handles = CS_MAX_CLIENTS;
static client_t cs_socket_services_client;	/* global SS client */
static client_types_t client_types[MAX_CLIENT_TYPES];
static cs_globals_t cs_globals;
int cs_reset_timeout_time = RESET_TIMEOUT_TIME;
int cs_rc1_delay = CS_RC1_DELAY;
int cs_rc2_delay = CS_RC2_DELAY;
int cs_rq_delay = CS_RQ_DELAY;

#ifdef	CS_DEBUG
int	cs_debug = 0;
#endif

/*
 * cs_init - Initialize CS internal structures, databases, and state,
 *		and register with SS
 *
 * XXX - Need to make sure that if we fail at any point that we free
 *		any resources that we allocated, as well as kill any
 *		threads that may have been started.
 */
int
cs_init()
{
	client_types_t *ct;
	client_t *client;

	/*
	 * Initialize the CS global structure
	 */
	bzero((caddr_t)&cs_globals, sizeof (cs_globals_t));

	mutex_init(&cs_globals.global_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&cs_globals.window_lock, NULL, MUTEX_DRIVER, NULL);

	cs_globals.init_state = GLOBAL_INIT_STATE_MUTEX;

	/*
	 * Set up the global Socket Services client, since we're going to
	 *	need it once we register with SS.
	 */
	client = &cs_socket_services_client;
	bzero((caddr_t)client, sizeof (client_t));
	client->client_handle = CS_SS_CLIENT_HANDLE;
	client->flags |= (INFO_SOCKET_SERVICES | CLIENT_CARD_INSERTED);

	/*
	 * Setup the client type structure - this is used in the socket event
	 *	thread to sequence the delivery of events to all clients on
	 *	the socket.
	 */
	ct = &client_types[0];
	ct->type = INFO_IO_CLIENT;
	ct->order = CLIENT_EVENTS_LIFO;
	ct->next = &client_types[1];

	ct = ct->next;
	ct->type = INFO_MTD_CLIENT;
	ct->order = CLIENT_EVENTS_FIFO;
	ct->next = &client_types[2];

	ct = ct->next;
	ct->type = INFO_MEM_CLIENT;
	ct->order = CLIENT_EVENTS_FIFO;
	ct->next = NULL;

	return (CS_SUCCESS);
}

/*
 * cs_deinit - Deinitialize CS
 *
 * This function cleans up any allocated resources, stops any running threads,
 *	destroys any mutexes and condition variables, and finally frees up the
 *	global socket and window structure arrays.
 */
int
cs_deinit()
{
	cs_socket_t *sp;
	int sn, have_clients = 0, have_sockets = 0;
	cs_register_cardservices_t rcs;

#if defined(CS_DEBUG)
	if (cs_debug > 1)
	    cmn_err(CE_CONT, "CS: cs_deinit\n");
#endif

	/*
	 * Deregister with the Card Services kernel stubs module
	 */
	rcs.magic = CS_STUBS_MAGIC;
	rcs.function = CS_ENTRY_DEREGISTER;
	(void) csx_register_cardservices(&rcs);

	/*
	 * Set the GLOBAL_INIT_STATE_NO_CLIENTS flag to prevent new clients
	 *	from registering.
	 */
	mutex_enter(&cs_globals.global_lock);
	cs_globals.init_state |= GLOBAL_INIT_STATE_NO_CLIENTS;
	mutex_exit(&cs_globals.global_lock);

	/*
	 * Go through each socket and make sure that there are no clients
	 *	on any of the sockets.  If there are, we can't deinit until
	 *	all the clients for every socket are gone.
	 */
	for (sn = 0; sn < cs_globals.max_socket_num; sn++) {
	    if ((sp = cs_get_sp(sn)) != NULL) {
		have_sockets++;
		if (sp->client_list) {
		    cmn_err(CE_CONT, "cs_deinit: cannot unload module since "
				"socket %d has registered clients\n", sn);
		    have_clients++;
		}
	    }
	}

	/*
	 * We don't allow unload if there are any clients registered
	 *	or if there are still sockets that are active.
	 */
	if ((have_clients > 0) || (have_sockets > 0))
	    return (BAD_FUNCTION);

#ifdef	XXX
	/*
	 * If one or more sockets have been added, we need to deallocate
	 *	the resources associated with those sockets.
	 */

	/*
	 * First, tell Socket Services that we're leaving, so that we
	 *	don't get any more event callbacks.
	 */
	SocketServices(CSUnregister);

	/*
	 * Wait for the soft int timer to tell us it's done
	 */
	mutex_enter(&cs_globals.global_lock);
	cs_globals.init_state |= GLOBAL_INIT_STATE_UNLOADING;
	mutex_exit(&cs_globals.global_lock);
	UNTIMEOUT(cs_globals.sotfint_tmo);

	/*
	 * Remove the soft interrupt handler.
	 */
	mutex_enter(&cs_globals.global_lock);
	if (cs_globals.init_state & GLOBAL_INIT_STATE_SOFTINTR) {
	    ddi_remove_softintr(cs_globals.softint_id);
	    cs_globals.init_state &= ~GLOBAL_INIT_STATE_SOFTINTR;
	}
	mutex_exit(&cs_globals.global_lock);

	return (CS_SUCCESS);

	/*
	 * Go through each socket and free any resource allocated to that
	 *	socket, as well as any mutexs and condition variables.
	 */
	for (sn = 0; sn < cs_globals.max_socket_num; sn++) {
	    set_socket_t set_socket;

	    if ((sp = cs_get_sp(sn)) != NULL) {

		/*
		 * untimeout possible pending ready/busy timer
		 */
		UNTIMEOUT(sp->rdybsy_tmo_id);

		if (sp->init_state & SOCKET_INIT_STATE_MUTEX)
		    mutex_enter(&sp->lock);
		sp->flags = SOCKET_UNLOAD_MODULE;
		if (sp->init_state & SOCKET_INIT_STATE_SOFTINTR)
		    sp->init_state &= ~SOCKET_INIT_STATE_SOFTINTR;
		if (sp->init_state & SOCKET_INIT_STATE_MUTEX)
		    mutex_exit(&sp->lock);

		if (sp->init_state & SOCKET_INIT_STATE_MUTEX)
		    mutex_enter(&sp->cis_lock);
		(void) cs_destroy_cis(sp);
		if (sp->init_state & SOCKET_INIT_STATE_MUTEX)
		    mutex_exit(&sp->cis_lock);

		/*
		 * Tell the event handler thread that we want it to exit, then
		 *	wait around until it tells us that it has exited.
		 */
		if (sp->init_state & SOCKET_INIT_STATE_MUTEX)
		    mutex_enter(&sp->client_lock);
		if (sp->init_state & SOCKET_INIT_STATE_THREAD) {
		    sp->thread_state = SOCKET_THREAD_EXIT;
		    cv_broadcast(&sp->thread_cv);
		    cv_wait(&sp->caller_cv, &sp->client_lock);
		}
		if (sp->init_state & SOCKET_INIT_STATE_MUTEX)
		    mutex_exit(&sp->client_lock);

		/*
		 * Tell the SS work thread that we want it to exit, then
		 *	wait around until it tells us that it has exited.
		 */
		if (sp->init_state & SOCKET_INIT_STATE_MUTEX)
		    mutex_enter(&sp->ss_thread_lock);
		if (sp->init_state & SOCKET_INIT_STATE_SS_THREAD) {
		    sp->ss_thread_state = SOCKET_THREAD_EXIT;
		    cv_broadcast(&sp->ss_thread_cv);
		    cv_wait(&sp->ss_caller_cv, &sp->ss_thread_lock);
		}

		if (sp->init_state & SOCKET_INIT_STATE_MUTEX)
		    mutex_exit(&sp->ss_thread_lock);

		/*
		 * Free the mutexii and condition variables that we used.
		 */
		if (sp->init_state & SOCKET_INIT_STATE_MUTEX) {
		    mutex_destroy(&sp->lock);
		    mutex_destroy(&sp->client_lock);
		    mutex_destroy(&sp->cis_lock);
		    mutex_destroy(&sp->ss_thread_lock);
		}

		if (sp->init_state & SOCKET_INIT_STATE_CV) {
		    cv_destroy(&sp->thread_cv);
		    cv_destroy(&sp->caller_cv);
		    cv_destroy(&sp->reset_cv);
		    cv_destroy(&sp->ss_thread_cv);
		    cv_destroy(&sp->ss_caller_cv);
		}

#ifdef	USE_IOMMAP_WINDOW
		/*
		 * Free the memory-mapped IO structure if we allocated one.
		 */
		if (sp->io_mmap_window)
		    kmem_free(sp->io_mmap_window, sizeof (io_mmap_window_t));
#endif	/* USE_IOMMAP_WINDOW */

		/*
		 * Return the socket to memory-only mode and turn off the
		 *	socket power.
		 */
		sp->event_mask = 0;
		set_socket.socket = sp->socket_num;
		set_socket.SCIntMask = 0;
		set_socket.IREQRouting = 0;
		set_socket.IFType = IF_MEMORY;
		set_socket.CtlInd = 0; /* turn off controls and indicators */
		set_socket.State = (unsigned)~0; /* clear latched state bits */

		(void) cs_convert_powerlevel(sp->socket_num, 0, VCC,
						&set_socket.VccLevel);
		(void) cs_convert_powerlevel(sp->socket_num, 0, VPP1,
						&set_socket.Vpp1Level);
		(void) cs_convert_powerlevel(sp->socket_num, 0, VPP2,
						&set_socket.Vpp2Level);

		/*
		 * If we fail this call, there's not much we can do, so
		 *	just continue with the resource deallocation.
		 */
		if ((ret =
			SocketServices(SS_SetSocket, &set_socket)) != SUCCESS) {
		    cmn_err(CE_CONT,
			"cs_deinit: socket %d SS_SetSocket failure %d\n",
							sp->socket_num, ret);
		}
	    } /* cs_get_sp */
	} /* for (sn) */
#endif	/* XXX */

	/*
	 * Destroy the global mutexii.
	 */
	mutex_destroy(&cs_globals.global_lock);
	mutex_destroy(&cs_globals.window_lock);

#ifdef	XXX
	/*
	 * Free the global "super-client" structure
	 */
	if (cs_globals.sclient_list)
	    kmem_free(cs_globals.sclient_list,
		(cs_globals.num_sockets * sizeof (struct sclient_list_t)));
	cs_globals.sclient_list = NULL;
#endif	/* XXX */

	return (CS_SUCCESS);
}

/*
 * ==== drip, drip, drip - the Card Services waterfall :-) ====
 */

/*
 * CardServices - general Card Services entry point for CS clients
 *			and Socket Services; the address of this
 *			function is handed to SS via the CSRegister
 *			SS call
 */
int
CardServices(int function, ...)
{
	va_list arglist;
	int retcode = CS_UNSUPPORTED_FUNCTION;

	cs_socket_t	*socp;
	uint32_t	*offp;
	acc_handle_t	*hp;
	client_handle_t	ch;
	client_handle_t	*chp;
	window_handle_t	wh;
	window_handle_t	*whp;
	tuple_t		*tuple;
	cisparse_t	*cisparse;

#ifdef	CS_DEBUG
	if (cs_debug > 127) {
	    cmn_err(CE_CONT, "CardServices: called for function %s (0x%x)\n",
				cs_error2text(function, CSFUN2TEXT_FUNCTION),
				function);
	}
#endif

	va_start(arglist, function);

	/*
	 * Here's the Card Services waterfall
	 */
	switch (function) {
	/*
	 * We got here as a result of the CIS module calling us
	 *	in response to cs_ss_init() calling the CIS module
	 *	at CIS_PARSER(CISP_CIS_SETUP, ...)
	 */
	    case CISRegister: {
		cisregister_t *cisr;

		    cisr = va_arg(arglist, cisregister_t *);

		    if (cisr->cis_magic != PCCS_MAGIC ||
			cisr->cis_version != PCCS_VERSION) {
			    cmn_err(CE_WARN,
				"CS: CISRegister (%lx, %lx, %lx, %lx) *ERROR*",
					(long)cisr->cis_magic,
					(long)cisr->cis_version,
					(long)cisr->cis_parser,
					(long)cisr->cistpl_std_callout);
			retcode = CS_BAD_ARGS;
		    } else {
			/*
			 * Replace the CIS Parser entry point if
			 *	necessary.
			 */
			if (cisr->cis_parser != NULL)
			    cis_parser = cisr->cis_parser;
			cis_cistpl_std_callout = cisr->cistpl_std_callout;
			retcode = CS_SUCCESS;
		    }
		}
		break;
	    case CISUnregister:	/* XXX - should we do some more checking */
		/* XXX - need to protect this by a mutex */
		cis_parser = NULL;
		cis_cistpl_std_callout = NULL;
		retcode = CS_SUCCESS;
		break;
	    case InitCISWindow:
		socp	= va_arg(arglist, cs_socket_t *);
		offp	= va_arg(arglist, uint32_t *);
		hp	= va_arg(arglist, acc_handle_t *);
		retcode = cs_init_cis_window(socp, offp, hp,
				va_arg(arglist, uint32_t));
		break;
	    case RegisterClient:
		chp = va_arg(arglist, client_handle_t *),
		retcode = cs_register_client(chp,
				va_arg(arglist, client_reg_t *));
		break;
	    case DeregisterClient:
		retcode = cs_deregister_client(
				va_arg(arglist, client_handle_t));
		break;
	    case GetStatus:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_get_status(ch,
				va_arg(arglist, get_status_t *));
		break;
	    case ResetFunction:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_reset_function(ch,
				va_arg(arglist, reset_function_t *));
		break;
	    case SetEventMask:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_set_event_mask(ch,
				va_arg(arglist, sockevent_t *));
		break;
	    case GetEventMask:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_get_event_mask(ch,
				va_arg(arglist, sockevent_t *));
		break;
	    case RequestIO:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_request_io(ch,
				va_arg(arglist, io_req_t *));
		break;
	    case ReleaseIO:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_release_io(ch,
				va_arg(arglist, io_req_t *));
		break;
	    case RequestIRQ:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_request_irq(ch,
				va_arg(arglist, irq_req_t *));
		break;
	    case ReleaseIRQ:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_release_irq(ch,
				va_arg(arglist, irq_req_t *));
		break;
	    case RequestWindow:
		ch = va_arg(arglist, client_handle_t);
		whp = va_arg(arglist, window_handle_t *);
		retcode = cs_request_window(ch, whp,
				va_arg(arglist, win_req_t *));
		break;
	    case ReleaseWindow:
		retcode = cs_release_window(
				va_arg(arglist, window_handle_t));
		break;
	    case ModifyWindow:
		wh = va_arg(arglist, window_handle_t);
		retcode = cs_modify_window(wh,
				va_arg(arglist, modify_win_t *));
		break;
	    case MapMemPage:
		wh = va_arg(arglist, window_handle_t);
		retcode = cs_map_mem_page(wh,
				va_arg(arglist, map_mem_page_t *));
		break;
	    case RequestSocketMask:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_request_socket_mask(ch,
				va_arg(arglist, request_socket_mask_t *));
		break;
	    case ReleaseSocketMask:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_release_socket_mask(ch,
				va_arg(arglist, release_socket_mask_t *));
		break;
	    case RequestConfiguration:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_request_configuration(ch,
				va_arg(arglist, config_req_t *));
		break;
	    case GetPhysicalAdapterInfo:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_get_physical_adapter_info(ch,
				va_arg(arglist, get_physical_adapter_info_t *));
		break;
	    case GetCardServicesInfo:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_get_cardservices_info(ch,
				va_arg(arglist, get_cardservices_info_t *));
		break;
	    case GetConfigurationInfo:
		chp = va_arg(arglist, client_handle_t *);
		retcode = cs_get_configuration_info(chp,
				va_arg(arglist, get_configuration_info_t *));
		break;
	    case ModifyConfiguration:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_modify_configuration(ch,
				va_arg(arglist, modify_config_t *));
		break;
	    case AccessConfigurationRegister:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_access_configuration_register(ch,
				va_arg(arglist, access_config_reg_t *));
		break;
	    case ReleaseConfiguration:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_release_configuration(ch,
				va_arg(arglist, release_config_t *));
		break;
	    case OpenMemory:
		cmn_err(CE_CONT, "CS: OpenMemory\n");
		break;
	    case ReadMemory:
		cmn_err(CE_CONT, "CS: ReadMemory\n");
		break;
	    case WriteMemory:
		cmn_err(CE_CONT, "CS: WriteMemory\n");
		break;
	    case CopyMemory:
		cmn_err(CE_CONT, "CS: CopyMemory\n");
		break;
	    case RegisterEraseQueue:
		cmn_err(CE_CONT, "CS: RegisterEraseQueue\n");
		break;
	    case CheckEraseQueue:
		cmn_err(CE_CONT, "CS: CheckEraseQueue\n");
		break;
	    case DeregisterEraseQueue:
		cmn_err(CE_CONT, "CS: DeregisterEraseQueue\n");
		break;
	    case CloseMemory:
		cmn_err(CE_CONT, "CS: CloseMemory\n");
		break;
	    case GetFirstRegion:
		cmn_err(CE_CONT, "CS: GetFirstRegion\n");
		break;
	    case GetNextRegion:
		cmn_err(CE_CONT, "CS: GetNextRegion\n");
		break;
	    case GetFirstPartition:
		cmn_err(CE_CONT, "CS: GetFirstPartition\n");
		break;
	    case GetNextPartition:
		cmn_err(CE_CONT, "CS: GetNextPartition\n");
		break;
	    case ReturnSSEntry:
		cmn_err(CE_CONT, "CS: ReturnSSEntry\n");
		break;
	    case MapLogSocket:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_map_log_socket(ch,
				va_arg(arglist, map_log_socket_t *));
		break;
	    case MapPhySocket:
		cmn_err(CE_CONT, "CS: MapPhySocket\n");
		break;
	    case MapLogWindow:
		cmn_err(CE_CONT, "CS: MapLogWindow\n");
		break;
	    case MapPhyWindow:
		cmn_err(CE_CONT, "CS: MapPhyWindow\n");
		break;
	    case RegisterMTD:
		cmn_err(CE_CONT, "CS: RegisterMTD\n");
		break;
	    case RegisterTimer:
		cmn_err(CE_CONT, "CS: RegisterTimer\n");
		break;
	    case SetRegion:
		cmn_err(CE_CONT, "CS: SetRegion\n");
		break;
	    case RequestExclusive:
		cmn_err(CE_CONT, "CS: RequestExclusive\n");
		break;
	    case ReleaseExclusive:
		cmn_err(CE_CONT, "CS: ReleaseExclusive\n");
		break;
	    case GetFirstClient:
		retcode = cs_get_firstnext_client(
				va_arg(arglist, get_firstnext_client_t *),
				CS_GET_FIRST_FLAG);
		break;
	    case GetNextClient:
		retcode = cs_get_firstnext_client(
				va_arg(arglist, get_firstnext_client_t *),
				CS_GET_NEXT_FLAG);
		break;
	    case GetClientInfo:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_get_client_info(ch,
				va_arg(arglist, client_info_t *));
		break;
	    case AddSocketServices:
		cmn_err(CE_CONT, "CS: AddSocketServices\n");
		break;
	    case ReplaceSocketServices:
		cmn_err(CE_CONT, "CS: ReplaceSocketServices\n");
		break;
	    case VendorSpecific:
		cmn_err(CE_CONT, "CS: VendorSpecific\n");
		break;
	    case AdjustResourceInfo:
		cmn_err(CE_CONT, "CS: AdjustResourceInfo\n");
		break;
	    case ValidateCIS:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_validate_cis(ch,
				va_arg(arglist, cisinfo_t *));
		break;
	    case GetFirstTuple:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_get_firstnext_tuple(ch,
				va_arg(arglist, tuple_t *),
				CS_GET_FIRST_FLAG);
		break;
	    case GetNextTuple:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_get_firstnext_tuple(ch,
				va_arg(arglist, tuple_t *),
				CS_GET_NEXT_FLAG);
		break;
	    case GetTupleData:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_get_tuple_data(ch,
				va_arg(arglist, tuple_t *));
		break;
	    case ParseTuple:
		ch = va_arg(arglist, client_handle_t);
		tuple = va_arg(arglist, tuple_t *);
		cisparse = va_arg(arglist, cisparse_t *);
		retcode = cs_parse_tuple(ch, tuple, cisparse,
				va_arg(arglist, uint_t));
		break;
	    case MakeDeviceNode:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_make_device_node(ch,
				va_arg(arglist, make_device_node_t *));
		break;
	    case RemoveDeviceNode:
		ch = va_arg(arglist, client_handle_t);
		retcode = cs_remove_device_node(ch,
				va_arg(arglist, remove_device_node_t *));
		break;
	    case ConvertSpeed:
		retcode = cs_convert_speed(
				va_arg(arglist, convert_speed_t *));
		break;
	    case ConvertSize:
		retcode = cs_convert_size(
				va_arg(arglist, convert_size_t *));
		break;
	    case Event2Text:
		retcode = cs_event2text(
				va_arg(arglist, event2text_t *), 1);
		break;
	    case Error2Text: {
		error2text_t *cft;

		cft = va_arg(arglist, error2text_t *);
		(void) strcpy(cft->text,
				cs_error2text(cft->item, CSFUN2TEXT_RETURN));
		retcode = CS_SUCCESS;
		}
		break;
	    case CS_DDI_Info:
		retcode = cs_ddi_info(va_arg(arglist, cs_ddi_info_t *));
		break;
	    case CS_Sys_Ctl:
		retcode = cs_sys_ctl(va_arg(arglist, cs_sys_ctl_t *));
		break;
	    default:
		cmn_err(CE_CONT, "CS: {unknown function %d}\n", function);
		break;
	} /* switch(function) */

	va_end(arglist);

#ifdef	CS_DEBUG
	if (cs_debug > 127) {
	    cmn_err(CE_CONT, "CardServices: returning %s (0x%x)\n",
				cs_error2text(retcode, CSFUN2TEXT_RETURN),
				retcode);
	}
#endif

	return (retcode);
}

/*
 * ==== tuple and CIS handling section ====
 */

/*
 * cs_parse_tuple - This function supports the CS ParseTuple function call.
 *
 *    returns:	CS_SUCCESS - if tuple parsed sucessfully
 *		CS_NO_CARD - if no card in socket
 *		CS_BAD_ARGS - if passed CIS list pointer is NULL
 *		CS_UNKNOWN_TUPLE - if unknown tuple passed to CIS parser
 *		CS_BAD_CIS - if generic parser error
 *		CS_NO_CIS - if no CIS for card/function
 *
 *    See notes for the cs_get_firstnext_tuple function.
 */
static int
cs_parse_tuple(client_handle_t client_handle, tuple_t *tuple,
				cisparse_t *cisparse, cisdata_t cisdata)
{
	cs_socket_t *sp;
	client_t *client;
	uint32_t fn;
	int ret;

	if ((ret = cs_get_socket(client_handle, &tuple->Socket,
					&fn, &sp, &client)) != CS_SUCCESS)
	    return (ret);

	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED))
	    return (CS_NO_CARD);

	/*
	 * Sanity check to be sure that we've got a non-NULL CIS list
	 *	pointer.
	 */
	if (!(tuple->CISOffset))
	    return (CS_BAD_ARGS);

	mutex_enter(&sp->cis_lock);

	/*
	 * Check to see if there is a valid CIS for this function.
	 *	There is an implicit assumption here that if this
	 *	is a multi-function CIS and the specified function
	 *	number is not CS_GLOBAL_CIS that in order for there
	 *	to be a valid function-specific CIS, there also must
	 *	be a valid global CIS. This means that we don't need
	 *	to know whether this tuple came from the global CIS
	 *	or from the function-specific CIS.
	 */
	if ((sp->cis_flags & CW_VALID_CIS) &&
				(sp->cis[fn].flags & CW_VALID_CIS)) {
	    ret = (int)(uintptr_t)CIS_PARSER(CISP_CIS_PARSE_TUPLE,
				cis_cistpl_std_callout,
				tuple->CISOffset,
				(tuple->Attributes & TUPLE_RETURN_NAME)?
							HANDTPL_RETURN_NAME:
							HANDTPL_PARSE_LTUPLE,
				cisparse, cisdata);
	    mutex_exit(&sp->cis_lock);
	    if (ret == CISTPLF_UNKNOWN)
		return (CS_UNKNOWN_TUPLE);
	    if (ret != CISTPLF_NOERROR)
		return (CS_BAD_CIS);
	    ret = CS_SUCCESS;
	} else {
	    mutex_exit(&sp->cis_lock);
	    ret = CS_NO_CIS;
	} /* if (CW_VALID_CIS) */

	return (ret);
}

/*
 * cs_get_firstnext_tuple - returns the first/next tuple of the specified type
 *				this is to support the GetFirstTuple and
 *				GetNextTuple function call
 *
 *    flags - one of:
 *		CS_GET_FIRST_FLAG causes function to support GetFirstTuple
 *		CS_GET_NEXT_FLAG causes function to support GetNextTuple
 *
 *	tuple_t->Attributes flags:
 *		TUPLE_RETURN_LINK - XXX Not implemented, see notes below.
 *		TUPLE_RETURN_IGNORED_TUPLES - return tuples with
 *				CISTPLF_IGNORE_TUPLE set in the
 *				cistpl_t->flags member.
 *
 *    Notes for regular PC card driver callers:
 *
 *	On a single-function card, the caller will get back all the tuples in
 *	the CIS.
 *
 *	On a multi-function card, the caller will get the tuples from the
 *	global CIS followed by the tuples in the function-specific CIS. The
 *	caller will not get any tuples from a function-specific CIS that
 *	does not belong to the caller's function.
 *
 *    Notes for Socket Services, the "super-client" or CSI driver callers:
 *
 *	On a single-function card, the operation is the same as for regular
 *	PC card driver callers with the addition that if the function number
 *	is set to CS_GLOBAL_CIS this function will return CS_NO_CIS.
 *
 *	On a multi-function card, the operation is the same as for regular
 *	PC card driver callers with the addition that if the function number
 *	is set to CS_GLOBAL_CIS the caller will only get tuples from the
 *	global CIS. If a particular function nubmer does not exist, this
 *	function will return CS_NO_CIS for that function.
 *
 *    General notes:
 *
 *	On both a single-function card and a multi-function card, if the tuple
 *	comes from the global CIS chain, the CISTPLF_GLOBAL_CIS flag will be
 *	set in the tuple_t->flags member.
 *
 *	On a multi-function card, if the tuple comes from the function-specific
 *	CIS chain, the CISTPLF_MF_CIS flag will be set in the tuple_t->flags
 *	member.
 *
 *	For other flags that are set in the tuple_t->flags member, see the
 *	comments for the cis_list_lcreate function in the cis.c file.
 *
 *	The CIS parser may not include all the tuples that are in the CIS in
 *	the private CIS list that it creates and maintains. See the CIS
 *	parser documentation for a list of tuples that the parser does not
 *	include in the list.
 *
 *	If a tuple has the CISTPLF_IGNORE_TUPLE flag set and the flags
 *	parameter CIS_GET_LTUPLE_IGNORE is not set, that tuple will not
 *	be returned to the caller. Instead, the next tuple that matches
 *	the calling criteria will be returned (or NULL if no other tuples
 *	match the calling criteria). If CIS_GET_LTUPLE_IGNORE is set in
 *	the flags paramter, tuples in the CIS list that match the calling
 *	criteria will be returned.
 *
 * XXX The PC Card 95 Standard says that if the TUPLE_RETURN_LINK flag in
 *	the tuple_t->Attributes member is not set, then we don't return
 *	any of the link tuples. This function ignores this flag and always
 *	returns link tuples.
 *
 *    Return codes:
 *		CS_SUCCESS - if tuple sucessfully found and returned
 *		CS_NO_CARD - if no card inserted
 *		CS_NO_CIS - if no CIS for the specified card/function
 *		CS_NO_MORE_ITEMS - if tuple not found or no more tuples
 *					to return
 *
 *    See notes for cs_get_socket for a description of valid client, socket
 *	and function number combinations.
 */
static int
cs_get_firstnext_tuple(client_handle_t client_handle,
    tuple_t *tuple, uint32_t flags)
{
	cs_socket_t *sp;
	client_t *client;
	uint32_t fn;
	int ret;

	if ((ret = cs_get_socket(client_handle, &tuple->Socket, &fn,
						&sp, &client)) != CS_SUCCESS)
	    return (ret);

	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED))
	    return (CS_NO_CARD);

	mutex_enter(&sp->cis_lock);

	/*
	 * If there's no CIS on this card or no CIS for the specified
	 *	function, then we can't do much.
	 */
	if ((!(sp->cis_flags & CW_VALID_CIS)) ||
				(!(sp->cis[fn].flags & CW_VALID_CIS))) {
	    mutex_exit(&sp->cis_lock);
	    return (CS_NO_CIS);
	}

	/*
	 * This will set the CIS_GET_LTUPLE_IGNORE flag if the
	 *	TUPLE_RETURN_IGNORED_TUPLES flag is set. The
	 *	assumption here is that the CIS_GET_LTUPLE_IGNORE
	 *	flag and the TUPLE_RETURN_IGNORED_TUPLES flag
	 *	shares the same bit position. If this ever changes,
	 *	we'll ahve to re-work this section of code.
	 */
	if (tuple->Attributes & TUPLE_RETURN_IGNORED_TUPLES)
	    flags |= CIS_GET_LTUPLE_IGNORE;

	/*
	 * Are we GetFirstTuple or GetNextTuple?
	 */
	if ((flags & CIS_GET_LTUPLE_OPMASK) & CS_GET_FIRST_FLAG) {
	/*
	 * Initialize the tuple structure; we need this information when
	 *	we have to process a GetNextTuple or ParseTuple call.
	 * If this card has a multi-function CIS, then we always start out
	 *	delivering tuples from the global CIS chain. If this card does
	 *	not have a multi-function CIS, then the function 0 CIS chain
	 *	will contain the complete CIS list.
	 * If this is a multi-function card, then use the GET_FIRST_LTUPLE
	 *	macro to return the first tuple in the CIS list - we do this
	 *	since we don't want to return tuples with CISTPLF_IGNORE_TUPLE
	 *	set unless CIS_GET_LTUPLE_IGNORE is set in the flags parameter.
	 * Note that we don't have to cross over into the fucntion-specific
	 *	CIS chain if GET_FIRST_LTUPLE returns NULL, since a MF CIS will
	 *	always have at least a CISTPL_LONGLINK_MFC tuple in the global
	 *	CIS chain - the test for NULL is just a sanity check.
	 */
	    if (sp->cis_flags & CW_MULTI_FUNCTION_CIS) {
		if ((tuple->CISOffset =
			GET_FIRST_LTUPLE(sp->cis[CS_GLOBAL_CIS].cis,
							flags)) == NULL) {
		    mutex_exit(&sp->cis_lock);
		    return (CS_NO_MORE_ITEMS);
		} /* GET_FIRST_LTUPLE */
	    } else {
		tuple->CISOffset = sp->cis[0].cis;
	    } /* CW_MULTI_FUNCTION_CIS */
	} else {
	    cistpl_t *tp;

		/*
		 * Check to be sure that we have a non-NULL tuple list pointer.
		 *	This is necessary in the case where the caller calls us
		 *	with get next tuple requests but we don't have any more
		 *	tuples to give back.
		 */
	    if (tuple->CISOffset == NULL) {
		mutex_exit(&sp->cis_lock);
		return (CS_NO_MORE_ITEMS);
	    }

		/*
		 * Point to the next tuple in the list.  If we're searching for
		 *	a particular tuple, FIND_LTUPLE_FWD will find it.
		 *
		 * If there are no more tuples in the chain that we're looking
		 *	at, then if we're looking at the global portion of a
		 *	multi-function CIS, switch to the function-specific list
		 *	and start looking there.
		 */
	    if ((tp = GET_NEXT_TUPLE(tuple->CISOffset, flags)) == NULL) {
		if (sp->cis_flags & CW_MULTI_FUNCTION_CIS) {
		    if ((tuple->CISOffset->flags & CISTPLF_GLOBAL_CIS) &&
							(fn != CS_GLOBAL_CIS)) {
			tp = GET_FIRST_LTUPLE(sp->cis[fn].cis, flags);
		    } /* CISTPLF_GLOBAL_CIS */
		} /* CW_MULTI_FUNCTION_CIS */
	    } /* GET_NEXT_TUPLE */

		/*
		 * If there are no more tuples in the chain, then return.
		 */
	    if ((tuple->CISOffset = tp) == NULL) {
		mutex_exit(&sp->cis_lock);
		return (CS_NO_MORE_ITEMS);
	    }
	} /* CS_GET_FIRST_FLAG */

	/*
	 * Check if we want to get the first of a particular type of tuple
	 *	or just the first tuple in the chain.
	 * If there are no more tuples of the type we're searching for in
	 *	the chain that we're looking at, then if we're looking at
	 *	the global portion of a multi-function CIS, switch to the
	 *	function-specific list and start looking there.
	 */
	if (tuple->DesiredTuple != RETURN_FIRST_TUPLE) {
	    cistpl_t *tp;

	    if ((tp = FIND_LTUPLE_FWD(tuple->CISOffset,
					tuple->DesiredTuple, flags)) == NULL) {
		if (sp->cis_flags & CW_MULTI_FUNCTION_CIS) {
		    if ((tuple->CISOffset->flags & CISTPLF_GLOBAL_CIS) &&
							(fn != CS_GLOBAL_CIS)) {
			tp = FIND_FIRST_LTUPLE(sp->cis[fn].cis,
						tuple->DesiredTuple, flags);
		    } /* CISTPLF_GLOBAL_CIS */
		} /* CW_MULTI_FUNCTION_CIS */
	    } /* FIND_LTUPLE_FWD */

		/*
		 * If there are no more tuples in the chain, then return.
		 */
	    if ((tuple->CISOffset = tp) == NULL) {
		mutex_exit(&sp->cis_lock);
		return (CS_NO_MORE_ITEMS);
	    }
	} /* !RETURN_FIRST_TUPLE */

	/*
	 * We've got a tuple, now fill out the rest of the tuple_t
	 *	structure.  Callers can use the flags member to
	 *	determine whether or not the tuple data was copied
	 *	to the linked list or if it's still on the card.
	 */
	tuple->Flags = tuple->CISOffset->flags;
	tuple->TupleCode = tuple->CISOffset->type;
	tuple->TupleLink = tuple->CISOffset->len;
	tuple->TupleDataLen = tuple->CISOffset->len;

	mutex_exit(&sp->cis_lock);

	return (CS_SUCCESS);
}

/*
 * cs_get_tuple_data - get the data portion of a tuple; this is to
 *	support the GetTupleData function call.
 *
 *    Note that if the data body of a tuple was not read from the CIS,
 *	then this function will return CS_NO_MORE_ITEMS.
 *
 *    For flags that are set in the tuple_t->flags member, see the
 *	comments for the cis_list_lcreate function in the cis.c file.
 *	These flags are copied into the tuple_t->flags member by the
 *	cs_get_firstnext_tuple function call.
 *
 *    See notes for the cs_get_firstnext_tuple function.
 */
static int
cs_get_tuple_data(client_handle_t client_handle, tuple_t *tuple)
{
	cs_socket_t *sp;
	client_t *client;
	int ret, nbytes;
	uint32_t fn, flags;
	cisdata_t *tsd, *tdd;
	uint32_t newoffset;
	acc_handle_t cis_handle;

	if ((ret = cs_get_socket(client_handle, &tuple->Socket, &fn,
						&sp, &client)) != CS_SUCCESS)
	    return (ret);

	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED))
	    return (CS_NO_CARD);

	mutex_enter(&sp->cis_lock);

	if ((sp->cis_flags & CW_VALID_CIS) &&
				(sp->cis[fn].flags & CW_VALID_CIS)) {

		/*
		 * Check to be sure that we have a non-NULL pointer to
		 *	a CIS list.
		 */
	    if (!(tuple->CISOffset)) {
		mutex_exit(&sp->cis_lock);
		return (CS_NO_MORE_ITEMS);
	    }

	/*
	 * Since the tuple data buffer that the caller calls us with
	 *	is preallocated in the tuple_t structure, we ignore any
	 *	TupleDataMax value that the caller has setup and use the
	 *	actual size of the tuple data buffer in the structure.
	 */
	    tuple->TupleDataMax = sizeof (tuple->TupleData);

	/*
	 * Make sure the requested offset is not past the end of the
	 *	tuple data body nor past the end of the user-supplied
	 *	buffer.
	 */
	    if ((int)tuple->TupleOffset >= min((int)tuple->TupleLink,
						(int)tuple->TupleDataMax)) {
		mutex_exit(&sp->cis_lock);
		return (CS_NO_MORE_ITEMS);
	    }

	    tuple->TupleDataLen = tuple->TupleLink;

	    if ((nbytes = min((int)tuple->TupleDataMax -
						(int)tuple->TupleOffset,
						(int)tuple->TupleDataLen -
						(int)tuple->TupleOffset)) < 1) {
		mutex_exit(&sp->cis_lock);
		return (CS_BAD_ARGS);
	    }

	/*
	 * The tuple data destination is always the tuple_t->TupleData
	 *	buffer in the tuple_t structure no matter where we read the
	 *	tuple data from.
	 */
	    tdd = tuple->TupleData;
	    bzero((caddr_t)tdd, sizeof (tuple->TupleData));

	/*
	 * Do we have a copy of the tuple data?  If not, we have to
	 *	get a pointer to the CIS and read the tuple data from the
	 *	card itself.
	 */
	    switch (tuple->CISOffset->flags & CISTPLF_SPACE_MASK) {
		case CISTPLF_LM_SPACE:
		    tsd = (tuple->CISOffset->data +
					(unsigned)tuple->TupleOffset);
		    while (nbytes--)
			*tdd++ = *tsd++;
		    break;
		case CISTPLF_AM_SPACE:
		case CISTPLF_CM_SPACE:
		    newoffset = tuple->CISOffset->offset;

		/*
		 * Setup the proper space flags as well as setup the
		 *	address offset to point to the start of the tuple
		 *	data area; we need to do the latter since the
		 *	cis_store_cis_addr function in cis.c sets up the
		 *	tuple->CISOffset->offset offset to point to the
		 *	start of the tuple.
		 */
		    if (tuple->CISOffset->flags & CISTPLF_AM_SPACE) {
			flags = CISTPLF_AM_SPACE;
			newoffset += ((tuple->TupleOffset * 2) + 4);
		    } else {
			flags = CISTPLF_CM_SPACE;
			newoffset += (tuple->TupleOffset + 2);
		    }

		    if (cs_init_cis_window(sp, &newoffset, &cis_handle,
							flags) != CS_SUCCESS) {
			mutex_exit(&sp->cis_lock);
			cmn_err(CE_CONT, "cs_get_tuple_data: socket %d "
						"can't init CIS window\n",
							sp->socket_num);
			return (CS_GENERAL_FAILURE);
		    } /* cs_init_cis_window */
		    while (nbytes--) {
			*tdd++ = csx_Get8(cis_handle, newoffset++);
			if (tuple->CISOffset->flags & CISTPLF_AM_SPACE)
			    newoffset++;
		    } /* while */
		    break;
		default:
		    mutex_exit(&sp->cis_lock);
		    return (CS_GENERAL_FAILURE);
	    } /* switch */

	    ret = CS_SUCCESS;
	} else {
	    ret = CS_NO_CIS;
	} /* if (CW_VALID_CIS) */

	mutex_exit(&sp->cis_lock);

	return (ret);
}

/*
 * cs_validate_cis - validates the CIS on a card in the given socket; this
 *			is to support the ValidateCIS function call.
 *
 *    Notes for regular PC card driver callers:
 *
 *	Regular PC card drivers calling ValidateCIS will get the meaning of
 *	the structure members as specified in the standard.
 *
 *    Notes for Socket Services, the "super-client" or CSI driver callers:
 *
 *		with: Function Number = CS_GLOBAL_CIS
 *
 *	For a single-function card, CS_NO_CIS will be returned and the
 *	cisinfo_t->Chains and cisinfo_t->Tuples members will be set to 0.
 *
 *	For a multi-function card, cisinfo_t->Chains will contain a count of
 *	the number of CIS chains in the global portion of the CIS, and
 *	cisinfo_t->Tuples will contain a count of the number of tuples in
 *	the global portion of the CIS.
 *
 *		with: 0 <= Function Number < CIS_MAX_FUNCTIONS
 *
 *	For a single-function card, if the function number is equal to 0 and
 *	has a CIS, cisinfo_t->Chains will contain a count of the number of
 *	CIS chains in the CIS, and cisinfo_t->Tuples will contain a count of
 *	the number of tuples in the CIS. If the card does not have a CIS, or
 *	if the function number is not equal to 0, CS_NO_CIS will be returned
 *	and the cisinfo_t->Chains and cisinfo_t->Tuples members will be set
 *	to 0.
 *
 *	For a multi-function card, cisinfo_t->Chains will contain a count of
 *	the number of CIS chains in the global and function-specific
 *	portions of the CIS, and cisinfo_t->Tuples will contain a count of
 *	the number of tuples in the global and function-specific portions of
 *	the CIS. If the function does not exist or has no CIS, CS_NO_CIS
 *	will be returned and the cisinfo_t->Chains and cisinfo_t->Tuples
 *	members will be set to 0.
 *
 *    General notes:
 *
 *	If the card does not have a CIS, or if the function does not exist
 *	or has no CIS, CS_NO_CIS will be returned and the cisinfo_t->Chains
 *	and cisinfo_t->Tuples members will be set to 0.
 *
 *	Most of the work of validating the CIS has already been done by the
 *	CIS parser module, so we don't have to do much here except for
 *	looking at the various flags and tuple/chain counts that were already
 *	setup by the CIS parser.
 *
 *    See notes for the cs_get_firstnext_tuple function.
 */
static int
cs_validate_cis(client_handle_t client_handle, cisinfo_t *cisinfo)
{
	cs_socket_t *sp;
	client_t *client;
	uint32_t fn;
	int ret;

	if ((ret = cs_get_socket(client_handle, &cisinfo->Socket, &fn,
						&sp, &client)) != CS_SUCCESS)
	    return (ret);

	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED))
	    return (CS_NO_CARD);

	mutex_enter(&sp->cis_lock);
	if ((sp->cis_flags & CW_VALID_CIS) &&
				(sp->cis[fn].flags & CW_VALID_CIS)) {
	    cisinfo->Chains = sp->cis[fn].nchains;
	    cisinfo->Tuples = sp->cis[fn].ntuples;

	    if ((fn != CS_GLOBAL_CIS) &&
			(sp->cis[CS_GLOBAL_CIS].flags & CW_VALID_CIS)) {
		cisinfo->Chains += sp->cis[CS_GLOBAL_CIS].nchains;
		cisinfo->Tuples += sp->cis[CS_GLOBAL_CIS].ntuples;
	    } /* !CS_GLOBAL_CIS */

	    ret = CS_SUCCESS;
	} else {
	    cisinfo->Chains = 0;
	    cisinfo->Tuples = 0;
	    ret = CS_NO_CIS;
	}
	mutex_exit(&sp->cis_lock);

	return (ret);
}

/*
 * cs_init_cis_window - initializes the CIS window for the passed socket
 *
 *	calling: *sp - pointer to the per-socket structure
 *		 *offset - offset from start of AM or CM space
 *		 *hp - pointer to acc_handle_t to store modified
 *				window access handle in
 *		 flags - one of:
 *				CISTPLF_AM_SPACE - set window to AM space
 *				CISTPLF_CM_SPACE - set window to CM space
 *
 *	returns: CS_SUCCESS if CIS window was set up
 *		 *offset - contains adjusted offset to use to access
 *				requested space
 *		 CS_BAD_WINDOW if CIS window could not be setup
 *		 CS_GENERAL_FAILURE if socket has a CIS window number
 *					but the window flags are wrong
 *
 *	Note: This function will check to be sure that there is a valid
 *		CIS window allocated to this socket.
 *	      If there is an error in setting up the window hardware, the
 *		CIS window information for this socket is cleared.
 *	      This function is also used by routines that need to get
 *		a pointer to the base of AM space to access the card's
 *		configuration registers.
 *	      The passed offset is the un-window-size-aligned offset.
 */
int
cs_init_cis_window(cs_socket_t *sp, uint32_t *offset,
    acc_handle_t *hp, uint32_t flags)
{
	set_window_t sw;
	get_window_t gw;
	inquire_window_t iw;
	set_page_t set_page;
	cs_window_t *cw;

	/*
	 * Check to be sure that we have a valid CIS window
	 */
	if (!SOCKET_HAS_CIS_WINDOW(sp)) {
	    cmn_err(CE_CONT,
			"cs_init_cis_window: socket %d has no CIS window\n",
				sp->socket_num);
	    return (CS_BAD_WINDOW);
	}

	/*
	 * Check to be sure that this window is allocated for CIS use
	 */
	if ((cw = cs_get_wp(sp->cis_win_num)) == NULL)
	    return (CS_BAD_WINDOW);

	if (!(cw->state & CW_CIS)) {
	    cmn_err(CE_CONT,
		"cs_init_cis_window: socket %d invalid CIS window state 0x%x\n",
				sp->socket_num, cw->state);
	    return (CS_BAD_WINDOW);
	}

	/*
	 * Get the characteristics of this window - we use this to
	 *	determine whether we need to re-map the window or
	 *	just move the window offset on the card.
	 */
	iw.window = sp->cis_win_num;
	SocketServices(SS_InquireWindow, &iw);

	/*
	 * We've got a window, now set up the hardware. If we've got
	 *	a variable sized window, then all we need to do is to
	 *	get a valid mapping to the base of the window using
	 *	the current window size; if we've got a fixed-size
	 *	window, then we need to get a mapping to the window
	 *	starting at offset zero of the window.
	 */
	if (iw.mem_win_char.MemWndCaps & WC_SIZE) {
	    sw.WindowSize = sp->cis_win_size;
	    set_page.offset = ((*offset / sp->cis_win_size) *
						sp->cis_win_size);
	} else {
	    set_page.offset = ((*offset / iw.mem_win_char.MinSize) *
						iw.mem_win_char.MinSize);
	    sw.WindowSize = (((*offset & ~(PAGESIZE - 1)) &
					(set_page.offset - 1)) + PAGESIZE);
	}

	/*
	 * Return a normalized base offset; this takes care of the case
	 *	where the required offset is greater than the window size.
	 * BugID 1236404
	 *	code was:
	 *		*offset = *offset & (set_page.offset - 1);
	 */
	*offset = *offset - set_page.offset;

#ifdef	CS_DEBUG
	if (cs_debug > 1)
	    cmn_err(CE_CONT, "cs_init_cis_window: WindowSize 0x%x "
							"offset 0x%x\n",
							(int)sw.WindowSize,
							(int)set_page.offset);
	if (cs_debug > 1)
	    cmn_err(CE_CONT, "\t*offset = 0x%x space = %s\n",
							(int)*offset,
					(flags & CISTPLF_AM_SPACE)?
					"CISTPLF_AM_SPACE":"CISTPLF_CM_SPACE");
#endif

	sw.window = sp->cis_win_num;
	sw.socket = sp->socket_num;
	sw.state = (WS_ENABLED | WS_EXACT_MAPIN);
	sw.attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	sw.attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	sw.attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/*
	 * The PCMCIA SS spec specifies this be expressed in
	 *	a device speed format per 5.2.7.1.3 but
	 *	our implementation of SS_SetWindow uses
	 *	actual nanoseconds.
	 */
	sw.speed = CIS_DEFAULT_SPEED;
	sw.base = 0;
	/*
	 * Set up the window - if this fails, then just set the
	 *	CIS window number back to it's initialized value so
	 *	that we'll fail when we break out of the loop.
	 */
	if (SocketServices(SS_SetWindow, &sw) != SUCCESS) {
	    sp->cis_win_num = PCMCIA_MAX_WINDOWS;
	    cw->state = 0; /* XXX do we really want to do this? */
	    return (CS_BAD_WINDOW);
	} else {
		set_page.window = sp->cis_win_num;
		set_page.page = 0;
		set_page.state = PS_ENABLED;
		if (flags & CISTPLF_AM_SPACE)
		    set_page.state |= PS_ATTRIBUTE;

		if (SocketServices(SS_SetPage, &set_page) != SUCCESS) {
		    sp->cis_win_num = PCMCIA_MAX_WINDOWS;
		    cw->state = 0; /* XXX do we really want to do this? */
		    return (CS_BAD_WINDOW);
		} /* if (SS_SetPage) */
	} /* if (SS_SetWindow) */

	/*
	 * Get the window information for the CIS window for this socket.
	 */
	gw.window = sp->cis_win_num;
	gw.socket = sp->socket_num; /* XXX - SS_GetWindow should set this */
	if (SocketServices(SS_GetWindow, &gw) != SUCCESS)
	    return (CS_BAD_WINDOW);

	*hp = (acc_handle_t)gw.handle;

	return (CS_SUCCESS);
}

/*
 * ==== client registration/deregistration section ====
 */

/*
 * cs_register_client - This supports the RegisterClient call.
 *
 * Upon successful registration, the client_handle_t * handle argument will
 *	contain the new client handle and we return CS_SUCCESS.
 */
static int
cs_register_client(client_handle_t *ch, client_reg_t *cr)
{
	uint32_t sn;
	int super_client = 0;
	sclient_reg_t *scr = cr->priv;
	struct sclient_list_t *scli;

	/*
	 * See if we're not supposed to register any new clients.
	 */
	if (cs_globals.init_state & GLOBAL_INIT_STATE_NO_CLIENTS)
	    return (CS_OUT_OF_RESOURCE);

	/*
	 * Do a version check - if the client expects a later version of
	 *	Card Services than what we are, return CS_BAD_VERSION.
	 * XXX - How do we specify just a PARTICULAR version of CS??
	 */
	if (CS_VERSION < cr->Version)
	    return (CS_BAD_VERSION);

	/*
	 * Check to be sure that the client has given us a valid set of
	 *	client type flags.  We also use this opportunity to see
	 *	if the registering client is Socket Services or is a
	 *	"super-client" or a CSI client.
	 *
	 * Note that SS can not set any flag in the Attributes field other
	 *	than the INFO_SOCKET_SERVICES flag.
	 *
	 * Valid combinations of cr->Attributes and cr->EventMask flags:
	 *
	 *  for Socket Services:
	 *	cr->Attributes:
	 *	    set:
	 *		INFO_SOCKET_SERVICES
	 *	    clear:
	 *		{all other flags}
	 *	cr->EventMask:
	 *	    don't care:
	 *		{all flags}
	 *
	 *  for regular clients:
	 *	cr->Attributes:
	 *	    only one of:
	 *		INFO_IO_CLIENT
	 *		INFO_MTD_CLIENT
	 *		INFO_MEM_CLIENT
	 *	    don't care:
	 *		INFO_CARD_SHARE
	 *		INFO_CARD_EXCL
	 *	cr->EventMask:
	 *	    clear:
	 *		CS_EVENT_ALL_CLIENTS
	 *	    don't care:
	 *		{all other flags}
	 *
	 *  for CSI clients:
	 *	cr->Attributes:
	 *	    set:
	 *		INFO_IO_CLIENT
	 *		INFO_CSI_CLIENT
	 *	    clear:
	 *		INFO_MTD_CLIENT
	 *		INFO_MEM_CLIENT
	 *	    don't care:
	 *		INFO_CARD_SHARE
	 *		INFO_CARD_EXCL
	 *	cr->EventMask:
	 *	    don't care:
	 *		{all flags}
	 *
	 *  for "super-clients":
	 *	cr->Attributes:
	 *	    set:
	 *		INFO_IO_CLIENT
	 *		INFO_MTD_CLIENT
	 *		INFO_SOCKET_SERVICES
	 *		INFO_CARD_SHARE
	 *	    clear:
	 *		INFO_MEM_CLIENT
	 *		INFO_CARD_EXCL
	 *	cr->EventMask:
	 *	    don't care:
	 *		{all flags}
	 */
	switch (cr->Attributes & INFO_CLIENT_TYPE_MASK) {
	/*
	 * Check first to see if this is Socket Services registering; if
	 *	so, we don't do anything but return the client handle that is
	 *	in the global SS client.
	 */
	    case INFO_SOCKET_SERVICES:
		*ch = cs_socket_services_client.client_handle;
		return (CS_SUCCESS);
		/* NOTREACHED */
	    /* CSI clients */
	    case (INFO_CSI_CLIENT | INFO_IO_CLIENT):
		break;
	    /* regular clients */
	    case INFO_IO_CLIENT:
	    case INFO_MTD_CLIENT:
	    case INFO_MEM_CLIENT:
		if (cr->EventMask & CS_EVENT_ALL_CLIENTS)
		    return (CS_BAD_ATTRIBUTE);
		break;
	    /* "super-client" clients */
	    case (INFO_IO_CLIENT | INFO_MTD_CLIENT | INFO_SOCKET_SERVICES):
		if ((!(cr->Attributes & INFO_CARD_SHARE)) ||
				(cr->Attributes & INFO_CARD_EXCL))
		    return (CS_BAD_ATTRIBUTE);
		/*
		 * We only allow one "super-client" per system.
		 */
		mutex_enter(&cs_globals.global_lock);
		if (cs_globals.flags & GLOBAL_SUPER_CLIENT_REGISTERED) {
		    mutex_exit(&cs_globals.global_lock);
		    return (CS_NO_MORE_ITEMS);
		}
		cs_globals.flags |= GLOBAL_SUPER_CLIENT_REGISTERED;
		mutex_exit(&cs_globals.global_lock);
		super_client = CLIENT_SUPER_CLIENT;
		break;
	    default:
		return (CS_BAD_ATTRIBUTE);
	} /* switch (cr->Attributes) */

	/*
	 * Now, actually create the client node on the socket; this will
	 *	also return the new client handle if there were no errors
	 *	creating the client node.
	 * The DIP2SOCKET_NUM macro will return the socket and function
	 *	number using the encoding specified in the cs_priv.h file.
	 */
	if (super_client != CLIENT_SUPER_CLIENT) {
	    if (cr->Attributes & INFO_CSI_CLIENT)
		sn = (uint32_t)(uintptr_t)cr->priv;
	    else
		sn = DIP2SOCKET_NUM(cr->dip);
	    return (cs_add_client_to_socket(sn, ch, cr, super_client));
	} /* CLIENT_SUPER_CLIENT */

	/*
	 * This registering client is a "super-client", so we create one
	 *	client node for each socket in the system.  We use the
	 *	client_reg_t.priv structure member to point to a struct
	 *	that the "super-client" client knows about.  The client
	 *	handle pointer is not used in this case.
	 * We return CS_SUCCESS if at least one client node could be
	 *	created.  The client must check the error codes in the
	 *	error code array to determine which clients could not
	 *	be created on which sockets.
	 * We return CS_BAD_HANDLE if no client nodes could be created.
	 */
	scr->num_clients = 0;
	scr->max_socket_num = cs_globals.max_socket_num;
	scr->num_sockets = cs_globals.num_sockets;
	scr->num_windows = cs_globals.num_windows;

	*(scr->sclient_list) = cs_globals.sclient_list;

	for (sn = 0; sn < scr->num_sockets; sn++) {
	    scli = scr->sclient_list[sn];
	    if ((scli->error = cs_add_client_to_socket(sn, &scli->client_handle,
					    cr, super_client)) == CS_SUCCESS) {
		scr->num_clients++;
	    }
	}

	/*
	 * If we couldn't create any client nodes at all, then
	 *	return an error.
	 */
	if (!scr->num_clients) {
	/*
	 * XXX - The global superclient lock now gets
	 * cleared in cs_deregister_client
	 */
	    /* cs_clear_superclient_lock(super_client); */
	    return (CS_BAD_HANDLE);
	}

	return (CS_SUCCESS);
}

/*
 * cs_add_client_to_socket - this function creates the client node on the
 *				requested socket.
 *
 * Note that if we return an error, there is no state that can be cleaned
 *	up.  The only way that we can return an error with allocated resources
 *	would be if one of the client handle functions had an internal error.
 *	Since we wouldn't get a valid client handle in this case anyway, there
 *	would be no way to find out what was allocated and what wasn't.
 */
static int
cs_add_client_to_socket(unsigned sn, client_handle_t *ch,
					client_reg_t *cr, int super_client)
{
	cs_socket_t *sp;
	client_t *client, *cclp;
	int error, cie = 1;
	int client_lock_acquired;

	if (cr->event_handler == NULL)
	    return (CS_BAD_ARGS);

	if ((sp = cs_get_sp(sn)) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 * Run through all of the registered clients and compare the passed
	 *	dip to the dip of each client to make sure that this client
	 *	is not trying to register more than once.  If they are, then
	 *	display a message and return an error.
	 * XXX - we should really check all the sockets in case the client
	 *	manipulates the instance number in the dip.
	 * XXX - if we check each socket, we ned to also check for the
	 *	"super-client" since it will use the same dip for all
	 *	of it's client nodes.
	 */
	mutex_enter(&sp->lock);
	client = sp->client_list;
	while (client) {
	    if (!(cr->Attributes & INFO_CSI_CLIENT) &&
						(client->dip == cr->dip)) {
		mutex_exit(&sp->lock);
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		cmn_err(CE_CONT, "cs_add_client_to_socket: socket %d "
					"function 0x%x\n"
					"\tclient already registered with "
					"handle 0x%x\n",
						(int)CS_GET_SOCKET_NUMBER(sn),
						(int)CS_GET_FUNCTION_NUMBER(sn),
						(int)client->client_handle);
		return (CS_BAD_HANDLE);
	    }
	    client = client->next;
	} /* while (client) */
	mutex_exit(&sp->lock);

	/*
	 * Create a unique client handle then make sure that we can find it.
	 *	This has the side effect of getting us a pointer to the
	 *	client structure as well.
	 * Create a client list entry - cs_create_client_handle will use this
	 *	as the new client node.
	 * We do it here so that we can grab the sp->lock mutex for the
	 *	duration of our manipulation of the client list.
	 * If this function fails, then it will not have added the newly
	 *	allocated client node to the client list on this socket,
	 *	so we have to free the node that we allocated.
	 */
	cclp = (client_t *)kmem_zalloc(sizeof (client_t), KM_SLEEP);

	mutex_enter(&sp->lock);
	if (!(*ch = cs_create_client_handle(sn, cclp))) {
	    mutex_exit(&sp->lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    kmem_free(cclp, sizeof (client_t));
	    return (CS_OUT_OF_RESOURCE);
	}

	/*
	 *  Make sure that this is a valid client handle.  We should never
	 *	fail this since we just got a valid client handle.
	 * If this fails, then we have an internal error so don't bother
	 *	trying to clean up the allocated client handle since the
	 *	whole system is probably hosed anyway and will shortly
	 *	esplode.
	 * It doesn't make sense to call cs_deregister_client at this point
	 *	to clean up this broken client since the deregistration
	 *	code will also call cs_find_client and most likely fail.
	 */
	if (!(client = cs_find_client(*ch, &error))) {
	    mutex_exit(&sp->lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    cmn_err(CE_CONT, "cs_add_client_to_socket: socket %d function 0x%x "
				"invalid client handle created handle 0x%x\n",
						(int)CS_GET_SOCKET_NUMBER(sn),
						(int)CS_GET_FUNCTION_NUMBER(sn),
						(int)*ch);
	    return (error);
	}

	/*
	 * Save the DDI information.
	 */
	client->dip = cr->dip;
	cr->driver_name[MODMAXNAMELEN - 1] = NULL;
	client->driver_name = (char *)kmem_zalloc(strlen(cr->driver_name) + 1,
								KM_SLEEP);
	(void) strcpy(client->driver_name, cr->driver_name);
	client->instance = ddi_get_instance(cr->dip);

	/*
	 * Copy over the interesting items that the client gave us.
	 */
	client->flags = (cr->Attributes & INFO_CLIENT_TYPE_MASK);
	client->event_callback_handler = cr->event_handler;
	bcopy((caddr_t)&cr->event_callback_args,
				(caddr_t)&client->event_callback_args,
				sizeof (event_callback_args_t));
	/*
	 * Set the client handle since the client needs a client handle
	 *	when they call us for their event handler.
	 */
	client->event_callback_args.client_handle = *ch;

	/*
	 * Initialize the IO window numbers; if an IO window number is equal
	 *	to PCMCIA_MAX_WINDOWS it means that IO range is not in use.
	 */
	client->io_alloc.Window1 = PCMCIA_MAX_WINDOWS;
	client->io_alloc.Window2 = PCMCIA_MAX_WINDOWS;

	/*
	 * Give the client the iblock and idevice cookies to use in
	 *	the client's event handler high priority mutex.
	 */
	cr->iblk_cookie = sp->iblk;
	cr->idev_cookie = sp->idev;

	/*
	 * Set up the global event mask information; we copy this directly
	 *	from the client; since we are the only source of events,
	 *	any bogus bits that the client puts in here won't matter
	 *	because we'll never look at them.
	 */
	client->global_mask = cr->EventMask;

	/*
	 * If this client registered as a CSI client, set the appropriate
	 *	flag in the client's flags area.
	 */
	if (cr->Attributes & INFO_CSI_CLIENT)
	    client->flags |= CLIENT_CSI_CLIENT;

	/*
	 * If this client registered as a "super-client" set the appropriate
	 *	flag in the client's flags area.
	 */
	if (super_client == CLIENT_SUPER_CLIENT)
	    client->flags |= CLIENT_SUPER_CLIENT;

	/*
	 * Save other misc information that this client gave us - it is
	 *	used in the GetClientInfo function.
	 */
	client->flags |= (cr->Attributes & INFO_CARD_FLAGS_MASK);

	/*
	 * Determine if we should give artificial card insertion events and
	 *	a registration complete event. Since we don't differentiate
	 *	between sharable and exclusive use cards when giving clients
	 *	event notification, we modify the definition of the share/excl
	 *	flags as follows:
	 *
	 *	    If either INFO_CARD_SHARE or INFO_CARD_EXCL is set,
	 *	    the client will receive artificial card insertion
	 *	    events (if the client's card is currently in the
	 *	    socket) and a registration complete event.
	 *
	 *	    If neither of the INFO_CARD_SHARE or INFO_CARD_EXCL is
	 *	    set, the client will not receive an artificial card
	 *	    insertion event nor a registration complete event
	 *	    due to the client's call to register client.
	 *
	 *	    The client's event mask is not affected by the setting
	 *	    of these two bits.
	 */
	if (cr->Attributes & (INFO_CARD_SHARE | INFO_CARD_EXCL))
	    client->pending_events = CS_EVENT_REGISTRATION_COMPLETE;

	/*
	 * Check to see if the card for this client is currently in
	 *	the socket. If it is, then set CLIENT_CARD_INSERTED
	 *	since clients that are calling GetStatus at attach
	 *	time will typically check to see if their card is
	 *	currently installed.
	 * If this is the CSI client, we also need to check to see
	 *	if there is any card inserted in the socket, since
	 *	the cs_card_for_client function will always return
	 *	TRUE for a CSI client.
	 * XXX What about super-clients?
	 */
	if (client->flags & CLIENT_CSI_CLIENT) {
	    get_ss_status_t get_ss_status;

	    get_ss_status.socket = sp->socket_num;

	    if (SocketServices(SS_GetStatus, &get_ss_status) != SUCCESS) {
		mutex_exit(&sp->lock);
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		return (CS_BAD_SOCKET);
	    } /* SS_GetStatus */

	    if (!(cs_sbm2cse(get_ss_status.CardState) &
			CS_EVENT_CARD_INSERTION))
		cie = 0;

	} /* CLIENT_CSI_CLIENT */

	if (cs_card_for_client(client) && (cie != 0)) {
	    client->pending_events |= CS_EVENT_CARD_INSERTION;
	    client->flags |= CLIENT_CARD_INSERTED;
	} /* cs_card_for_client */

	sp->num_clients++;
	mutex_exit(&sp->lock);
	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	return (CS_SUCCESS);
}

/*
 * cs_deregister_client - This supports the DeregisterClient call.
 */
static int
cs_deregister_client(client_handle_t client_handle)
{
	cs_socket_t *sp;
	client_t *client;
	int error, super_client = 0;
	int client_lock_acquired;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't do anything except for return success.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_SUCCESS);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	/*
	 * Make sure that any resources allocated by this client are
	 *	not still allocated, and that if this is an MTD that
	 *	no MTD operations are still in progress.
	 */
	if (client->flags &    (CLIENT_IO_ALLOCATED	|
				CLIENT_IRQ_ALLOCATED	|
				CLIENT_WIN_ALLOCATED	|
				REQ_CONFIGURATION_DONE	|
				REQ_SOCKET_MASK_DONE	|
				REQ_IO_DONE		|
				REQ_IRQ_DONE)) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BUSY);
	}

	if (client->flags & CLIENT_MTD_IN_PROGRESS) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_IN_USE);
	}

	/*
	 * Any previously allocated resources are not allocated anymore, and
	 *	no MTD operations are in progress, so if this is an MTD client
	 *	then do any MTD-specific client deregistration, and then
	 *	nuke this client.
	 * We expect cs_deregister_mtd to never fail.
	 */
	if (client->flags & INFO_MTD_CLIENT)
	    (void) cs_deregister_mtd(client_handle);

	if (client->flags & CLIENT_SUPER_CLIENT)
	    super_client = CLIENT_SUPER_CLIENT;

	kmem_free(client->driver_name, strlen(client->driver_name) + 1);

	error = cs_destroy_client_handle(client_handle);

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	/*
	 * If this was the "super-client" deregistering, then this
	 *	will clear the global "super-client" lock.
	 * XXX - move this outside the per-socket code.
	 */
	cs_clear_superclient_lock(super_client);

	return (error);
}

/*
 * cs_create_next_client_minor - returns the next available client minor
 *					number or 0 if none available
 *
 * Note that cs_find_client will always return a valid pointer to the
 *	global Socket Services client which has a client minor number
 *	of 0; this means that this function can never return a 0 as the
 *	next valid available client minor number.
 */
unsigned
cs_create_next_client_minor(unsigned socket_num, unsigned next_minor)
{
	unsigned max_client_handles = cs_max_client_handles;

	do {
	    next_minor &= CS_MAX_CLIENTS_MASK;
	    if (!cs_find_client(MAKE_CLIENT_HANDLE(
					CS_GET_SOCKET_NUMBER(socket_num),
					CS_GET_FUNCTION_NUMBER(socket_num),
							next_minor), NULL)) {
		return (next_minor);
	    }
	    next_minor++;
	} while (max_client_handles--);

	return (0);
}

/*
 * cs_find_client - finds the client pointer associated with the client handle
 *			or NULL if client not found
 *
 * returns:	(client_t *)NULL - if client not found or an error occured
 *					If the error argument is not NULL,
 *					it is set to:
 *			CS_BAD_SOCKET - socket number in client_handle_t is
 *						invalid
 *			CS_BAD_HANDLE - client not found
 *			If no error, the error argument is not modified.
 *		(client_t *) - pointer to client_t structure
 *
 * Note that each socket always has a pseudo client with a client minor number
 *	of 0; this client minor number is used for Socket Services access to
 *	Card Services functions. The client pointer returned for client minor
 *	number 0 is the global Socket Services client pointer.
 */
static client_t *
cs_find_client(client_handle_t client_handle, int *error)
{
	cs_socket_t *sp;
	client_t *clp;

	/*
	 * If we are being asked to see if a client with a minor number
	 *	of 0 exists, always return a pointer to the global Socket
	 *	Services client, since this client always exists, and is
	 *	only for use by Socket Services.  There is no socket
	 *	associated with this special client handle.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (&cs_socket_services_client);

	/*
	 * Check to be sure that the socket number is in range
	 */
	if (!(CHECK_SOCKET_NUM(GET_CLIENT_SOCKET(client_handle),
					cs_globals.max_socket_num))) {
	    if (error)
		*error = CS_BAD_SOCKET;
	    return (NULL);
	}

	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL) {
	    if (error)
		*error = CS_BAD_SOCKET;
	    return (NULL);
	}

	clp = sp->client_list;

	while (clp) {
	    if (clp->client_handle == client_handle)
		return (clp);
	    clp = clp->next;
	}

	if (error)
	    *error = CS_BAD_HANDLE;

	return (NULL);
}

/*
 * cs_destroy_client_handle - destroys client handle and client structure of
 *				passed client handle
 *
 * returns:	CS_SUCCESS - if client handle sucessfully destroyed
 *		CS_BAD_HANDLE - if client handle is invalid or if trying
 *					to destroy global SS client
 *		{other errors} - other errors from cs_find_client()
 */
static int
cs_destroy_client_handle(client_handle_t client_handle)
{
	client_t *clp;
	cs_socket_t *sp;
	int error = CS_BAD_HANDLE;

	/*
	 * See if we were passed a valid client handle or if we're being asked
	 *	to destroy the Socket Services client
	 */
	if ((!(clp = cs_find_client(client_handle, &error))) ||
			(CLIENT_HANDLE_IS_SS(client_handle)))
	    return (error);

	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	/*
	 * Recycle this client's minor number.  This will most likely
	 *	be the next client minor number we use, but it is also
	 *	a hint to cs_create_client_handle, and that function
	 *	may actually create a new client handle using a minor
	 *	number different that this number.
	 */
	mutex_enter(&sp->lock);
	sp->next_cl_minor = GET_CLIENT_MINOR(client_handle);

	/*
	 * See if we're the first or not in the client list; if we're
	 *	not first, then just adjust the client behind us to
	 *	point to the client ahead of us; this could be NULL
	 *	if we're the last client in the list.
	 */
	if (clp->prev) {
	    clp->prev->next = clp->next;
	} else {
	/*
	 * We are first, so adjust the client list head pointer
	 *	in the socket to point to the client structure that
	 *	follows us; this could turn out to be NULL if we're
	 *	the only client on this socket.
	 */
	    sp->client_list = clp->next;
	}

	/*
	 * If we're not the last client in the list, point the next
	 *	client to the client behind us; this could turn out
	 *	to be NULL if we're the first client on this socket.
	 */
	if (clp->next)
	    clp->next->prev = clp->prev;

	sp->num_clients--;
	mutex_exit(&sp->lock);

	/*
	 * Free this client's memory.
	 */
	kmem_free(clp, sizeof (client_t));

	return (CS_SUCCESS);
}

/*
 * cs_create_client_handle - create a new client handle for the passed
 *				socket and function number
 *
 * returns:	0 -  if can't create client for some reason
 *		client_handle_t - new client handle
 */
static client_handle_t
cs_create_client_handle(unsigned socket_num, client_t *cclp)
{
	client_t *clp;
	cs_socket_t *sp;
	unsigned next_minor;
	client_handle_t client_handle;

	if ((sp = cs_get_sp(socket_num)) == NULL)
	    return (0);

	/*
	 * Get the next available minor number that we can use.  We use the
	 *	next_cl_minor number as a hint to cs_create_next_client_minor
	 *	and in most cases this will be the minor number we get back.
	 * If for some reason we can't get a minor number, return an error.
	 *	The only way we could get an error would be if there are
	 *	already the maximum number of clients for this socket. Since
	 *	the maximum number of clients per socket is pretty large,
	 *	this error is unlikely to occur.
	 */
	if (!(next_minor =
		cs_create_next_client_minor(socket_num, sp->next_cl_minor)))
	    return (0);

	/*
	 * Got a new client minor number, now create a new client handle.
	 */
	client_handle = MAKE_CLIENT_HANDLE(CS_GET_SOCKET_NUMBER(socket_num),
					CS_GET_FUNCTION_NUMBER(socket_num),
					next_minor);

	/*
	 * If this client handle exists, then we have an internal
	 *	error; this should never happen, BTW.  This is really
	 *	a double-check on the cs_create_next_client_minor
	 *	function, which also calls cs_find_client.
	 */
	if (cs_find_client(client_handle, NULL)) {
	    cmn_err(CE_CONT,
		"cs_create_client_handle: duplicate client handle 0x%x\n",
							(int)client_handle);
	    return (0);
	}

	/*
	 * If we don't have any clients on this socket yet, create
	 *	a new client and hang it on the socket client list.
	 */
	if (!sp->client_list) {
	    sp->client_list = cclp;
	    clp = sp->client_list;
	} else {
	/*
	 * There are other clients on this socket, so look for
	 *	the last client and add our new client after it.
	 */
	    clp = sp->client_list;
	    while (clp->next) {
		clp = clp->next;
	    }

	    clp->next = cclp;
	    clp->next->prev = clp;
	    clp = clp->next;
	} /* if (!sp->client_list) */

	/*
	 * Assign the new client handle to this new client structure.
	 */
	clp->client_handle = client_handle;

	/*
	 * Create the next available client minor number for this socket
	 *	and save it away.
	 */
	sp->next_cl_minor =
		cs_create_next_client_minor(socket_num, sp->next_cl_minor);

	return (client_handle);
}

/*
 * cs_clear_superclient_lock - clears the global "super-client" lock
 *
 * Note: this function uses the cs_globals.global_lock so observe proper
 *		nexting of locks!!
 */
static void
cs_clear_superclient_lock(int super_client)
{

	/*
	 * If this was a "super-client" registering then we need
	 *	to clear the GLOBAL_SUPER_CLIENT_REGISTERED flag
	 *	so that other "super-clients" can register.
	 */
	if (super_client == CLIENT_SUPER_CLIENT) {
	    mutex_enter(&cs_globals.global_lock);
	    cs_globals.flags &= ~GLOBAL_SUPER_CLIENT_REGISTERED;
	    mutex_exit(&cs_globals.global_lock);
	}
}

/*
 * ==== event handling section ====
 */

/*
 * cs_event - CS event hi-priority callback handler
 *
 *	This function gets called by SS and is passed the event type in
 *		the "event" argument, and the socket number in the "sn"
 *		argument. The "sn" argument is a valid logical socket
 *		number for all events except the PCE_SS_READY event.
 *
 *	The PCE_SS_INIT_STATE, PCE_ADD_SOCKET and PCE_DROP_SOCKET events
 *		are never called at high priority. These events return
 *		the following return codes:
 *
 *			CS_SUCCESS - operation sucessful
 *			CS_BAD_SOCKET - unable to complete operation
 *			CS_UNSUPPORTED_FUNCTION - bad subfunction of
 *							PCE_SS_INIT_STATE
 *
 *		The caller MUST look at these return codes!
 *
 *	This function is called at high-priority interrupt time for standard
 *		Card Services events, and the only standard Card Services
 *		event that it handles directly is the CS_EVENT_CARD_REMOVAL
 *		event, which gets shuttled right into the client's event
 *		handler.  All other events are just queued up and the socket
 *		event thread is woken up via the soft interrupt handler.
 *	Note that CS_EVENT_CARD_INSERTION events are not set in the clients'
 *		event field, since the CS card insertion/card ready processing
 *		code is responsible for setting this event in a client's
 *		event field.
 *
 */
/*ARGSUSED*/
uint32_t
cs_event(event_t event, uint32_t sn, uint32_t arg)
{
	client_t *client;
	cs_socket_t *sp;
	client_types_t *ct;
	uint32_t ret = CS_SUCCESS;

	/*
	 * Handle special SS<->CS events
	 */
	switch (event) {
	    case PCE_SS_INIT_STATE:
		mutex_enter(&cs_globals.global_lock);
		switch (sn) {
		    case PCE_SS_STATE_INIT:
			if ((ret = cs_ss_init()) == CS_SUCCESS)
			    cs_globals.init_state |= GLOBAL_INIT_STATE_SS_READY;
			break;
		    case PCE_SS_STATE_DEINIT:
			cs_globals.init_state &= ~GLOBAL_INIT_STATE_SS_READY;
			break;
		    default:
			ret = CS_UNSUPPORTED_FUNCTION;
			cmn_err(CE_CONT, "cs_event: PCE_SS_INIT_STATE invalid "
						"directive: 0x%x\n", sn);
			break;
		} /* switch (sn) */
		mutex_exit(&cs_globals.global_lock);
		return (ret);
	    case PCE_ADD_SOCKET:
		return (cs_add_socket(sn));
	    case PCE_DROP_SOCKET:
		return (cs_drop_socket(sn));
	} /* switch (event) */

	if ((sp = cs_get_sp(sn)) == NULL)
	    return (CS_BAD_SOCKET);

	/*
	 * Check to see if CS wants to unload - we do this since it's possible
	 *	to disable certain sockets.  Do NOT acquire any locks yet.
	 */
	if (sp->flags & SOCKET_UNLOAD_MODULE) {
	    if (event == PCE_CARD_INSERT)
		cmn_err(CE_CONT, "PCMCIA: socket %d disabled - please "
							"remove card\n", sn);
	    return (CS_SUCCESS);
	}

	mutex_enter(&sp->lock);

#ifdef	CS_DEBUG
	if (cs_debug > 1) {
	    event2text_t event2text;

	    event2text.event = event;
	    (void) cs_event2text(&event2text, 0);
	    cmn_err(CE_CONT, "cs_event: event=%s (x%x), socket=0x%x\n",
				event2text.text, (int)event, (int)sn);
	}
#endif

	/*
	 * Convert SS events to CS events; handle the PRR if necessary.
	 */
	sp->events |= ss_to_cs_events(sp, event);

	/*
	 * We want to maintain the required event dispatching order as
	 *	specified in the PCMCIA spec, so we cycle through all
	 *	clients on this socket to make sure that they are
	 *	notified in the correct order of any high-priority
	 *	events.
	 */
	ct = &client_types[0];
	while (ct) {
	/*
	 * Point to the head of the client list for this socket, and go
	 *	through each client to set up the client events as well as
	 *	call the client's event handler directly if we have a high
	 *	priority event that we need to tell the client about.
	 */
	    client = sp->client_list;

	    if (ct->order & CLIENT_EVENTS_LIFO) {
		client_t *clp = NULL;

		while (client) {
		    clp = client;
		    client = client->next;
		}
		client = clp;
	    }

	    while (client) {
		client->events |= ((sp->events & ~CS_EVENT_CARD_INSERTION) &
				    (client->event_mask | client->global_mask));
		if (client->flags & ct->type) {
#ifdef	CS_DEBUG
		    if (cs_debug > 1) {
			cmn_err(CE_CONT, "cs_event: socket %d client [%s] "
						"events 0x%x flags 0x%x\n",
						sn, client->driver_name,
						(int)client->events,
						(int)client->flags);
		    }
#endif

		/*
		 * Handle the suspend and card removal events
		 *	specially here so that the client can receive
		 *	these events at high-priority.
		 */
		    if (client->events & CS_EVENT_PM_SUSPEND) {
			if (client->flags & CLIENT_CARD_INSERTED) {
			    CLIENT_EVENT_CALLBACK(client, CS_EVENT_PM_SUSPEND,
							CS_EVENT_PRI_HIGH);
			} /* if (CLIENT_CARD_INSERTED) */
			client->events &= ~CS_EVENT_PM_SUSPEND;
		    } /* if (CS_EVENT_PM_SUSPEND) */

		    if (client->events & CS_EVENT_CARD_REMOVAL) {
			if (client->flags & CLIENT_CARD_INSERTED) {
			    client->flags &= ~(CLIENT_CARD_INSERTED |
						CLIENT_SENT_INSERTION);
			    CLIENT_EVENT_CALLBACK(client,
							CS_EVENT_CARD_REMOVAL,
							CS_EVENT_PRI_HIGH);
			/*
			 * Check to see if the client wants low priority
			 *	removal events as well.
			 */
			    if ((client->event_mask | client->global_mask) &
						CS_EVENT_CARD_REMOVAL_LOWP) {
				client->events |= CS_EVENT_CARD_REMOVAL_LOWP;
			    }
			} /* if (CLIENT_CARD_INSERTED) */
			client->events &= ~CS_EVENT_CARD_REMOVAL;
		    } /* if (CS_EVENT_CARD_REMOVAL) */

		} /* if (ct->type) */
		if (ct->order & CLIENT_EVENTS_LIFO) {
		    client = client->prev;
		} else {
		    client = client->next;
		}
	    } /* while (client) */

	    ct = ct->next;
	} /* while (ct) */

	/*
	 * Set the SOCKET_NEEDS_THREAD flag so that the soft interrupt
	 *	handler will wakeup this socket's event thread.
	 */
	if (sp->events)
	    sp->flags |= SOCKET_NEEDS_THREAD;

	/*
	 * Fire off a soft interrupt that will cause the socket thread
	 *	to be woken up and any remaining events to be sent to
	 *	the clients on this socket.
	 */
	if ((sp->init_state & SOCKET_INIT_STATE_SOFTINTR) &&
			!(cs_globals.init_state & GLOBAL_INIT_STATE_UNLOADING))
	    ddi_trigger_softintr(sp->softint_id);

	mutex_exit(&sp->lock);

	return (CS_SUCCESS);
}

/*
 * cs_card_insertion - handle card insertion and card ready events
 *
 * We read the CIS, if present, and store it away, then tell SS that
 *	we have read the CIS and it's ready to be parsed.  Since card
 *	insertion and card ready events are pretty closely intertwined,
 *	we handle both here.  For card ready events that are not the
 *	result of a card insertion event, we expect that the caller has
 *	already done the appropriate processing and that we will not be
 *	called unless we received a card ready event right after a card
 *	insertion event, i.e. that the SOCKET_WAIT_FOR_READY flag in
 *	sp->thread_state was set or if we get a CARD_READY event right
 *	after a CARD_INSERTION event.
 *
 *    calling:	sp - pointer to socket structure
 *		event - event to handle, one of:
 *				CS_EVENT_CARD_INSERTION
 *				CS_EVENT_CARD_READY
 *				CS_EVENT_SS_UPDATED
 */
static int
cs_card_insertion(cs_socket_t *sp, event_t event)
{
	int ret;

	/*
	 * Since we're only called while waiting for the card insertion
	 *	and card ready sequence to occur, we may have a pending
	 *	card ready timer that hasn't gone off yet if we got a
	 *	real card ready event.
	 */
	UNTIMEOUT(sp->rdybsy_tmo_id);

#ifdef	CS_DEBUG
	if (cs_debug > 1) {
	    cmn_err(CE_CONT, "cs_card_insertion: event=0x%x, socket=0x%x\n",
						(int)event, sp->socket_num);
	}
#endif

	/*
	 * Handle card insertion processing
	 */
	if (event & CS_EVENT_CARD_INSERTION) {
	    set_socket_t set_socket;
	    get_ss_status_t gs;

	/*
	 * Check to be sure that we have a valid CIS window
	 */
	    if (!SOCKET_HAS_CIS_WINDOW(sp)) {
		cmn_err(CE_CONT,
			"cs_card_insertion: socket %d has no "
							"CIS window\n",
				sp->socket_num);
		return (CS_GENERAL_FAILURE);
	    }

	/*
	 * Apply power to the socket, enable card detect and card ready
	 *	events, then reset the socket.
	 */
	    mutex_enter(&sp->lock);
	    sp->event_mask =   (CS_EVENT_CARD_REMOVAL   |
				CS_EVENT_CARD_READY);
	    mutex_exit(&sp->lock);
	    set_socket.socket = sp->socket_num;
	    set_socket.SCIntMask = (SBM_CD | SBM_RDYBSY);
	    set_socket.IREQRouting = 0;
	    set_socket.IFType = IF_MEMORY;
	    set_socket.CtlInd = 0; /* turn off controls and indicators */
	    set_socket.State = (unsigned)~0;	/* clear latched state bits */

	    (void) cs_convert_powerlevel(sp->socket_num, 50, VCC,
						&set_socket.VccLevel);
	    (void) cs_convert_powerlevel(sp->socket_num, 50, VPP1,
						&set_socket.Vpp1Level);
	    (void) cs_convert_powerlevel(sp->socket_num, 50, VPP2,
						&set_socket.Vpp2Level);

	    if ((ret = SocketServices(SS_SetSocket, &set_socket)) != SUCCESS) {
		cmn_err(CE_CONT,
		    "cs_card_insertion: socket %d SS_SetSocket failure %d\n",
				sp->socket_num, ret);
		return (ret);
	    }

	/*
	 * Clear the ready and ready_timeout events since they are now
	 *	bogus since we're about to reset the socket.
	 * XXX - should these be cleared right after the RESET??
	 */
	    mutex_enter(&sp->lock);

	    sp->events &= ~(CS_EVENT_CARD_READY | CS_EVENT_READY_TIMEOUT);
	    mutex_exit(&sp->lock);

	    SocketServices(SS_ResetSocket, sp->socket_num,
						RESET_MODE_CARD_ONLY);

	/*
	 * We are required by the PCMCIA spec to wait some number of
	 *	milliseconds after reset before we access the card, so
	 *	we set up a timer here that will wake us up and allow us
	 *	to continue with our card initialization.
	 */
	    mutex_enter(&sp->lock);
	    sp->thread_state |= SOCKET_RESET_TIMER;
	    (void) timeout(cs_ready_timeout, sp,
		drv_usectohz(cs_reset_timeout_time * 1000));
	    cv_wait(&sp->reset_cv, &sp->lock);
	    sp->thread_state &= ~SOCKET_RESET_TIMER;
	    mutex_exit(&sp->lock);

#ifdef	CS_DEBUG
	    if (cs_debug > 2) {
		cmn_err(CE_CONT, "cs_card_insertion: socket %d out of RESET "
		    "for %d mS sp->events 0x%x\n",
		    sp->socket_num, cs_reset_timeout_time, (int)sp->events);
	    }
#endif

	/*
	 * If we have a pending CS_EVENT_CARD_REMOVAL event it
	 *	means that we likely got CD line bounce on the
	 *	insertion, so terminate this processing.
	 */
	    if (sp->events & CS_EVENT_CARD_REMOVAL) {
#ifdef	CS_DEBUG
		if (cs_debug > 0) {
		    cmn_err(CE_CONT, "cs_card_insertion: socket %d "
						"CS_EVENT_CARD_REMOVAL event "
						"terminating insertion "
						"processing\n",
							sp->socket_num);
		}
#endif
	    return (CS_SUCCESS);
	    } /* if (CS_EVENT_CARD_REMOVAL) */

	/*
	 * If we got a card ready event after the reset, then don't
	 *	bother setting up a card ready timer, since we'll blast
	 *	right on through to the card ready processing.
	 * Get the current card status to see if it's ready; if it
	 *	is, we probably won't get a card ready event.
	 */
	    gs.socket = sp->socket_num;
	    gs.CardState = 0;
	    if ((ret = SocketServices(SS_GetStatus, &gs)) != SUCCESS) {
		cmn_err(CE_CONT,
		    "cs_card_insertion: socket %d SS_GetStatus failure %d\n",
				sp->socket_num, ret);
		return (ret);
	    }

	    mutex_enter(&sp->lock);
	    if ((sp->events & CS_EVENT_CARD_READY) ||
					(gs.CardState & SBM_RDYBSY)) {
		event = CS_EVENT_CARD_READY;
#ifdef	CS_DEBUG
		if (cs_debug > 1) {
		    cmn_err(CE_CONT, "cs_card_insertion: socket %d card "
						"READY\n", sp->socket_num);
		}
#endif

	    } else {
#ifdef	CS_DEBUG
		if (cs_debug > 1) {
		    cmn_err(CE_CONT, "cs_card_insertion: socket %d setting "
					"READY timer\n", sp->socket_num);
		}
#endif

		sp->rdybsy_tmo_id = timeout(cs_ready_timeout, sp,
		    READY_TIMEOUT_TIME);
		sp->thread_state |= SOCKET_WAIT_FOR_READY;

	    } /* if (CS_EVENT_CARD_READY) */

	    mutex_exit(&sp->lock);

	} /* if (CS_EVENT_CARD_INSERTION) */

	/*
	 * Handle card ready processing.  This is only card ready processing
	 *	for card ready events in conjunction with a card insertion.
	 */
	if (event == CS_EVENT_CARD_READY) {
	    get_socket_t get_socket;
	    set_socket_t set_socket;

	/*
	 * The only events that we want to see now are card removal
	 *	events.
	 */
	    mutex_enter(&sp->lock);
	    sp->event_mask = CS_EVENT_CARD_REMOVAL;
	    mutex_exit(&sp->lock);
	    get_socket.socket = sp->socket_num;
	    if (SocketServices(SS_GetSocket, &get_socket) != SUCCESS) {
		cmn_err(CE_CONT,
			"cs_card_insertion: socket %d SS_GetSocket failed\n",
							sp->socket_num);
		return (CS_BAD_SOCKET);
	    }

	    set_socket.socket = sp->socket_num;
	    set_socket.SCIntMask = SBM_CD;
	    set_socket.VccLevel = get_socket.VccLevel;
	    set_socket.Vpp1Level = get_socket.Vpp1Level;
	    set_socket.Vpp2Level = get_socket.Vpp2Level;
	    set_socket.IREQRouting = get_socket.IRQRouting;
	    set_socket.IFType = get_socket.IFType;
	    set_socket.CtlInd = get_socket.CtlInd;
	    /* XXX (is ~0 correct here?) to reset latched values */
	    set_socket.State = (unsigned)~0;

	    if (SocketServices(SS_SetSocket, &set_socket) != SUCCESS) {
		cmn_err(CE_CONT,
			"cs_card_insertion: socket %d SS_SetSocket failed\n",
							sp->socket_num);

		return (CS_BAD_SOCKET);
	    }

		/*
		 * Grab the cis_lock mutex to protect the CIS-to-be and
		 *	the CIS window, then fire off the CIS parser to
		 *	create a local copy of the card's CIS.
		 */
		mutex_enter(&sp->cis_lock);

		if ((ret = cs_create_cis(sp)) != CS_SUCCESS) {
		    mutex_exit(&sp->cis_lock);
		    return (ret);
		}

		mutex_exit(&sp->cis_lock);

		/*
		 * If we have a pending CS_EVENT_CARD_REMOVAL event it
		 *	means that we likely got CD line bounce on the
		 *	insertion, so destroy the CIS and terminate this
		 *	processing. We'll get called back to handle the
		 *	insertion again later.
		 */
		if (sp->events & CS_EVENT_CARD_REMOVAL) {
		    mutex_enter(&sp->cis_lock);
		    (void) cs_destroy_cis(sp);
		    mutex_exit(&sp->cis_lock);
		} else {
			/*
			 * Schedule the call to the Socket Services work thread.
			 */
		    mutex_enter(&sp->ss_thread_lock);
		    sp->ss_thread_state |= SOCKET_THREAD_CSCISInit;
		    cv_broadcast(&sp->ss_thread_cv);
		    mutex_exit(&sp->ss_thread_lock);
		} /* if (CS_EVENT_CARD_REMOVAL) */
	} /* if (CS_EVENT_CARD_READY) */

	/*
	 * Socket Services has parsed the CIS and has done any other
	 *	work to get the client driver loaded and attached if
	 *	necessary, so setup the per-client state.
	 */
	if (event == CS_EVENT_SS_UPDATED) {
	    client_t *client;

	/*
	 * Now that we and SS are done handling the card insertion
	 *	semantics, go through each client on this socket and set
	 *	the CS_EVENT_CARD_INSERTION event in each client's event
	 *	field.  We do this here instead of in cs_event so that
	 *	when a client gets a CS_EVENT_CARD_INSERTION event, the
	 *	card insertion and ready processing has already been done
	 *	and SocketServices has had a chance to create a dip for
	 *	the card in this socket.
	 */
	    mutex_enter(&sp->lock);
	    client = sp->client_list;
	    while (client) {
		client->events |= (CS_EVENT_CARD_INSERTION &
				(client->event_mask | client->global_mask));
		client = client->next;
	    } /* while (client) */

	    mutex_exit(&sp->lock);

	} /* if (CS_EVENT_SS_UPDATED) */

	return (CS_SUCCESS);
}

/*
 * cs_card_removal - handle card removal events
 *
 * Destroy the CIS.
 *
 *    calling:	sp - pointer to socket structure
 *
 */
static int
cs_card_removal(cs_socket_t *sp)
{
	set_socket_t set_socket;
	int ret;

#ifdef	CS_DEBUG
	if (cs_debug > 0) {
	    cmn_err(CE_CONT, "cs_card_removal: socket %d\n", sp->socket_num);
	}
#endif

	/*
	 * Remove any pending card ready timer
	 */
	UNTIMEOUT(sp->rdybsy_tmo_id);

	/*
	 * Clear various flags so that everyone else knows that there's
	 *	nothing on this socket anymore.  Note that we clear the
	 *	SOCKET_CARD_INSERTED and SOCKET_IS_IO flags in the
	 *	ss_to_cs_events event mapping function.
	 */
	mutex_enter(&sp->lock);
	sp->thread_state &= ~(SOCKET_WAIT_FOR_READY | SOCKET_RESET_TIMER);

	/*
	 * Turn off socket power and set the socket back to memory mode.
	 * Disable all socket events except for CARD_INSERTION events.
	 */
	sp->event_mask = CS_EVENT_CARD_INSERTION;
	mutex_exit(&sp->lock);
	set_socket.socket = sp->socket_num;
	set_socket.SCIntMask = SBM_CD;
	set_socket.IREQRouting = 0;
	set_socket.IFType = IF_MEMORY;
	set_socket.CtlInd = 0; /* turn off controls and indicators */
	set_socket.State = (unsigned)~0;	/* clear latched state bits */

	(void) cs_convert_powerlevel(sp->socket_num, 0, VCC,
					&set_socket.VccLevel);
	(void) cs_convert_powerlevel(sp->socket_num, 0, VPP1,
					&set_socket.Vpp1Level);
	(void) cs_convert_powerlevel(sp->socket_num, 0, VPP2,
					&set_socket.Vpp2Level);

	if ((ret = SocketServices(SS_SetSocket, &set_socket)) != SUCCESS) {
	    cmn_err(CE_CONT,
		"cs_card_removal: socket %d SS_SetSocket failure %d\n",
				sp->socket_num, ret);
	    return (ret);
	}

#ifdef	CS_DEBUG
	if (cs_debug > 2) {
	    cmn_err(CE_CONT, "cs_card_removal: socket %d "
					"calling cs_destroy_cis\n",
							sp->socket_num);
	}
#endif

	/*
	 * Destroy the CIS and tell Socket Services that we're done
	 *	handling the card removal event.
	 */
	mutex_enter(&sp->cis_lock);
	(void) cs_destroy_cis(sp);
	mutex_exit(&sp->cis_lock);

#ifdef	CS_DEBUG
	if (cs_debug > 2) {
	    cmn_err(CE_CONT, "cs_card_removal: calling CSCardRemoved\n");
	}
#endif

	SocketServices(CSCardRemoved, sp->socket_num);

	return (CS_SUCCESS);
}

/*
 * ss_to_cs_events - convert Socket Services events to Card Services event
 *			masks; this function will not read the PRR if the
 *			socket is in IO mode; this happens in cs_event_thread
 *
 * This function returns a bit mask of events.
 *
 * Note that we do some simple hysterious on card insertion and card removal
 *	events to prevent spurious insertion and removal events from being
 *	propogated down the chain.
 */
static event_t
ss_to_cs_events(cs_socket_t *sp, event_t event)
{
	event_t revent = 0;

	switch (event) {
	    case PCE_CARD_STATUS_CHANGE:
		revent |= CS_EVENT_STATUS_CHANGE;
		break;
	    case PCE_CARD_REMOVAL:
		if (sp->flags & SOCKET_CARD_INSERTED) {
		    sp->flags &= ~(SOCKET_CARD_INSERTED | SOCKET_IS_IO);
		    revent |= CS_EVENT_CARD_REMOVAL;
			/*
			 * If we're processing a removal event, it makes
			 *	no sense to keep any insertion or ready events,
			 *	so nuke them here.  This will not clear any
			 *	insertion events in the per-client event field.
			 */
		    sp->events &= ~(CS_EVENT_CARD_INSERTION |
				    CS_EVENT_CARD_READY |
				    CS_EVENT_READY_TIMEOUT);

		/*
		 * We also don't need to wait for READY anymore since
		 *	it probably won't show up, or if it does, it will
		 *	be a bogus READY event as the card is sliding out
		 *	of the socket.  Since we never do a cv_wait on the
		 *	card ready timer, it's OK for that timer to either
		 *	never go off (via an UNTIMEOUT in cs_card_removal)
		 *	or to go off but not do a cv_broadcast (since the
		 *	SOCKET_WAIT_FOR_READY flag is cleared here).
		 */
		    sp->thread_state &= ~SOCKET_WAIT_FOR_READY;

		}
		break;
	    case PCE_CARD_INSERT:
		if (!(sp->flags & SOCKET_CARD_INSERTED)) {
		    sp->flags |= SOCKET_CARD_INSERTED;
		    revent |= CS_EVENT_CARD_INSERTION;
		}
		break;
	    case PCE_CARD_READY:
		if (sp->flags & SOCKET_CARD_INSERTED)
		    revent |= CS_EVENT_CARD_READY;
		break;
	    case PCE_CARD_BATTERY_WARN:
		if (sp->flags & SOCKET_CARD_INSERTED)
		    revent |= CS_EVENT_BATTERY_LOW;
		break;
	    case PCE_CARD_BATTERY_DEAD:
		if (sp->flags & SOCKET_CARD_INSERTED)
		    revent |= CS_EVENT_BATTERY_DEAD;
		break;
	    case PCE_CARD_WRITE_PROTECT:
		if (sp->flags & SOCKET_CARD_INSERTED)
		    revent |= CS_EVENT_WRITE_PROTECT;
		break;
	    case PCE_PM_RESUME:
		revent |= CS_EVENT_PM_RESUME;
		break;
	    case PCE_PM_SUSPEND:
		revent |= CS_EVENT_PM_SUSPEND;
		break;
	    default:
		cmn_err(CE_CONT, "ss_to_cs_events: unknown event 0x%x\n",
								(int)event);
		break;
	} /* switch(event) */

	return (revent);
}

/*
 * cs_ready_timeout - general purpose READY/BUSY and RESET timer
 *
 * Note that we really only expect one of the two events to be asserted when
 *	we are called.  XXX - Perhaps this might be a problem later on??
 *
 *	There is also the problem of cv_broadcast dropping the interrupt
 *	priority, even though we have our high-priority mutex held.  If
 *	we hold our high-priority mutex (sp->lock) over a cv_broadcast, and
 *	we get a high-priority interrupt during this time, the system will
 *	deadlock or panic.  Thanks to Andy Banta for finding this out in
 *	the SPC/S (stc.c) driver.
 *
 * This callback routine can not grab the sp->client_lock mutex or deadlock
 *	will result.
 */
void
cs_ready_timeout(void *arg)
{
	cs_socket_t *sp = arg;
	kcondvar_t *cvp = NULL;

	mutex_enter(&sp->lock);

	if (sp->thread_state & SOCKET_RESET_TIMER) {
#ifdef	CS_DEBUG
	if (cs_debug > 1) {
	    cmn_err(CE_CONT, "cs_ready_timeout: SOCKET_RESET_TIMER socket %d\n",
							sp->socket_num);
	}
#endif

	    cvp = &sp->reset_cv;
	}

	if (sp->thread_state & SOCKET_WAIT_FOR_READY) {
	    sp->events |= CS_EVENT_READY_TIMEOUT;
	    cvp = &sp->thread_cv;

#ifdef	CS_DEBUG
	    if (cs_debug > 1) {
		cmn_err(CE_CONT, "cs_ready_timeout: SOCKET_WAIT_FOR_READY "
						"socket %d\n", sp->socket_num);
	    }
#endif

	}

	mutex_exit(&sp->lock);

	if (cvp)
	    cv_broadcast(cvp);
}

/*
 * cs_event_softintr_timeout - wrapper function to call cs_socket_event_softintr
 */
/* ARGSUSED */
void
cs_event_softintr_timeout(void *arg)
{

	/*
	 * If we're trying to unload this module, then don't do
	 *	anything but exit.
	 * We acquire the cs_globals.global_lock mutex here so that
	 *	we can correctly synchronize with cs_deinit when it
	 *	is telling us to shut down. XXX - is this bogus??
	 */
	mutex_enter(&cs_globals.global_lock);
	if (!(cs_globals.init_state & GLOBAL_INIT_STATE_UNLOADING)) {
	    mutex_exit(&cs_globals.global_lock);
	    (void) cs_socket_event_softintr(NULL);
	    cs_globals.sotfint_tmo = timeout(cs_event_softintr_timeout,
		NULL, SOFTINT_TIMEOUT_TIME);
	} else {
	    mutex_exit(&cs_globals.global_lock);
	}
}

/*
 * cs_socket_event_softintr - This function just does a cv_broadcast on behalf
 *				of the high-priority interrupt handler.
 *
 *	Note: There is no calling argument.
 */
/*ARGSUSED*/
uint32_t
cs_socket_event_softintr(caddr_t notused)
{
	cs_socket_t *sp;
	uint32_t sn;
	int ret = DDI_INTR_UNCLAIMED;

	/*
	 * If the module is on it's way out, then don't bother
	 *	to do anything else except return.
	 */
	mutex_enter(&cs_globals.global_lock);
	if ((cs_globals.init_state & GLOBAL_INIT_STATE_UNLOADING) ||
				(cs_globals.init_state & GLOBAL_IN_SOFTINTR)) {
		mutex_exit(&cs_globals.global_lock);

		/*
		 * Note that we return DDI_INTR_UNCLAIMED here
		 *	since we don't want to be constantly
		 *	called back.
		 */
		return (ret);
	} else {
	    cs_globals.init_state |= GLOBAL_IN_SOFTINTR;
	    mutex_exit(&cs_globals.global_lock);
	}

	/*
	 * Go through each socket and dispatch the appropriate events.
	 *	We have to funnel everything through this one routine because
	 *	we can't do a cv_broadcast from a high level interrupt handler
	 *	and we also can't have more than one soft interrupt handler
	 *	on a single dip and using the same handler address.
	 */
	for (sn = 0; sn < cs_globals.max_socket_num; sn++) {
	    if ((sp = cs_get_sp(sn)) != NULL) {
		if (sp->init_state & SOCKET_INIT_STATE_READY) {
			/*
			 * If we're being asked to unload CS, then don't bother
			 *	waking up the socket event thread handler.
			 */
		    if (!(sp->flags & SOCKET_UNLOAD_MODULE) &&
					(sp->flags & SOCKET_NEEDS_THREAD)) {
			ret = DDI_INTR_CLAIMED;
			mutex_enter(&sp->client_lock);
			cv_broadcast(&sp->thread_cv);
			mutex_exit(&sp->client_lock);
		    } /* if (SOCKET_NEEDS_THREAD) */
		} /* if (SOCKET_INIT_STATE_READY) */
	    } /* cs_get_sp */
	} /* for (sn) */

	mutex_enter(&cs_globals.global_lock);
	cs_globals.init_state &= ~GLOBAL_IN_SOFTINTR;
	mutex_exit(&cs_globals.global_lock);

	return (ret);
}

/*
 * cs_event_thread - This is the per-socket event thread.
 */
static void
cs_event_thread(uint32_t sn)
{
	cs_socket_t	*sp;
	client_t	*client;
	client_types_t	*ct;

	if ((sp = cs_get_sp(sn)) == NULL)
	    return;

#ifdef	CS_DEBUG
	if (cs_debug > 1) {
	    cmn_err(CE_CONT, "cs_event_thread: socket %d thread started\n",
								sp->socket_num);
	}
#endif

	CALLB_CPR_INIT(&sp->cprinfo_cs, &sp->client_lock,
					callb_generic_cpr, "cs_event_thread");

	mutex_enter(&sp->client_lock);

	for (;;) {

	    CALLB_CPR_SAFE_BEGIN(&sp->cprinfo_cs);
	    cv_wait(&sp->thread_cv, &sp->client_lock);
	    CALLB_CPR_SAFE_END(&sp->cprinfo_cs, &sp->client_lock);

	    mutex_enter(&sp->lock);
	    sp->flags &= ~SOCKET_NEEDS_THREAD;
	    mutex_exit(&sp->lock);

	/*
	 * Check to see if there are any special thread operations that
	 *	we are being asked to perform.
	 */
	    if (sp->thread_state & SOCKET_THREAD_EXIT) {
#ifdef	CS_DEBUG
		if (cs_debug > 1) {
		    cmn_err(CE_CONT, "cs_event_thread: socket %d "
							"SOCKET_THREAD_EXIT\n",
							sp->socket_num);
		}
#endif
		CALLB_CPR_EXIT(&sp->cprinfo_cs);
		cv_broadcast(&sp->caller_cv);	/* wakes up cs_deinit */
		mutex_exit(&sp->client_lock);
		return;
	    } /* if (SOCKET_THREAD_EXIT) */

#ifdef	CS_DEBUG
	    if (cs_debug > 1) {
		cmn_err(CE_CONT, "cs_event_thread: socket %d sp->events 0x%x\n",
							sp->socket_num,
							(int)sp->events);
	    }
#endif

	/*
	 * Handle CS_EVENT_CARD_INSERTION events
	 */
	    if (sp->events & CS_EVENT_CARD_INSERTION) {
		mutex_enter(&sp->lock);
		sp->events &= ~CS_EVENT_CARD_INSERTION;
		mutex_exit(&sp->lock);

		/*
		 * If we have a pending CS_EVENT_CARD_REMOVAL event it
		 *	means that we likely got CD line bounce on the
		 *	insertion, so terminate this processing.
		 */
		if ((sp->events & CS_EVENT_CARD_REMOVAL) == 0) {
		    (void) cs_card_insertion(sp, CS_EVENT_CARD_INSERTION);
		}
#ifdef	CS_DEBUG
		else if (cs_debug > 0) {
			cmn_err(CE_CONT, "cs_event_thread: socket %d "
					"CS_EVENT_CARD_REMOVAL event "
					"terminating "
					"CS_EVENT_CARD_INSERTION "
					"processing\n", sp->socket_num);
		    }
#endif
	} /* if (CS_EVENT_CARD_INSERTION) */

	/*
	 * Handle CS_EVENT_CARD_READY and CS_EVENT_READY_TIMEOUT events
	 */
	    if (sp->events & (CS_EVENT_CARD_READY | CS_EVENT_READY_TIMEOUT)) {
		mutex_enter(&sp->lock);
		sp->events &= ~(CS_EVENT_CARD_READY | CS_EVENT_READY_TIMEOUT);
		mutex_exit(&sp->lock);
		if (sp->thread_state & SOCKET_WAIT_FOR_READY) {
		    mutex_enter(&sp->lock);
		    sp->thread_state &= ~SOCKET_WAIT_FOR_READY;
		    mutex_exit(&sp->lock);
		    (void) cs_card_insertion(sp, CS_EVENT_CARD_READY);
		} /* if (SOCKET_WAIT_FOR_READY) */
	    } /* if (CS_EVENT_CARD_READY) */

	/*
	 * Handle CS_EVENT_SS_UPDATED events
	 */
	    if (sp->events & CS_EVENT_SS_UPDATED) {
		mutex_enter(&sp->lock);
		sp->events &= ~CS_EVENT_SS_UPDATED;
		mutex_exit(&sp->lock);
		(void) cs_card_insertion(sp, CS_EVENT_SS_UPDATED);
	    } /* if (CS_EVENT_SS_UPDATED) */

	/*
	 * Handle CS_EVENT_STATUS_CHANGE events
	 */
	    if (sp->events & CS_EVENT_STATUS_CHANGE) {
		event_t revent;

		mutex_enter(&sp->cis_lock);
		mutex_enter(&sp->lock);
		sp->events &= ~CS_EVENT_STATUS_CHANGE;

		/*
		 * Go through each client and add any events that we saw to
		 *	the client's event list if the client has that event
		 *	enabled in their event mask.
		 * Remove any events that may be pending for this client if
		 *	the client's event mask says that the client doesn't
		 *	want to see those events anymore. This handles the
		 *	case where the client had an event enabled in it's
		 *	event mask when the event came in but between that
		 *	time and the time we're called here the client
		 *	disabled that event.
		 */
		client = sp->client_list;

		while (client) {
			/*
			 * Read the PRR (if it exists) and check for any events.
			 * The PRR will only be read if the socket is in IO
			 * mode, if there is a card in the socket, and if there
			 * is a PRR.
			 * We don't have to clear revent before we call the
			 * cs_read_event_status function since it will
			 * clear it before adding any current events.
			 */
		    if (client->flags & CLIENT_CARD_INSERTED) {
			(void) cs_read_event_status(sp, client,
							&revent, NULL, 0);

			client->events = ((client->events | revent) &
						(client->event_mask |
							client->global_mask));
		    } /* CLIENT_CARD_INSERTED */
		    client = client->next;
		} /* while (client) */

		mutex_exit(&sp->lock);
		mutex_exit(&sp->cis_lock);
	    } /* if (CS_EVENT_STATUS_CHANGE) */

	/*
	 * We want to maintain the required event dispatching order as
	 *	specified in the PCMCIA spec, so we cycle through all
	 *	clients on this socket to make sure that they are
	 *	notified in the correct order.
	 */
	    ct = &client_types[0];
	    while (ct) {
		/*
		 * Point to the head of the client list for this socket, and go
		 *	through each client to set up the client events as well
		 *	as call the client's event handler directly if we have
		 *	a high priority event that we need to tell the client
		 *	about.
		 */
		client = sp->client_list;

		if (ct->order & CLIENT_EVENTS_LIFO) {
		    client_t *clp = NULL;

		    while (client) {
			clp = client;
			client = client->next;
		    }
		    client = clp;
		}

		while (client) {
		    if (client->flags & ct->type) {
			    uint32_t bit = 0;
			    event_t event;

			while (client->events) {

			    switch (event = CS_BIT_GET(client->events, bit)) {
				/*
				 * Clients always receive registration complete
				 *	events, even if there is no card of
				 *	their type currently in the socket.
				 */
				case CS_EVENT_REGISTRATION_COMPLETE:
				    CLIENT_EVENT_CALLBACK(client, event,
							CS_EVENT_PRI_LOW);
				    break;
				/*
				 * The client only gets a card insertion event
				 *	if there is currently a card in the
				 *	socket that the client can control.
				 *	The nexus determines this. We also
				 *	prevent the client from receiving
				 *	multiple CS_EVENT_CARD_INSERTION
				 *	events without receiving intervening
				 *	CS_EVENT_CARD_REMOVAL events.
				 */
				case CS_EVENT_CARD_INSERTION:
				    if (cs_card_for_client(client)) {
					int send_insertion;

					mutex_enter(&sp->lock);
					send_insertion = client->flags;
					client->flags |=
						(CLIENT_CARD_INSERTED |
						CLIENT_SENT_INSERTION);
					mutex_exit(&sp->lock);
					if (!(send_insertion &
						    CLIENT_SENT_INSERTION)) {
					    CLIENT_EVENT_CALLBACK(client,
						event, CS_EVENT_PRI_LOW);
					} /* if (!CLIENT_SENT_INSERTION) */
				    }
				    break;
				/*
				 * The CS_EVENT_CARD_REMOVAL_LOWP is a low
				 *	priority CS_EVENT_CARD_REMOVAL event.
				 */
				case CS_EVENT_CARD_REMOVAL_LOWP:
				    mutex_enter(&sp->lock);
				    client->flags &= ~CLIENT_SENT_INSERTION;
				    mutex_exit(&sp->lock);
				    CLIENT_EVENT_CALLBACK(client,
							CS_EVENT_CARD_REMOVAL,
							CS_EVENT_PRI_LOW);
				    break;
				/*
				 * The hardware card removal events are handed
				 *	to the client in cs_event at high
				 *	priority interrupt time; this card
				 *	removal event is a software-generated
				 *	event.
				 */
				case CS_EVENT_CARD_REMOVAL:
				    if (client->flags & CLIENT_CARD_INSERTED) {
					mutex_enter(&sp->lock);
					client->flags &=
						~(CLIENT_CARD_INSERTED |
						CLIENT_SENT_INSERTION);
					mutex_exit(&sp->lock);
					CLIENT_EVENT_CALLBACK(client, event,
							CS_EVENT_PRI_LOW);
				    }
				    break;
				/*
				 * Write protect events require the info field
				 *	of the client's event callback args to
				 *	be zero if the card is not write
				 *	protected and one if it is.
				 */
				case CS_EVENT_WRITE_PROTECT:
				    if (client->flags & CLIENT_CARD_INSERTED) {
					get_ss_status_t gs;

					mutex_enter(&sp->cis_lock);
					mutex_enter(&sp->lock);
					(void) cs_read_event_status(sp, client,
									NULL,
									&gs, 0);
					if (gs.CardState & SBM_WP) {
					    client->event_callback_args.info =
						(void *)
						CS_EVENT_WRITE_PROTECT_WPON;
					} else {
					    client->event_callback_args.info =
						(void *)
						CS_EVENT_WRITE_PROTECT_WPOFF;
					}
					mutex_exit(&sp->lock);
					mutex_exit(&sp->cis_lock);
					CLIENT_EVENT_CALLBACK(client, event,
							CS_EVENT_PRI_LOW);
				    } /* CLIENT_CARD_INSERTED */
				    break;
				case CS_EVENT_CLIENT_INFO:
				    CLIENT_EVENT_CALLBACK(client, event,
							CS_EVENT_PRI_LOW);
				    break;
				case 0:
				    break;
				default:
				    if (client->flags & CLIENT_CARD_INSERTED) {
					CLIENT_EVENT_CALLBACK(client, event,
							CS_EVENT_PRI_LOW);
				    }
				    break;
			    } /* switch */
			    mutex_enter(&sp->lock);
			    CS_BIT_CLEAR(client->events, bit);
			    mutex_exit(&sp->lock);
			    bit++;
			} /* while (client->events) */
		    } /* if (ct->type) */
		    if (ct->order & CLIENT_EVENTS_LIFO) {
			client = client->prev;
		    } else {
			client = client->next;
		    }
		} /* while (client) */

		ct = ct->next;
	    } /* while (ct) */

	/*
	 * Handle CS_EVENT_CARD_REMOVAL events
	 */
	    if (sp->events & CS_EVENT_CARD_REMOVAL) {
		mutex_enter(&sp->lock);
		sp->events &= ~CS_EVENT_CARD_REMOVAL;
		mutex_exit(&sp->lock);
		(void) cs_card_removal(sp);
	    } /* if (CS_EVENT_CARD_REMOVAL) */

		/*
		 * If someone is waiting for us to complete, signal them now.
		 */
	    if (sp->thread_state & SOCKET_WAIT_SYNC) {
		mutex_enter(&sp->lock);
		sp->thread_state &= ~SOCKET_WAIT_SYNC;
		mutex_exit(&sp->lock);
		cv_broadcast(&sp->caller_cv);
	    } /* SOCKET_WAIT_SYNC */

	} /* for (;;) */
}

/*
 * cs_card_for_client - checks to see if a card that the client can control
 *			is currently inserted in the socket.  Socket Services
 *			has to tell us if this is the case.
 */
static int
cs_card_for_client(client_t *client)
{

	/*
	 * If the client has set the CS_EVENT_ALL_CLIENTS it means that they
	 *	want to get all events for all clients, irrespective of
	 *	whether or not there is a card in the socket.  Such clients
	 *	have to be very careful if they touch the card hardware in
	 *	any way to prevent causing problems for other clients on the
	 *	same socket.  This flag will typically only be set by the
	 *	"super-client" or CSI types of clients that wish to get
	 *	information on other clients or cards in the system.
	 * Note that the CS_EVENT_ALL_CLIENTS must be set in either the
	 *	client's global event mask or client event mask.
	 * The client must also have registered as a "super-client" or as a
	 *	CSI client for this socket.
	 */
	if ((client->flags & (CLIENT_SUPER_CLIENT | CLIENT_CSI_CLIENT)) &&
			((client->global_mask | client->event_mask) &
							CS_EVENT_ALL_CLIENTS))
	    return (1);

	/*
	 * Look for the PCM_DEV_ACTIVE property on this client's dip; if
	 *	it's found, it means that this client can control the card
	 *	that is currently in the socket.  This is a boolean
	 *	property managed by Socket Services.
	 */
	if (ddi_getprop(DDI_DEV_T_ANY, client->dip,    (DDI_PROP_CANSLEEP |
							DDI_PROP_NOTPROM),
							PCM_DEV_ACTIVE, NULL)) {
#ifdef	CS_DEBUG
	    if (cs_debug > 1) {
		cmn_err(CE_CONT, "cs_card_for_client: client handle 0x%x "
					"driver [%s] says %s found\n",
						(int)client->client_handle,
						client->driver_name,
						PCM_DEV_ACTIVE);
	    }
#endif
	    return (1);
	}

	return (0);
}

/*
 * cs_ss_thread - This is the Socket Services work thread. We fire off
 *			any calls to Socket Services here that we want
 *			to run on a thread that is seperate from the
 *			per-socket event thread.
 */
static void
cs_ss_thread(uint32_t sn)
{
	cs_socket_t *sp;

	if ((sp = cs_get_sp(sn)) == NULL)
	    return;

	/*
	 * Tell CPR that we've started a new thread.
	 */
	CALLB_CPR_INIT(&sp->cprinfo_ss, &sp->ss_thread_lock,
					callb_generic_cpr, "cs_ss_thread");

	mutex_enter(&sp->ss_thread_lock);

	for (;;) {

	    CALLB_CPR_SAFE_BEGIN(&sp->cprinfo_ss);
	    cv_wait(&sp->ss_thread_cv, &sp->ss_thread_lock);
	    CALLB_CPR_SAFE_END(&sp->cprinfo_ss, &sp->ss_thread_lock);

		/*
		 * Check to see if there are any special thread operations
		 * that we are being asked to perform.
		 */
	    if (sp->ss_thread_state & SOCKET_THREAD_EXIT) {
#ifdef	CS_DEBUG
		if (cs_debug > 1) {
		    cmn_err(CE_CONT, "cs_ss_thread: socket %d "
					"SOCKET_THREAD_EXIT\n",
						sp->socket_num);
		}
#endif
		CALLB_CPR_EXIT(&sp->cprinfo_ss);
		cv_broadcast(&sp->ss_caller_cv);	/* wake up cs_deinit */
		mutex_exit(&sp->ss_thread_lock);
		return;
	    } /* if (SOCKET_THREAD_EXIT) */

#ifdef	CS_DEBUG
	    if (cs_debug > 1) {
		cmn_err(CE_CONT, "cs_ss_thread: socket %d "
					"ss_thread_state = 0x%x\n",
						(int)sp->socket_num,
						(int)sp->ss_thread_state);
	    }
#endif

		/*
		 * Call SocketServices(CSCISInit) to have SS parse the
		 *	CIS and load/attach any client drivers necessary.
		 */
	    if (sp->ss_thread_state & SOCKET_THREAD_CSCISInit) {

		sp->ss_thread_state &= ~SOCKET_THREAD_CSCISInit;

		if (!(sp->flags & SOCKET_CARD_INSERTED)) {
		    cmn_err(CE_CONT, "cs_ss_thread %d "
					"card NOT inserted\n",
					sp->socket_num);
		}

#ifdef	CS_DEBUG
		if (cs_debug > 1) {
		    cmn_err(CE_CONT, "cs_ss_thread: socket %d calling "
						"CSCISInit\n", sp->socket_num);
		}
#endif

		/*
		 * Tell SS that we have a complete CIS and that it can now
		 *	be parsed.
		 * Note that in some cases the client driver may block in
		 *	their attach routine, causing this call to block until
		 *	the client completes their attach.
		 */
		SocketServices(CSCISInit, sp->socket_num);

		/*
		 * Set the CS_EVENT_SS_UPDATED event for this socket so that the
		 *	event thread can continue any card insertion processing
		 *	that it has to do.
		 */
		mutex_enter(&sp->lock);
		sp->events |= CS_EVENT_SS_UPDATED;
		mutex_exit(&sp->lock);

		/*
		 * Wake up this socket's event thread so that clients can
		 *	continue any card insertion or attach processing
		 *	that they need to do.
		 */
		cv_broadcast(&sp->thread_cv);
	    } /* if ST_CSCISInit */

	} /* for (;;) */
}

/*
 * cs_request_socket_mask - set the client's event mask as well as causes
 *				any events pending from RegisterClient to
 *				be scheduled to be sent to the client
 */
static int
cs_request_socket_mask(client_handle_t client_handle,
					request_socket_mask_t *se)
{
	cs_socket_t *sp;
	client_t *client;
	int error;
	int client_lock_acquired;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't do anything except for return success.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_SUCCESS);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	mutex_enter(&sp->lock);

	/*
	 * If this client has already done a RequestSocketMask without
	 *	a corresponding ReleaseSocketMask, then return an error.
	 */
	if (client->flags & REQ_SOCKET_MASK_DONE) {
	    mutex_exit(&sp->lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_IN_USE);
	}

	/*
	 * Set up the event mask information; we copy this directly from
	 *	the client; since we are the only source of events, any
	 *	bogus bits that the client puts in here won't matter
	 *	because we'll never look at them.
	 */
	client->event_mask = se->EventMask;

	/*
	 * If RegisterClient left us some events to process, set these
	 *	events up here.
	 */
	if (client->pending_events) {
	    client->events |= client->pending_events;
	    client->pending_events = 0;
#ifdef	CS_DEBUG
	    if (cs_debug > 1) {
		cmn_err(CE_CONT, "cs_request_socket_mask: client_handle = 0x%x "
				"driver_name = [%s] events = 0x%x\n",
					(int)client->client_handle,
					client->driver_name,
					(int)client->events);
	    }
#endif
	}

	client->flags |= REQ_SOCKET_MASK_DONE;

	/*
	 * Merge all the clients' event masks and set the socket
	 *	to generate the appropriate events.
	 */
	(void) cs_set_socket_event_mask(sp, cs_merge_event_masks(sp, client));

	mutex_exit(&sp->lock);

	/*
	 * Wakeup the event thread if there are any client events to process.
	 */
	if (client->events) {
	    cv_broadcast(&sp->thread_cv);
#ifdef	CS_DEBUG
	    if (cs_debug > 1) {
		cmn_err(CE_CONT, "cs_request_socket_mask: did cv_broadcast for "
				"client_handle = 0x%x "
				"driver_name = [%s] events = 0x%x\n",
					(int)client->client_handle,
					client->driver_name,
					(int)client->events);
	    }
#endif

	}
	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	return (CS_SUCCESS);
}

/*
 * cs_release_socket_mask - clear the client's event mask
 *
 * Once this function returns, the client is guaranteed
 *	not to get any more event callbacks.
 */
/*ARGSUSED*/
static int
cs_release_socket_mask(client_handle_t client_handle,
					release_socket_mask_t *rsm)
{
	cs_socket_t *sp;
	client_t *client;
	int error;
	int client_lock_acquired;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't do anything except for return success.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_SUCCESS);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	mutex_enter(&sp->lock);

	/*
	 * If this client has already done a RequestSocketMask without
	 *	a corresponding ReleaseSocketMask, then return an error.
	 */
	if (!(client->flags & REQ_SOCKET_MASK_DONE)) {
	    mutex_exit(&sp->lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_SOCKET);
	}

	/*
	 * Clear both the client event mask and the global event mask.
	 *	We clear both since the semantics of this function are
	 *	that once it returns, the client will not be called at
	 *	it's event handler for any events until RequestSocketMask
	 *	is called again.
	 */
	client->event_mask = 0;
	client->global_mask = 0;
	client->flags &= ~REQ_SOCKET_MASK_DONE;

	/*
	 * Merge all the clients' event masks and set the socket
	 *	to generate the appropriate events.
	 */
	(void) cs_set_socket_event_mask(sp, cs_merge_event_masks(sp, client));

	mutex_exit(&sp->lock);
	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	return (CS_SUCCESS);
}

/*
 * cs_get_event_mask - return the event mask for this client
 */
static int
cs_get_event_mask(client_handle_t client_handle, sockevent_t *se)
{
	cs_socket_t *sp;
	client_t *client;
	int error;
	int client_lock_acquired;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't do anything except for return success.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_SUCCESS);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	mutex_enter(&sp->lock);

#ifdef	XXX
	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 * XXX - how can a client get their event masks if their card
	 *	goes away?
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED)) {
	    mutex_exit(&sp->lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_NO_CARD);
	}
#endif

	/*
	 * We are only allowed to get the client event mask if a
	 *	RequestSocketMask has been called previously.  We
	 *	are allowed to get the global event mask at any
	 *	time.
	 * The global event mask is initially set by the client
	 *	in the call to RegisterClient.  The client event
	 *	mask is set by the client in calls to SetEventMask
	 *	and RequestSocketMask and gotten in calls to
	 *	GetEventMask.
	 */
	if (se->Attributes & CONF_EVENT_MASK_CLIENT) {
	    if (!(client->flags & REQ_SOCKET_MASK_DONE)) {
		mutex_exit(&sp->lock);
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		return (CS_BAD_SOCKET);
	    }
	    se->EventMask = client->event_mask;
	} else {
	    se->EventMask = client->global_mask;
	}

	mutex_exit(&sp->lock);
	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	return (CS_SUCCESS);
}

/*
 * cs_set_event_mask - set the event mask for this client
 */
static int
cs_set_event_mask(client_handle_t client_handle, sockevent_t *se)
{
	cs_socket_t *sp;
	client_t *client;
	int error;
	int client_lock_acquired;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't do anything except for return success.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_SUCCESS);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	mutex_enter(&sp->lock);

#ifdef	XXX
	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED)) {
	    mutex_exit(&sp->lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_NO_CARD);
	}
#endif

	/*
	 * We are only allowed to set the client event mask if a
	 *	RequestSocketMask has been called previously.  We
	 *	are allowed to set the global event mask at any
	 *	time.
	 * The global event mask is initially set by the client
	 *	in the call to RegisterClient.  The client event
	 *	mask is set by the client in calls to SetEventMask
	 *	and RequestSocketMask and gotten in calls to
	 *	GetEventMask.
	 */
	if (se->Attributes & CONF_EVENT_MASK_CLIENT) {
	    if (!(client->flags & REQ_SOCKET_MASK_DONE)) {
		mutex_exit(&sp->lock);
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		return (CS_BAD_SOCKET);
	    }
	    client->event_mask = se->EventMask;
	} else {
	    client->global_mask = se->EventMask;
	}

	/*
	 * Merge all the clients' event masks and set the socket
	 *	to generate the appropriate events.
	 */
	(void) cs_set_socket_event_mask(sp, cs_merge_event_masks(sp, client));

	mutex_exit(&sp->lock);
	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	return (CS_SUCCESS);
}

/*
 * cs_read_event_status - handles PRR events and returns card status
 *
 *	calling: *sp - socket struct point
 *		 *client - client to check events on
 *		 *revent - pointer to event mask to update; if NULL, will
 *				not be updated, if non-NULL, will be updated
 *				with CS-format events; it is NOT necessary
 *				to clear this value before calling this
 *				function
 *		 *gs - pointer to a get_ss_status_t used for the SS GetStatus
 *				call; it is not necessary to initialize any
 *				members in this structure; set to NULL if
 *				not used
 *		flags - if CS_RES_IGNORE_NO_CARD is set, the check for a
 *				card present will not be done
 *
 *	returns: CS_SUCCESS
 *		 CS_NO_CARD - if no card is in the socket and the flags arg
 *				is not set to CS_RES_IGNORE_NO_CARD
 *		 CS_BAD_SOCKET - if the SS_GetStatus function returned an
 *					error
 *
 *	Note that if the client that configured this socket has told us that
 *		the READY pin in the PRR isn't valid and the socket is in IO
 *		mode, we always return that the card is READY.
 *
 *	Note that if gs is not NULL, the current card state will be returned
 *		in the gs->CardState member; this will always reflect the
 *		current card state and the state will come from both the
 *		SS_GetStatus call and the PRR, whichever is appropriate for
 *		the mode that the socket is currently in.
 */
static int
cs_read_event_status(cs_socket_t *sp, client_t *client, event_t *revent,
						get_ss_status_t *gs, int flags)
{
	cfg_regs_t prrd = 0;

	/*
	 * SOCKET_IS_IO will only be set if a RequestConfiguration
	 *	has been done by at least one client on this socket.
	 * If there isn't a card in the socket or the caller wants to ignore
	 *	whether the card is in the socket or not, get the current
	 *	card status.
	 */
	if ((sp->flags & SOCKET_CARD_INSERTED) ||
					(flags & CS_RES_IGNORE_NO_CARD)) {
	    if (sp->flags & SOCKET_IS_IO) {
		if (client->present & CONFIG_PINREPL_REG_PRESENT) {
		    acc_handle_t cis_handle;
		    uint32_t newoffset = client->config_regs_offset;

			/*
			 * Get a handle to the CIS window
			 */
		    if (cs_init_cis_window(sp, &newoffset, &cis_handle,
					CISTPLF_AM_SPACE) != CS_SUCCESS) {
			cmn_err(CE_CONT, "cs_read_event_status: socket %d "
					    "can't init CIS window\n",
							sp->socket_num);
			return (CS_GENERAL_FAILURE);
		    } /* cs_init_cis_window */

		    prrd = csx_Get8(cis_handle, client->config_regs.prr_p);
		    prrd &= client->pin;

#ifdef	CS_DEBUG
		    if (cs_debug > 1) {
			cmn_err(CE_CONT, "cs_read_event_status: "
						"prrd 0x%x client->pin 0x%x\n",
								(int)prrd,
								client->pin);
			cmn_err(CE_CONT, "PRR(1) = [%s%s%s%s%s%s%s%s]\n",
						((prrd & PRR_WP_STATUS)?
							"PRR_WP_STATUS ":""),
						((prrd & PRR_READY_STATUS)?
							"PRR_READY_STATUS ":""),
						((prrd & PRR_BVD2_STATUS)?
							"PRR_BVD2_STATUS ":""),
						((prrd & PRR_BVD1_STATUS)?
							"PRR_BVD1_STATUS ":""),
						((prrd & PRR_WP_EVENT)?
							"PRR_WP_EVENT ":""),
						((prrd & PRR_READY_EVENT)?
							"PRR_READY_EVENT ":""),
						((prrd & PRR_BVD2_EVENT)?
							"PRR_BVD2_EVENT ":""),
						((prrd & PRR_BVD1_EVENT)?
							"PRR_BVD1_EVENT ":""));
		    }
#endif

			/*
			 * The caller wants the event changes sent back and
			 * the PRR event change bits cleared.
			 */
		    if (revent) {
			get_socket_t get_socket;
			set_socket_t set_socket;

			/*
			 * Bug ID: 1193636 - Card Services sends bogus
			 *	events on CS_EVENT_STATUS_CHANGE events
			 * Clear this before we OR-in any values.
			 */
			*revent = 0;

			PRR_EVENT(prrd, PRR_WP_EVENT, PRR_WP_STATUS,
					CS_EVENT_WRITE_PROTECT, *revent);

			PRR_EVENT(prrd, PRR_READY_EVENT, PRR_READY_STATUS,
					CS_EVENT_CARD_READY, *revent);

			PRR_EVENT(prrd, PRR_BVD2_EVENT, PRR_BVD2_STATUS,
					CS_EVENT_BATTERY_LOW, *revent);

			PRR_EVENT(prrd, PRR_BVD1_EVENT, PRR_BVD1_STATUS,
					CS_EVENT_BATTERY_DEAD, *revent);


#ifdef	CS_DEBUG
			if (cs_debug > 1) {

			    cmn_err(CE_CONT, "PRR() = [%s%s%s%s%s%s%s%s]\n",
						((prrd & PRR_WP_STATUS)?
							"PRR_WP_STATUS ":""),
						((prrd & PRR_READY_STATUS)?
							"PRR_READY_STATUS ":""),
						((prrd & PRR_BVD2_STATUS)?
							"PRR_BVD2_STATUS ":""),
						((prrd & PRR_BVD1_STATUS)?
							"PRR_BVD1_STATUS ":""),
						((prrd & PRR_WP_EVENT)?
							"PRR_WP_EVENT ":""),
						((prrd & PRR_READY_EVENT)?
							"PRR_READY_EVENT ":""),
						((prrd & PRR_BVD2_EVENT)?
							"PRR_BVD2_EVENT ":""),
						((prrd & PRR_BVD1_EVENT)?
							"PRR_BVD1_EVENT ":""));
			}
#endif

			if (prrd)
			    csx_Put8(cis_handle, client->config_regs.prr_p,
				prrd);

			/*
			 * We now have to reenable the status change interrupts
			 *	if there are any valid bits in the PRR. Since
			 *	the BVD1 signal becomes the STATUS_CHANGE
			 *	signal when the socket is in IO mode, we just
			 *	have to set the SBM_BVD1 enable bit in the
			 *	event mask.
			 */
			if (client->pin) {
			    get_socket.socket = sp->socket_num;
			    SocketServices(SS_GetSocket, &get_socket);
			    set_socket.socket = sp->socket_num;
			    set_socket.SCIntMask =
					get_socket.SCIntMask | SBM_BVD1;
			    set_socket.VccLevel = get_socket.VccLevel;
			    set_socket.Vpp1Level = get_socket.Vpp1Level;
			    set_socket.Vpp2Level = get_socket.Vpp2Level;
			    set_socket.IREQRouting = get_socket.IRQRouting;
			    set_socket.IFType = get_socket.IFType;
			    set_socket.CtlInd = get_socket.CtlInd;
			    set_socket.State = get_socket.state;
			    SocketServices(SS_SetSocket, &set_socket);
			} /* if (client->pin) */
		    } /* if (revent) */

		} /* if (CONFIG_PINREPL_REG_PRESENT) */
	    } /* if (SOCKET_IS_IO) */

	/*
	 * The caller wants the current card state; we just read
	 *	it and return a copy of it but do not clear any of
	 *	the event changed bits (if we're reading the PRR).
	 */
	    if (gs) {
		gs->socket = sp->socket_num;
		gs->CardState = 0;
		if (SocketServices(SS_GetStatus, gs) != SUCCESS)
		    return (CS_BAD_SOCKET);
		if (sp->flags & SOCKET_IS_IO) {
		/*
		 * If the socket is in IO mode, then clear the
		 *	gs->CardState bits that are now in the PRR
		 */
		    gs->CardState &= ~(SBM_WP | SBM_BVD1 |
						SBM_BVD2 | SBM_RDYBSY);

		/*
		 * Convert PRR status to SS_GetStatus status
		 */
		    if (prrd & PRR_WP_STATUS)
			gs->CardState |= SBM_WP;
		    if (prrd & PRR_BVD2_STATUS)
			gs->CardState |= SBM_BVD2;
		    if (prrd & PRR_BVD1_STATUS)
			gs->CardState |= SBM_BVD1;

		/*
		 * If the client has indicated that there is no
		 *	PRR or that the READY bit in the PRR isn't
		 *	valid, then we simulate the READY bit by
		 *	always returning READY.
		 */
		    if (!(client->present & CONFIG_PINREPL_REG_PRESENT) ||
			((client->present & CONFIG_PINREPL_REG_PRESENT) &&
			!((client->pin &
			    (PRR_READY_STATUS | PRR_READY_EVENT)) ==
				(PRR_READY_STATUS | PRR_READY_EVENT))) ||
				(prrd & PRR_READY_STATUS))
			gs->CardState |= SBM_RDYBSY;

#ifdef	CS_DEBUG
			if (cs_debug > 1) {
			    cmn_err(CE_CONT, "cs_read_event_status: prrd 0x%x "
				"client->pin 0x%x "
				"gs->CardState 0x%x\n",
				prrd, client->pin, gs->CardState);
			}
#endif

		} /* if (SOCKET_IS_IO) */
	    } /* if (gs) */
	    return (CS_SUCCESS);
	} /* if (SOCKET_CARD_INSERTED) */

	return (CS_NO_CARD);
}

/*
 * cs_get_status - gets live card status and latched card status changes
 *			supports the GetStatus CS call
 *
 *	returns: CS_SUCCESS
 *		 CS_BAD_HANDLE if the passed client handle is invalid
 *
 *	Note: This function resets the latched status values maintained
 *		by Socket Services
 */
static int
cs_get_status(client_handle_t client_handle, get_status_t *gs)
{
	cs_socket_t *sp;
	client_t *client;
	get_ss_status_t get_ss_status;
	get_socket_t get_socket;
	set_socket_t set_socket;
	int error;
	int client_lock_acquired;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't do anything except for return success.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_SUCCESS);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	/*
	 * Get the current card status as well as the latched card
	 *	state.  Set the CS_RES_IGNORE_NO_CARD so that even
	 *	if there is no card in the socket we'll still get
	 *	a valid status.
	 * Note that it is not necessary to initialize any values
	 *	in the get_ss_status structure.
	 */
	mutex_enter(&sp->cis_lock);
	if ((error = cs_read_event_status(sp, client, NULL, &get_ss_status,
					CS_RES_IGNORE_NO_CARD)) != CS_SUCCESS) {
	    mutex_exit(&sp->cis_lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	mutex_exit(&sp->cis_lock);

	gs->raw_CardState = cs_sbm2cse(get_ss_status.CardState);

	/*
	 * Assign the "live" card state to the "real" card state. If there's
	 *	no card in the socket or the card in the socket is not
	 *	for this client, then we lie and tell the caller that the
	 *	card is not inserted.
	 */
	gs->CardState = gs->raw_CardState;
	if (!(client->flags & CLIENT_CARD_INSERTED))
	    gs->CardState &= ~CS_EVENT_CARD_INSERTION;

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	get_socket.socket = sp->socket_num;
	if (SocketServices(SS_GetSocket, &get_socket) != SUCCESS)
	    return (CS_BAD_SOCKET);

	gs->SocketState = cs_sbm2cse(get_socket.state);

	set_socket.socket = sp->socket_num;
	set_socket.SCIntMask = get_socket.SCIntMask;
	set_socket.VccLevel = get_socket.VccLevel;
	set_socket.Vpp1Level = get_socket.Vpp1Level;
	set_socket.Vpp2Level = get_socket.Vpp2Level;
	set_socket.IREQRouting = get_socket.IRQRouting;
	set_socket.IFType = get_socket.IFType;
	set_socket.CtlInd = get_socket.CtlInd;
	/* XXX (is ~0 correct here?) reset latched values */
	set_socket.State = (unsigned)~0;

	if (SocketServices(SS_SetSocket, &set_socket) != SUCCESS)
	    return (CS_BAD_SOCKET);

	return (CS_SUCCESS);
}

/*
 * cs_cse2sbm - converts a CS event mask to an SS (SBM_XXX) event mask
 */
static event_t
cs_cse2sbm(event_t event_mask)
{
	event_t sbm_event = 0;

	/*
	 * XXX - we need to handle PM_CHANGE and RESET here as well
	 */
	if (event_mask & CS_EVENT_WRITE_PROTECT)
	    sbm_event |= SBM_WP;
	if (event_mask & CS_EVENT_BATTERY_DEAD)
	    sbm_event |= SBM_BVD1;
	if (event_mask & CS_EVENT_BATTERY_LOW)
	    sbm_event |= SBM_BVD2;
	if (event_mask & CS_EVENT_CARD_READY)
	    sbm_event |= SBM_RDYBSY;
	if (event_mask & CS_EVENT_CARD_LOCK)
	    sbm_event |= SBM_LOCKED;
	if (event_mask & CS_EVENT_EJECTION_REQUEST)
	    sbm_event |= SBM_EJECT;
	if (event_mask & CS_EVENT_INSERTION_REQUEST)
	    sbm_event |= SBM_INSERT;
	if (event_mask & (CS_EVENT_CARD_INSERTION | CS_EVENT_CARD_REMOVAL))
	    sbm_event |= SBM_CD;

	return (sbm_event);
}

/*
 * cs_sbm2cse - converts SBM_xxx state to CS event bits
 *
 * This function should never set any of the following bits:
 *
 *		CS_EVENT_MTD_REQUEST
 *		CS_EVENT_CLIENT_INFO
 *		CS_EVENT_TIMER_EXPIRED
 *		CS_EVENT_CARD_REMOVAL
 *		CS_EVENT_CARD_REMOVAL_LOWP
 *		CS_EVENT_ALL_CLIENTS
 *		CS_EVENT_READY_TIMEOUT
 *
 *	These bits are defined in the CS_STATUS_XXX series and are
 *	used by GetStatus.
 */
static uint32_t
cs_sbm2cse(uint32_t state)
{
	uint32_t rstate = 0;

	/*
	 * XXX - we need to handle PM_CHANGE and RESET here as well
	 */
	if (state & SBM_WP)
	    rstate |= CS_EVENT_WRITE_PROTECT;
	if (state & SBM_BVD1)
	    rstate |= CS_EVENT_BATTERY_DEAD;
	if (state & SBM_BVD2)
	    rstate |= CS_EVENT_BATTERY_LOW;
	if (state & SBM_RDYBSY)
	    rstate |= CS_EVENT_CARD_READY;
	if (state & SBM_LOCKED)
	    rstate |= CS_EVENT_CARD_LOCK;
	if (state & SBM_EJECT)
	    rstate |= CS_EVENT_EJECTION_REQUEST;
	if (state & SBM_INSERT)
	    rstate |= CS_EVENT_INSERTION_REQUEST;
	if (state & SBM_CD)
	    rstate |= CS_EVENT_CARD_INSERTION;

	return (rstate);
}

/*
 * cs_merge_event_masks - merge the CS global socket event mask with the
 *				passed client's event masks
 */
static unsigned
cs_merge_event_masks(cs_socket_t *sp, client_t *client)
{
	unsigned SCIntMask;
	uint32_t event_mask;

	/*
	 * We always want to see card detect and status change events.
	 */
	SCIntMask = SBM_CD;

	event_mask = client->event_mask | client->global_mask |
							sp->event_mask;

	if (!(sp->flags & SOCKET_IS_IO)) {
	    SCIntMask |= cs_cse2sbm(event_mask);
	} else {
		/*
		 * If the socket is in IO mode and there is a PRR present,
		 *	then we may need to enable PCE_CARD_STATUS_CHANGE
		 *	events.
		 */
	    if (client->present & CONFIG_PINREPL_REG_PRESENT) {

		SCIntMask |= (cs_cse2sbm(event_mask) &
				~(SBM_WP | SBM_BVD1 | SBM_BVD2 | SBM_RDYBSY));

		if ((client->pin & (PRR_WP_STATUS | PRR_WP_EVENT)) ==
					(PRR_WP_STATUS | PRR_WP_EVENT))
		    if (event_mask & CS_EVENT_WRITE_PROTECT)
			SCIntMask |= SBM_BVD1;

		if ((client->pin & (PRR_READY_STATUS | PRR_READY_EVENT)) ==
					(PRR_READY_STATUS | PRR_READY_EVENT))
		    if (event_mask & CS_EVENT_CARD_READY)
			    SCIntMask |= SBM_BVD1;

		if ((client->pin & (PRR_BVD2_STATUS | PRR_BVD2_EVENT)) ==
					(PRR_BVD2_STATUS | PRR_BVD2_EVENT))
		    if (event_mask & CS_EVENT_BATTERY_LOW)
			    SCIntMask |= SBM_BVD1;

		if ((client->pin & (PRR_BVD1_STATUS | PRR_BVD1_EVENT)) ==
					(PRR_BVD1_STATUS | PRR_BVD1_EVENT))
		    if (event_mask & CS_EVENT_BATTERY_DEAD)
			    SCIntMask |= SBM_BVD1;

	    } /* if (CONFIG_PINREPL_REG_PRESENT) */
	} /* if (!SOCKET_IS_IO) */

	return (SCIntMask);
}

/*
 * cs_set_socket_event_mask - set the event mask for the socket
 */
static int
cs_set_socket_event_mask(cs_socket_t *sp, unsigned event_mask)
{
	get_socket_t get_socket;
	set_socket_t set_socket;

	get_socket.socket = sp->socket_num;
	if (SocketServices(SS_GetSocket, &get_socket) != SUCCESS)
	    return (CS_BAD_SOCKET);

	set_socket.socket = sp->socket_num;
	set_socket.SCIntMask = event_mask;
	set_socket.VccLevel = get_socket.VccLevel;
	set_socket.Vpp1Level = get_socket.Vpp1Level;
	set_socket.Vpp2Level = get_socket.Vpp2Level;
	set_socket.IREQRouting = get_socket.IRQRouting;
	set_socket.IFType = get_socket.IFType;
	set_socket.CtlInd = get_socket.CtlInd;
	/* XXX (is ~0 correct here?) reset latched values */
	set_socket.State = (unsigned)~0;

	if (SocketServices(SS_SetSocket, &set_socket) != SUCCESS)
	    return (CS_BAD_SOCKET);

	return (CS_SUCCESS);
}

/*
 * ==== MTD handling section ====
 */
static int
cs_deregister_mtd(client_handle_t client_handle)
{

	cmn_err(CE_CONT, "cs_deregister_mtd: client_handle 0x%x\n",
							(int)client_handle);

	return (CS_SUCCESS);
}

/*
 * ==== memory window handling section ====
 */

/*
 * cs_request_window  - searches through window list for the socket to find a
 *			memory window that matches the requested criteria;
 *			this is RequestWindow
 *
 * calling:  cs_request_window(client_handle_t, *window_handle_t, win_req_t *)
 *
 *	On sucessful return, the window_handle_t * pointed to will
 *		contain a valid window handle for this window.
 *
 *	returns: CS_SUCCESS - if window found
 *		 CS_OUT_OF_RESOURCE - if no windows match requirements
 *		 CS_BAD_HANDLE - client handle is invalid
 *		 CS_BAD_SIZE - if requested size can not be met
 *		 CS_BAD_WINDOW - if an internal error occured
 *		 CS_UNSUPPORTED_FUNCTION - if SS is trying to call us
 *		 CS_NO_CARD - if no card is in socket
 *		 CS_BAD_ATTRIBUTE - if any of the unsupported Attrbute
 *					flags are set
 */
static int
cs_request_window(client_handle_t client_handle,
				window_handle_t *wh,
				win_req_t *rw)
{
	cs_socket_t *sp;
	cs_window_t *cw;
	client_t *client;
	modify_win_t mw;
	inquire_window_t iw;
	uint32_t aw;
	int error;
	int client_lock_acquired;
	uint32_t socket_num;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't support SS using this call.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_UNSUPPORTED_FUNCTION);

	/*
	 * Make sure that none of the unsupported flags are set.
	 */
	if (rw->Attributes &   (/* Compatability */
				WIN_PAGED |
				WIN_SHARED |
				WIN_FIRST_SHARED |
				WIN_BINDING_SPECIFIC |
				/* CS internal */
				WIN_DATA_WIDTH_VALID |
				/* IO window flags */
				WIN_MEMORY_TYPE_IO |
				/* CardBus flags */
				WIN_DATA_WIDTH_32 |
				WIN_PREFETCH_CACHE_MASK |
				WIN_BAR_MASK))
	    return (CS_BAD_ATTRIBUTE);

	mutex_enter(&cs_globals.window_lock);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (error);
	}

	mutex_enter(&sp->lock);

	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED)) {
	    mutex_exit(&sp->lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_NO_CARD);
	}

	mutex_exit(&sp->lock);

	socket_num = CS_MAKE_SOCKET_NUMBER(GET_CLIENT_SOCKET(client_handle),
	    GET_CLIENT_FUNCTION(client_handle));


	/*
	 * See if we can find a window that matches the caller's criteria.
	 *	If we can't, then thre's not much more that we can do except
	 *	for return an error.
	 */
	if ((error = cs_find_mem_window(sp->socket_num, rw, &aw)) !=
								CS_SUCCESS) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (error);
	}

	/*
	 * We got a window, now synthesize a new window handle for this
	 *	client and get a pointer to the global window structs
	 *	and assign this window to this client.
	 * We don't have to check for errors from cs_create_window_handle
	 *	since that function always returns a valid window handle
	 *	if it is given a valid window number.
	 */
	*wh = cs_create_window_handle(aw);
	if ((cw = cs_get_wp(aw)) == NULL) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_BAD_WINDOW);
	}

	cw->window_handle = *wh;
	cw->client_handle = client_handle;
	cw->socket_num = sp->socket_num;
	cw->state |= (CW_ALLOCATED | CW_MEM);

	mw.Attributes = (
				rw->Attributes |
				WIN_DATA_WIDTH_VALID |
				WIN_ACCESS_SPEED_VALID);
	mw.AccessSpeed = rw->win_params.AccessSpeed;

	if ((error = cs_modify_mem_window(*wh, &mw, rw, socket_num)) !=
	    CS_SUCCESS) {
	    cw->state = 0;
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (error);
	}

	/*
	 * Get any required card offset and pass it back to the client.
	 *	This is not defined in the current PCMCIA spec.  It is
	 *	an aid to clients that want to use it to generate an
	 *	optimum card offset.
	 */
	iw.window = GET_WINDOW_NUMBER(*wh);
	SocketServices(SS_InquireWindow, &iw);

	if (iw.mem_win_char.MemWndCaps & WC_CALIGN)
	    rw->ReqOffset = rw->Size;
	else
	    rw->ReqOffset = iw.mem_win_char.ReqOffset;

	/*
	 * Increment the client's memory window count; this is how we know
	 *	when a client has any allocated memory windows.
	 */
	client->memwin_count++;

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	mutex_exit(&cs_globals.window_lock);

	return (CS_SUCCESS);
}

/*
 * cs_release_window - deallocates the window associated with the passed
 *			window handle; this is ReleaseWindow
 *
 *	returns: CS_SUCCESS if window handle is valid and window was
 *			sucessfully deallocated
 *		 CS_BAD_HANDLE if window handle is invalid or if window
 *			handle is valid but window is not allocated
 */
static int
cs_release_window(window_handle_t wh)
{
	cs_socket_t *sp;
	cs_window_t *cw;
	client_t *client;
	int error;
	int client_lock_acquired;

	mutex_enter(&cs_globals.window_lock);

	if (!(cw = cs_find_window(wh))) {
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_BAD_HANDLE);
	}

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't support SS using this call.
	 */
	if (CLIENT_HANDLE_IS_SS(cw->client_handle)) {
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_UNSUPPORTED_FUNCTION);
	}

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(cw->client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(cw->client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (error);
	}

	/*
	 * Mark this window as not in use anymore.
	 */
	cw->state &= ~CW_WIN_IN_USE;

	/*
	 * Decrement the client's memory window count; this is how we know
	 *	when a client has any allocated memory windows.
	 */
	if (!(--(client->memwin_count)))
	    client->flags &= ~CLIENT_WIN_ALLOCATED;

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	mutex_exit(&cs_globals.window_lock);

	return (CS_SUCCESS);
}

/*
 * cs_modify_window - modifies a window's characteristics; this is ModifyWindow
 */
static int
cs_modify_window(window_handle_t wh, modify_win_t *mw)
{
	cs_socket_t *sp;
	cs_window_t *cw;
	client_t *client;
	int error;
	int client_lock_acquired;

	mutex_enter(&cs_globals.window_lock);

	/*
	 * Do some sanity checking - make sure that we can find a pointer
	 *	to the window structure, and if we can, get the client that
	 *	has allocated that window.
	 */
	if (!(cw = cs_find_window(wh))) {
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_BAD_HANDLE);
	}

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(cw->client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	if (!(client = cs_find_client(cw->client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (error);
	}

	mutex_enter(&sp->lock);

	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED)) {
	    mutex_exit(&sp->lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_NO_CARD);
	}

	mutex_exit(&sp->lock);

	mw->Attributes &= (
				WIN_MEMORY_TYPE_MASK |
				WIN_ENABLE |
				WIN_ACCESS_SPEED_VALID |
				WIN_ACC_ENDIAN_MASK |
				WIN_ACC_ORDER_MASK);

	mw->Attributes &= ~WIN_DATA_WIDTH_VALID;

	if ((error = cs_modify_mem_window(wh, mw, NULL, NULL)) != CS_SUCCESS) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (error);
	}

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	mutex_exit(&cs_globals.window_lock);

	return (CS_SUCCESS);
}

/*
 * cs_modify_mem_window - modifies a window's characteristics; used internally
 *				by Card Services
 *
 *    If *wr is NULL, it means that we're being called by ModifyWindow
 *    If *wr is non-NULL, it means that we are being called by RequestWindow
 *	and so we can't use SS_GetWindow.
 */
static int
cs_modify_mem_window(window_handle_t wh, modify_win_t *mw,
						win_req_t *wr, int sn)
{
	get_window_t gw;
	set_window_t sw;
	set_page_t set_page;
	get_page_t get_page;

	/*
	 * If the win_req_t struct pointer is NULL, it means that
	 *	we're being called by ModifyWindow, so get the
	 *	current window characteristics.
	 */
	if (!wr) {
	    gw.window = GET_WINDOW_NUMBER(wh);
	    if (SocketServices(SS_GetWindow, &gw) != SUCCESS)
		return (CS_BAD_WINDOW);
	    sw.state = gw.state;
	    sw.socket = gw.socket;
	    sw.WindowSize = gw.size;
	} else {
	    sw.state = 0;
	    sw.socket = sn;
	    sw.WindowSize = wr->Size;
	}

	/*
	 * If we're being called by RequestWindow, we must always have
	 *	WIN_ACCESS_SPEED_VALID set since get_window_t is not
	 *	defined.
	 */
	if (mw->Attributes & WIN_ACCESS_SPEED_VALID) {
	    convert_speed_t convert_speed;

	    convert_speed.Attributes = CONVERT_DEVSPEED_TO_NS;
	    convert_speed.devspeed = mw->AccessSpeed;

	    if (cs_convert_speed(&convert_speed) != CS_SUCCESS)
		return (CS_BAD_SPEED);

	    sw.speed = convert_speed.nS;
	} else {
	    sw.speed = gw.speed;
	}

	if (!wr) {
	    get_page.window = GET_WINDOW_NUMBER(wh);
	    get_page.page = 0;
	    if (SocketServices(SS_GetPage, &get_page) != SUCCESS)
		return (CS_BAD_WINDOW);
	    set_page.state = get_page.state;
	    set_page.offset = get_page.offset;
	} else {
	    set_page.state = 0;
	    set_page.offset = 0;
	}

	if (mw->Attributes & WIN_ENABLE) {
	    sw.state |= WS_ENABLED;
	    set_page.state |= PS_ENABLED;
	} else {
	    sw.state &= ~WS_ENABLED;
	    set_page.state &= ~PS_ENABLED;
	}

	if (mw->Attributes & WIN_DATA_WIDTH_VALID) {
	    if (mw->Attributes & WIN_DATA_WIDTH_16)
		sw.state |= WS_16BIT;
	    else
		sw.state &= ~WS_16BIT;
	}

	sw.window = GET_WINDOW_NUMBER(wh);
	sw.base = 0;

	cs_set_acc_attributes(&sw, mw->Attributes);

	if (SocketServices(SS_SetWindow, &sw) != SUCCESS)
	    return (CS_BAD_WINDOW);

	if (mw->Attributes & WIN_MEMORY_TYPE_AM)
	    set_page.state |= PS_ATTRIBUTE;
	else
	    set_page.state &= ~PS_ATTRIBUTE;

	set_page.window = GET_WINDOW_NUMBER(wh);
	set_page.page = 0;
	if (SocketServices(SS_SetPage, &set_page) != SUCCESS)
	    return (CS_BAD_OFFSET);

	/*
	 * Return the current base address of this window
	 */
	if (wr) {
	    gw.window = GET_WINDOW_NUMBER(wh);
	    if (SocketServices(SS_GetWindow, &gw) != SUCCESS)
		return (CS_BAD_WINDOW);

	    wr->Base.handle = (acc_handle_t)gw.handle;
	}

	return (CS_SUCCESS);
}

/*
 * cs_map_mem_page - sets the card offset of the mapped window
 */
static int
cs_map_mem_page(window_handle_t wh, map_mem_page_t *mmp)
{
	cs_socket_t *sp;
	cs_window_t *cw;
	client_t *client;
	inquire_window_t iw;
	get_window_t gw;
	set_page_t set_page;
	get_page_t get_page;
	int error;
	uint32_t size;
	int client_lock_acquired;

	/*
	 * We don't support paged windows, so never allow a page number
	 *	of other than 0
	 */
	if (mmp->Page)
	    return (CS_BAD_PAGE);

	mutex_enter(&cs_globals.window_lock);

	/*
	 * Do some sanity checking - make sure that we can find a pointer
	 *	to the window structure, and if we can, get the client that
	 *	has allocated that window.
	 */
	if (!(cw = cs_find_window(wh))) {
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_BAD_HANDLE);
	}

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(cw->client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	if (!(client = cs_find_client(cw->client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (error);
	}

	mutex_enter(&sp->lock);

	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED)) {
	    mutex_exit(&sp->lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_NO_CARD);
	}

	mutex_exit(&sp->lock);

	gw.window = GET_WINDOW_NUMBER(wh);
	SocketServices(SS_GetWindow, &gw);

	iw.window = GET_WINDOW_NUMBER(wh);
	SocketServices(SS_InquireWindow, &iw);

	if (iw.mem_win_char.MemWndCaps & WC_CALIGN)
	    size = gw.size;
	else
	    size = iw.mem_win_char.ReqOffset;

	if (((mmp->CardOffset/size)*size) != mmp->CardOffset) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_BAD_OFFSET);
	}

	get_page.window = GET_WINDOW_NUMBER(wh);
	get_page.page = 0;
	SocketServices(SS_GetPage, &get_page);

	set_page.window = GET_WINDOW_NUMBER(wh);
	set_page.page = 0;
	set_page.state = get_page.state;
	set_page.offset = mmp->CardOffset;
	if (SocketServices(SS_SetPage, &set_page) != SUCCESS) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_BAD_OFFSET);
	}

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	mutex_exit(&cs_globals.window_lock);

	return (CS_SUCCESS);
}

/*
 * cs_find_window - finds the window associated with the passed window
 *			handle; if the window handle is invalid or no
 *			windows match the passed window handle, NULL
 *			is returned.  Note that the window must be
 *			allocated for this function to return a valid
 *			window pointer.
 *
 *	returns: cs_window_t * pointer to the found window
 *		 NULL if window handle invalid or window not allocated
 */
cs_window_t *
cs_find_window(window_handle_t wh)
{
	cs_window_t *cw;

	if ((GET_WINDOW_NUMBER(wh) > cs_globals.num_windows) ||
			(GET_WINDOW_MAGIC(wh) != WINDOW_HANDLE_MAGIC))
	    return ((cs_window_t *)NULL);

	if ((cw = cs_get_wp(GET_WINDOW_NUMBER(wh))) == NULL)
	    return (NULL);

	if ((cw->state & CW_ALLOCATED) && (cw->state & CW_MEM))
	    return (cw);

	return ((cs_window_t *)NULL);
}

/*
 * cs_create_window_handle - creates a unique window handle based on the
 *				passed window number.
 */
static window_handle_t
cs_create_window_handle(uint32_t aw)
{
	return (WINDOW_HANDLE_MAGIC | (aw & WINDOW_HANDLE_MASK));
}

/*
 * cs_find_mem_window - tries to find a memory window matching the caller's
 *			criteria
 *
 *	We return the first window that matches the requested criteria.
 *
 *	returns: CS_SUCCESS - if memory window found
 *		 CS_OUT_OF_RESOURCE - if no windows match requirements
 *		 CS_BAD_SIZE - if requested size can not be met
 *		 CS_BAD_WINDOW - if an internal error occured
 */
/* BEGIN CSTYLED */
static int
cs_find_mem_window(uint32_t sn, win_req_t *rw, uint32_t *assigned_window)
{
	uint32_t wn;
	int error = CS_OUT_OF_RESOURCE;
	uint32_t window_num = PCMCIA_MAX_WINDOWS;
	uint32_t min_size = UINT_MAX;
	inquire_window_t inquire_window, *iw;
	uint32_t MinSize, MaxSize, ReqGran, MemWndCaps, WndCaps;
	uint32_t tws;

	iw = &inquire_window;

	for (wn = 0; wn < cs_globals.num_windows; wn++) {
	    cs_window_t *cw;

	    /*
	     * If we can't get a pointer to this window, we should contine
	     *	with scanning the next window, since this window might have
	     *	been dropped.
	     */
	    if ((cw = cs_get_wp(wn)) != NULL) {
	      iw->window = wn;

	      if (SocketServices(SS_InquireWindow, iw) != SUCCESS)
		return (CS_BAD_WINDOW);

	      MinSize = iw->mem_win_char.MinSize;
	      MaxSize = iw->mem_win_char.MaxSize;
	      ReqGran = iw->mem_win_char.ReqGran;
	      MemWndCaps = iw->mem_win_char.MemWndCaps;
	      WndCaps = iw->WndCaps;

	      if (WINDOW_FOR_SOCKET(iw->Sockets, sn) &&
					WINDOW_AVAILABLE_FOR_MEM(cw) &&
					WndCaps & (WC_COMMON|WC_ATTRIBUTE)) {
		if ((error = cs_valid_window_speed(iw, rw->win_params.AccessSpeed)) ==
					CS_SUCCESS) {
		    error = CS_OUT_OF_RESOURCE;
		    if (cs_memwin_space_and_map_ok(iw, rw)) {
			error = CS_BAD_SIZE;
			if (!rw->Size) {
			    min_size = min(min_size, MinSize);
			    window_num = wn;
			    goto found_window;
			} else {
			    if (!(MemWndCaps & WC_SIZE)) {
				if (rw->Size == MinSize) {
				    min_size = MinSize;
				    window_num = wn;
				    goto found_window;
				}
			    } else { /* WC_SIZE */
			      if (!ReqGran) {
				error = CS_BAD_WINDOW;
			      } else {
				if ((rw->Size >= MinSize) &&
							(rw->Size <= MaxSize)) {
				    if (MemWndCaps & WC_POW2) {
				      unsigned rg = ReqGran;
					for (tws = MinSize; tws <= MaxSize;
								rg = (rg<<1)) {
					    if (rw->Size == tws) {
						min_size = tws;
						window_num = wn;
						goto found_window;
					    }
					    tws += rg;
					  } /* for (tws) */
				    } else {
					for (tws = MinSize; tws <= MaxSize;
							tws += ReqGran) {
					    if (rw->Size == tws) {
						min_size = tws;
						window_num = wn;
						goto found_window;
					    }
					  } /* for (tws) */
				    } /* if (!WC_POW2) */
				} /* if (Size >= MinSize) */
			      } /* if (!ReqGran) */
			    } /* if (WC_SIZE) */
			} /* if (rw->Size) */
		    } /* if (cs_space_and_map_ok) */
		} /* if (cs_valid_window_speed) */
	      } /* if (WINDOW_FOR_SOCKET) */
	    } /* if (cs_get_wp) */
	} /* for (wn) */

	/*
	 * If we got here and the window_num wasn't set by any window
	 *	 matches in the above code, it means that we didn't
	 *	find a window matching the caller's criteria.
	 * If the error is CS_BAD_TYPE, it means that the last reason
	 *	that we couldn't match a window was because the caller's
	 *	requested speed was out of range of the last window that
	 *	we checked.  We convert this error code to CS_OUT_OF_RESOURCE
	 *	to conform to the RequestWindow section of the PCMCIA
	 *	Card Services spec.
	 */
	if (window_num == PCMCIA_MAX_WINDOWS) {
	    if (error == CS_BAD_TYPE)
		error = CS_OUT_OF_RESOURCE;
	    return (error);
	}

found_window:
	rw->Size = min_size;
	*assigned_window = window_num;
	iw->window = window_num;
	SocketServices(SS_InquireWindow, iw);
	MemWndCaps = iw->mem_win_char.MemWndCaps;

	if (MemWndCaps & WC_CALIGN)
	    rw->Attributes |= WIN_OFFSET_SIZE;
	else
	    rw->Attributes &= ~WIN_OFFSET_SIZE;
	return (CS_SUCCESS);
}
/* END CSTYLED */

/*
 * cs_memwin_space_and_map_ok - checks to see if the passed window mapping
 *				capabilities and window speeds are in the
 *				range of the passed window.
 *
 *	returns: 0 - if the capabilities are out of range
 *		 1 - if the capabilities are in range
 */
static int
cs_memwin_space_and_map_ok(inquire_window_t *iw, win_req_t *rw)
{

#ifdef	CS_DEBUG
	if (cs_debug > 240)
	    printf("-> s&m_ok: Attributes 0x%x AccessSpeed 0x%x "
					"WndCaps 0x%x MemWndCaps 0x%x\n",
					(int)rw->Attributes,
					(int)rw->win_params.AccessSpeed,
					iw->WndCaps,
					iw->mem_win_char.MemWndCaps);
#endif

	if (rw->win_params.AccessSpeed & WIN_USE_WAIT) {
	    if (!(iw->WndCaps & WC_WAIT))
		return (0);
	}

	if (rw->Attributes & WIN_DATA_WIDTH_16) {
	    if (!(iw->mem_win_char.MemWndCaps & WC_16BIT))
		return (0);
	} else {
	    if (!(iw->mem_win_char.MemWndCaps & WC_8BIT))
		return (0);
	}

	if (rw->Attributes & WIN_MEMORY_TYPE_AM) {
	    if (!(iw->WndCaps & WC_ATTRIBUTE))
		return (0);
	}

	if (rw->Attributes & WIN_MEMORY_TYPE_CM) {
	    if (!(iw->WndCaps & WC_COMMON))
		return (0);
	}

	return (1);
}

/*
 * cs_valid_window_speed - checks to see if requested window speed
 *				is in range of passed window
 *
 *	The inquire_window_t struct gives us speeds in nS, and we
 *	get speeds in the AccessSpeed variable as a devspeed code.
 *
 *	returns: CS_BAD_SPEED - if AccessSpeed is invalid devspeed code
 *		 CS_BAD_TYPE -	if AccessSpeed is not in range of valid
 *				speed for this window
 *		 CS_SUCCESS -	if window speed is in range
 */
static int
cs_valid_window_speed(inquire_window_t *iw, uint32_t AccessSpeed)
{
	convert_speed_t convert_speed, *cs;

	cs = &convert_speed;

	cs->Attributes = CONVERT_DEVSPEED_TO_NS;
	cs->devspeed = AccessSpeed;

	if (cs_convert_speed(cs) != CS_SUCCESS)
	    return (CS_BAD_SPEED);

	if ((cs->nS < iw->mem_win_char.Fastest) ||
		(cs->nS > iw->mem_win_char.Slowest))
	    return (CS_BAD_TYPE);

	return (CS_SUCCESS);
}

/*
 * ==== IO window handling section ====
 */

/*
 * cs_request_io - provides IO resources for clients; this is RequestIO
 *
 *	calling: cs_request_io(client_handle_t, io_req_t *)
 *
 *	returns: CS_SUCCESS - if IO resources available for client
 *		 CS_OUT_OF_RESOURCE - if no windows match requirements
 *		 CS_BAD_HANDLE - client handle is invalid
 *		 CS_UNSUPPORTED_FUNCTION - if SS is trying to call us
 *		 CS_NO_CARD - if no card is in socket
 *		 CS_BAD_ATTRIBUTE - if any of the unsupported Attribute
 *					flags are set
 *		 CS_BAD_BASE - if either or both base port addresses
 *					are invalid or out of range
 *		 CS_CONFIGURATION_LOCKED - a RequestConfiguration has
 *					already been done
 *		 CS_IN_USE - IO ports already in use or function has
 *					already been called
 *		 CS_BAD_WINDOW - if failure while trying to set window
 *					characteristics
 */
static int
cs_request_io(client_handle_t client_handle, io_req_t *ior)
{
	cs_socket_t *sp;
	client_t *client;
	int error;
	int client_lock_acquired;
	uint32_t socket_num;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't support SS using this call.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_UNSUPPORTED_FUNCTION);

	/*
	 * If the client has only requested one IO range, then make sure
	 *	that the Attributes2 filed is clear.
	 */
	if (!ior->NumPorts2)
	    ior->Attributes2 = 0;

	/*
	 * Make sure that none of the unsupported or reserved flags are set.
	 */
	if ((ior->Attributes1 | ior->Attributes2) &    (IO_SHARED |
							IO_FIRST_SHARED |
							IO_FORCE_ALIAS_ACCESS |
							IO_DEALLOCATE_WINDOW |
							IO_DISABLE_WINDOW))
	    return (CS_BAD_ATTRIBUTE);

	/*
	 * Make sure that we have a port count for the first region.
	 */
	if (!ior->NumPorts1)
	    return (CS_BAD_BASE);

	/*
	 * If we're being asked for multiple IO ranges, then both base port
	 *	members must be non-zero.
	 */
	if ((ior->NumPorts2) && !(ior->BasePort1.base && ior->BasePort2.base))
	    return (CS_BAD_BASE);

	mutex_enter(&cs_globals.window_lock);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (error);
	}

	/*
	 * If RequestConfiguration has already been done, we don't allow
	 *	this call.
	 */
	if (client->flags & REQ_CONFIGURATION_DONE) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_CONFIGURATION_LOCKED);
	}

	/*
	 * If RequestIO has already been done, we don't allow this call.
	 */
	if (client->flags & REQ_IO_DONE) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_IN_USE);
	}

	mutex_enter(&sp->lock);

	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED)) {
	    mutex_exit(&sp->lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_NO_CARD);
	}

	mutex_exit(&sp->lock);

	/*
	 * If we're only being asked for one IO range, then set BasePort2 to
	 *	zero, since we use it later on.
	 */
	if (!ior->NumPorts2)
	    ior->BasePort2.base = 0;

	/*
	 * See if we can allow Card Services to select the base address
	 *	value for this card; if the client has specified a non-zero
	 *	base IO address but the card doesn't decode enough IO
	 *	address lines to uniquely use that address, then we have
	 *	the flexibility to choose an alternative base address.
	 * Note that if the client specifies that the card decodes zero
	 *	IO address lines, then we have to use the NumPortsX
	 *	values to figure out how many address lines the card
	 *	actually decodes, and we have to round the NumPortsX
	 *	values up to the closest power of two.
	 */
	if (ior->IOAddrLines) {
	    ior->BasePort1.base = IOADDR_FROBNITZ(ior->BasePort1.base,
		ior->IOAddrLines);
	    ior->BasePort2.base = IOADDR_FROBNITZ(ior->BasePort2.base,
		ior->IOAddrLines);
	} else {
	    ior->BasePort1.base = ior->BasePort1.base &
				((IONUMPORTS_FROBNITZ(ior->NumPorts1) +
				IONUMPORTS_FROBNITZ(ior->NumPorts2)) - 1);
	    ior->BasePort2.base = ior->BasePort2.base &
				((IONUMPORTS_FROBNITZ(ior->NumPorts1) +
				IONUMPORTS_FROBNITZ(ior->NumPorts2)) - 1);
	}

	socket_num = CS_MAKE_SOCKET_NUMBER(GET_CLIENT_SOCKET(client_handle),
	    GET_CLIENT_FUNCTION(client_handle));


#ifdef	USE_IOMMAP_WINDOW
	/*
	 * Here is where the code diverges, depending on the type of IO windows
	 *	that this socket supports.  If this socket supportes memory
	 *	mapped IO windows, as determined by cs_init allocating an
	 *	io_mmap_window_t structure on the socket structure, then we
	 *	use one IO window for all the clients on this socket.  We can
	 *	do this safely since a memory mapped IO window implies that
	 *	only this socket shares the complete IO space of the card.
	 * See the next major block of code for a description of what we do
	 *	if a socket doesn't support memory mapped IO windows.
	 */
	if (sp->io_mmap_window) {
	    cs_window_t *cw;
	    io_mmap_window_t *imw = sp->io_mmap_window;
	    uint32_t offset;

		/*
		 * If we haven't allocated an IO window yet, do it now.
		 * Try to allocate the IO window that cs_init found for us;
		 * if that fails, then call cs_find_io_win to find a window.
		 */
	    if (!imw->count) {
		set_window_t set_window;

		if (!WINDOW_AVAILABLE_FOR_IO(imw->number)) {
		    iowin_char_t iowin_char;

		    iowin_char.IOWndCaps = (WC_IO_RANGE_PER_WINDOW |
					    WC_8BIT |
					    WC_16BIT);
		    if ((error = cs_find_io_win(sp->socket_num, &iowin_char,
				    &imw->number, &imw->size)) != CS_SUCCESS) {
			EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
			mutex_exit(&cs_globals.window_lock);
		    } /* cs_find_io_win */
		} /* if (!WINDOW_AVAILABLE_FOR_IO) */

		set_window.socket = socket_num;
		set_window.window = imw->number;
		set_window.speed = IO_WIN_SPEED;
		set_window.base.base = 0;
		set_window.WindowSize = imw->size;
		set_window.state = (WS_ENABLED | WS_16BIT |
				    WS_EXACT_MAPIN | WS_IO);

		/* XXX - what to d here? XXX */
		cs_set_acc_attributes(&set_window, Attributes);

		if (SocketServices(SS_SetWindow, &set_window) != SUCCESS) {
		    (void) cs_setup_io_win(socket_num, imw->number,
						NULL, NULL, NULL,
						(IO_DEALLOCATE_WINDOW |
						IO_DISABLE_WINDOW));
		    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		    mutex_exit(&cs_globals.window_lock);
		    return (CS_BAD_WINDOW);
		}

		imw->handle = set_window.base.handle;
		imw->size = set_window.WindowSize;

		/*
		 * Check the caller's port requirements to be sure that they
		 *	fit within our found IO window.
		 */
		if ((ior->BasePort1.base + ior->NumPorts1 +
			ior->BasePort2.base + ior->NumPorts2) > imw->size) {
		    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		    mutex_exit(&cs_globals.window_lock);
		    return (CS_BAD_BASE);
		}

		if ((cw = cs_get_wp(imw->number)) == NULL) {
		    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		    mutex_exit(&cs_globals.window_lock);
		    return (CS_BAD_WINDOW)
		}
		cw->state |= (CW_ALLOCATED | CW_IO);

	    } /* if (!imw->count) */

	    imw->count++;

		/*
		 * All common access handles for this type of adapter are
		 * duped.  We never give the original back to the caller.
		 */
	    /* XXX need to set endianess and data ordering flags */
	    csx_DupHandle(imw->handle, &ior->BasePort1.handle, 0);
	    csx_GetHandleOffset(ior->BasePort1.handle, &offset);
	    csx_SetHandleOffset(ior->BasePort1.handle,
		ior->BasePort1.base + offset);

	    if (ior->NumPorts2) {
		/* XXX need to set endianess and data ordering flags */
		csx_DupHandle(imw->handle, &ior->BasePort2.handle, 0);
		csx_GetHandleOffset(ior->BasePort2.handle, &offset);
		csx_SetHandleOffset(ior->BasePort2.handle,
		    ior->BasePort1.base + offset);
	    }

		/*
		 * We don't really use these two values if we've got a memory
		 * mapped IO window since the assigned window number is stored
		 * in imw->number.
		 */
	    client->io_alloc.Window1 = imw->number;
	    client->io_alloc.Window2 = PCMCIA_MAX_WINDOWS;

	/*
	 * This socket supports only IO port IO windows.
	 */
	} else {
#else	/* USE_IOMMAP_WINDOW */
	{
#endif	/* USE_IOMMAP_WINDOW */
	    baseaddru_t baseaddru;

	    baseaddru.base = ior->BasePort1.base;

	    if ((error = cs_allocate_io_win(sp->socket_num, ior->Attributes1,
		&client->io_alloc.Window1)) != CS_SUCCESS) {

		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		mutex_exit(&cs_globals.window_lock);
		return (error);
	    } /* if (cs_allocate_io_win(1)) */

		/*
		 * Setup the window hardware; if this fails, then we need to
		 *	deallocate the previously allocated window.
		 */
	    if ((error = cs_setup_io_win(socket_num,
						client->io_alloc.Window1,
						&baseaddru,
						&ior->NumPorts1,
						ior->IOAddrLines,
						ior->Attributes1)) !=
								CS_SUCCESS) {
		(void) cs_setup_io_win(socket_num, client->io_alloc.Window1,
					NULL, NULL, NULL,
					(
						IO_DEALLOCATE_WINDOW |
						IO_DISABLE_WINDOW));

		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		mutex_exit(&cs_globals.window_lock);
		return (error);
	    } /* if (cs_setup_io_win(1)) */

	    ior->BasePort1.handle = (acc_handle_t)baseaddru.handle;
	    ior->BasePort1.base = baseaddru.base;

		/*
		 * See if the client wants two IO ranges.
		 */
	    if (ior->NumPorts2) {
		baseaddru_t baseaddru;

		baseaddru.base = ior->BasePort2.base;

		/*
		 * If we fail to allocate this window, then we must deallocate
		 *	the previous IO window that is already allocated.
		 */
		if ((error = cs_allocate_io_win(sp->socket_num,
						ior->Attributes2,
						&client->io_alloc.Window2)) !=
								CS_SUCCESS) {
		    (void) cs_setup_io_win(socket_num,
						client->io_alloc.Window2,
						NULL, NULL, NULL,
						(
							IO_DEALLOCATE_WINDOW |
							IO_DISABLE_WINDOW));
		    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		    mutex_exit(&cs_globals.window_lock);
		    return (error);
		} /* if (cs_allocate_io_win(2)) */
		/*
		 * Setup the window hardware; if this fails, then we need to
		 *	deallocate the previously allocated window.
		 */
		if ((error = cs_setup_io_win(socket_num,
						client->io_alloc.Window2,
						&baseaddru,
						&ior->NumPorts2,
						ior->IOAddrLines,
						ior->Attributes2)) !=
								CS_SUCCESS) {
		    (void) cs_setup_io_win(socket_num,
						client->io_alloc.Window1,
						NULL, NULL, NULL,
						(
							IO_DEALLOCATE_WINDOW |
							IO_DISABLE_WINDOW));
		    (void) cs_setup_io_win(socket_num,
						client->io_alloc.Window2,
						NULL, NULL, NULL,
						(
							IO_DEALLOCATE_WINDOW |
							IO_DISABLE_WINDOW));
		    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		    mutex_exit(&cs_globals.window_lock);
		    return (error);
		} /* if (cs_setup_io_win(2)) */

		ior->BasePort2.handle = (acc_handle_t)baseaddru.handle;
		ior->BasePort2.base = baseaddru.base;

	    } else {
		client->io_alloc.Window2 = PCMCIA_MAX_WINDOWS;
	    } /* if (ior->NumPorts2) */
	} /* if (sp->io_mmap_window) */

	/*
	 * Save a copy of the client's port information so that we
	 *	can use it in the RequestConfiguration call.  We set
	 *	the IO window number(s) allocated in the respective
	 *	section of code, above.
	 */
	client->io_alloc.BasePort1.base = ior->BasePort1.base;
	client->io_alloc.BasePort1.handle = ior->BasePort1.handle;
	client->io_alloc.NumPorts1 = ior->NumPorts1;
	client->io_alloc.Attributes1 = ior->Attributes1;
	client->io_alloc.BasePort2.base = ior->BasePort2.base;
	client->io_alloc.BasePort2.handle = ior->BasePort2.handle;
	client->io_alloc.NumPorts2 = ior->NumPorts2;
	client->io_alloc.Attributes2 = ior->Attributes2;
	client->io_alloc.IOAddrLines = ior->IOAddrLines;

	/*
	 * Mark this client as having done a successful RequestIO call.
	 */
	client->flags |= (REQ_IO_DONE | CLIENT_IO_ALLOCATED);

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	mutex_exit(&cs_globals.window_lock);

	return (CS_SUCCESS);
}

/*
 * cs_release_io - releases IO resources allocated by RequestIO; this is
 *			ReleaseIO
 *
 *	calling: cs_release_io(client_handle_t, io_req_t *)
 *
 *	returns: CS_SUCCESS - if IO resources sucessfully deallocated
 *		 CS_BAD_HANDLE - client handle is invalid
 *		 CS_UNSUPPORTED_FUNCTION - if SS is trying to call us
 *		 CS_CONFIGURATION_LOCKED - a RequestConfiguration has been
 *				done without a ReleaseConfiguration
 *		 CS_IN_USE - no RequestIO has been done
 */
static int
cs_release_io(client_handle_t client_handle, io_req_t *ior)
{
	cs_socket_t *sp;
	client_t *client;
	int error;
	int client_lock_acquired;
	uint32_t socket_num;

#ifdef	lint
	ior = NULL;
#endif

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't support SS using this call.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_UNSUPPORTED_FUNCTION);

	mutex_enter(&cs_globals.window_lock);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (error);
	}

	/*
	 * If RequestConfiguration has already been done, we don't allow
	 *	this call.
	 */
	if (client->flags & REQ_CONFIGURATION_DONE) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_CONFIGURATION_LOCKED);
	}

	/*
	 * If RequestIO has not been done, we don't allow this call.
	 */
	if (!(client->flags & REQ_IO_DONE)) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_IN_USE);
	}

	socket_num = CS_MAKE_SOCKET_NUMBER(GET_CLIENT_SOCKET(client_handle),
	    GET_CLIENT_FUNCTION(client_handle));

#ifdef	XXX
	/*
	 * Check the passed IO allocation with the stored allocation; if
	 *	they don't match, then return an error.
	 */
	if ((client->io_alloc.BasePort1 != ior->BasePort1) ||
	    (client->io_alloc.NumPorts1 != ior->NumPorts1) ||
	    (client->io_alloc.Attributes1 != ior->Attributes1) ||
	    (client->io_alloc.BasePort2 != ior->BasePort2) ||
	    (client->io_alloc.NumPorts2 != ior->NumPorts2) ||
	    (client->io_alloc.Attributes2 != ior->Attributes2) ||
	    (client->io_alloc.IOAddrLines != ior->IOAddrLines)) {
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		mutex_exit(&cs_globals.window_lock);
		return (CS_BAD_ARGS);
	}
#endif

#ifdef	USE_IOMMAP_WINDOW
	/*
	 * The code diverges here depending on if this socket supports
	 *	memory mapped IO windows or not.  See comments in the
	 *	cs_request_io function for a description of what's
	 *	going on here.
	 */
	if (sp->io_mmap_window) {
	    io_mmap_window_t *imw = sp->io_mmap_window;

		/*
		 * We should never see this; if we do, it's an internal
		 *	consistency error.
		 */
	    if (!imw->count) {
		cmn_err(CE_CONT, "cs_release_io: socket %d !imw->count\n",
							    sp->socket_num);
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		mutex_exit(&cs_globals.window_lock);
		return (CS_GENERAL_FAILURE);
	    }

		/*
		 * All common access handles for this type of adapter are
		 *	duped. We never give the original back to the caller,
		 *	so it's OK to unconditionally free the handle here.
		 */
	    csx_FreeHandle(&ior->BasePort1.handle);

		/*
		 * If the IO window referance count is zero, then deallocate
		 * and disable this window.
		 */
	    if (!--(imw->count)) {
		(void) cs_setup_io_win(socket_num, imw->number, NULL,
								NULL, NULL,
						(
							IO_DEALLOCATE_WINDOW |
							IO_DISABLE_WINDOW));
	    } /* if (imw->count) */
	} else {
#endif	/* USE_IOMMAP_WINDOW */
	    (void) cs_setup_io_win(socket_num, client->io_alloc.Window1,
						NULL, NULL, NULL,
						(
							IO_DEALLOCATE_WINDOW |
							IO_DISABLE_WINDOW));
	    if (client->io_alloc.Window2 != PCMCIA_MAX_WINDOWS)
		(void) cs_setup_io_win(socket_num, client->io_alloc.Window2,
						NULL, NULL, NULL,
						(
							IO_DEALLOCATE_WINDOW |
							IO_DISABLE_WINDOW));
#ifdef	USE_IOMMAP_WINDOW
	} /* if (sp->io_mmap_window) */
#endif	/* USE_IOMMAP_WINDOW */

	/*
	 * Mark the client as not having any IO resources allocated.
	 */
	client->flags &= ~(REQ_IO_DONE | CLIENT_IO_ALLOCATED);

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	mutex_exit(&cs_globals.window_lock);
	return (CS_SUCCESS);
}

/*
 * cs_find_io_win - finds an IO window that matches the parameters specified
 *			in the flags argument
 *
 *	calling: sn - socket number to look for IO window on
 *		 *iwc - other window characteristics to match
 *		 *assigned_window - pointer to where we return the assigned
 *					window number if we found a window or
 *					undefined otherwise
 *		 *size - if non-NULL, the found window size will be stored here
 *
 *	returns: CS_SUCCESS - if IO window found
 *		 CS_OUT_OF_RESOURCE - if no windows match requirements
 */
static int
cs_find_io_win(uint32_t sn, iowin_char_t *iwc, uint32_t *assigned_window,
    uint32_t *size)
{
	inquire_window_t inquire_window, *iw;
	unsigned wn;

	iw = &inquire_window;

	for (wn = 0; wn < cs_globals.num_windows; wn++) {
	    iowin_char_t *iowc;
	    cs_window_t *cw;

	    if ((cw = cs_get_wp(wn)) != NULL) {

		iw->window = wn;
		SocketServices(SS_InquireWindow, iw);

		iowc = &iw->iowin_char;

		if (WINDOW_FOR_SOCKET(iw->Sockets, sn) &&
		    WINDOW_AVAILABLE_FOR_IO(cw) &&
		    (iw->WndCaps & WC_IO) &&
		    ((iowc->IOWndCaps & iwc->IOWndCaps) == iwc->IOWndCaps)) {

			*assigned_window = wn;

			if (size)
			    *size = iw->iowin_char.ReqGran;
			return (CS_SUCCESS);
		    } /* if (WINDOW_FOR_SOCKET) */
	    } /* cs_get_wp */
	} /* for (wn) */

	return (CS_OUT_OF_RESOURCE);
}

/*
 * cs_allocate_io_win - finds and allocates an IO window
 *
 *	calling: sn - socket number to look for window on
 *		 Attributes - window attributes in io_req_t.Attributes format
 *		 *assigned_window - pointer to return assigned window number
 *
 *	returns: CS_SUCCESS - IO window found and allocated
 *		 CS_OUT_OF_RESOURCE - if cs_find_io_win couldn't find a
 *				window that matches the passed criteria
 *
 * Note: This fucntion will find and allocate an IO window.  The caller is
 *	responsible for deallocating the window.
 */
static int
cs_allocate_io_win(uint32_t sn, uint32_t Attributes, uint32_t *assigned_window)
{
	iowin_char_t iowin_char;
	cs_window_t *cw;

	iowin_char.IOWndCaps =
		((Attributes & IO_DATA_PATH_WIDTH_16)?WC_16BIT:WC_8BIT);

	if (cs_find_io_win(sn, &iowin_char, assigned_window, NULL) ==
								CS_SUCCESS) {
	    if ((cw = cs_get_wp(*assigned_window)) == NULL)
		return (CS_OUT_OF_RESOURCE);

	    cw->state = (cw->state & CW_WINDOW_VALID) | (CW_ALLOCATED | CW_IO);
	    return (CS_SUCCESS);
	}

	return (CS_OUT_OF_RESOURCE);
}

/*
 * cs_setup_io_win - setup and destroy an IO window
 *
 *	calling: sn - socket number
 *		 wn - window number
 * XXX Base - pointer to XXX
 *		 *NumPorts - pointer to number of allocated ports to return
 *		 IOAddrLines - number of IO address lines decoded by this card
 *		 Attributes - either io_req_t attributes, or a combination of
 *				the following flags:
 *				    IO_DEALLOCATE_WINDOW - deallocate the window
 *				    IO_DISABLE_WINDOW - disable the window
 *				When either of these two flags are set, *Base
 *				    and NumPorts should be NULL.
 *
 *	returns: CS_SUCCESS - if no failure
 *		 CS_BAD_WINDOW - if error while trying to configure window
 *
 * Note: We use the IOAddrLines value to determine what base address to pass
 *		to Socket Services.
 */
static int
cs_setup_io_win(uint32_t sn, uint32_t wn, baseaddru_t *Base, uint32_t *NumPorts,
    uint32_t IOAddrLines, uint32_t Attributes)
{
	set_window_t set_window;

	if (Attributes & (IO_DEALLOCATE_WINDOW | IO_DISABLE_WINDOW)) {

	    if (Attributes & IO_DEALLOCATE_WINDOW) {
		cs_window_t *cw;

		if ((cw = cs_get_wp(wn)) == NULL)
		    return (CS_BAD_WINDOW);
		cw->state &= CW_WINDOW_VALID;

	    } /* IO_DEALLOCATE_WINDOW */

	    if (Attributes & IO_DISABLE_WINDOW) {
		get_window_t get_window;

		get_window.window = wn;

		SocketServices(SS_GetWindow, &get_window);

		set_window.socket = get_window.socket;
		set_window.window = get_window.window;
		set_window.speed = get_window.speed;
		set_window.base = 0;
		set_window.WindowSize = get_window.size;
		set_window.state = get_window.state & ~WS_ENABLED;

		cs_set_acc_attributes(&set_window, Attributes);

		SocketServices(SS_SetWindow, &set_window);
	    } /* IO_DISABLE_WINDOW */

	    return (CS_SUCCESS);

	} /* if (IO_DEALLOCATE_WINDOW | IO_DISABLE_WINDOW) */

	/*
	 * See if we can allow Socket Services to select the base address
	 *	value for this card; if the client has specified a non-zero
	 *	base IO address but the card doesn't decode enough IO
	 *	address lines to uniquely use that address, then we have
	 *	the flexibility to choose an alternative base address.
	 * XXX - Is this really correct in all cases?
	 */
	if (!IOAddrLines)
	    Base->base = 0;
	else
	    Base->base = IOADDR_FROBNITZ(Base->base, IOAddrLines);

	set_window.socket = sn;
	set_window.window = wn;
	set_window.speed = IO_WIN_SPEED;
	set_window.base = Base->base;
	set_window.WindowSize = *NumPorts;
	set_window.state = (WS_ENABLED | WS_IO |
			((Attributes & IO_DATA_PATH_WIDTH_16)?WS_16BIT:0));

	cs_set_acc_attributes(&set_window, Attributes);

	if (SocketServices(SS_SetWindow, &set_window) != SUCCESS)
	    return (CS_BAD_WINDOW);

	Base->base = set_window.base;
	Base->handle = set_window.handle;
	*NumPorts = set_window.WindowSize;

	return (CS_SUCCESS);
}

/*
 * ==== IRQ handling functions ====
 */

/*
 * cs_request_irq - add's client's IRQ handler; supports RequestIRQ
 *
 *	calling: irq_req_t.Attributes - must have the IRQ_TYPE_EXCLUSIVE
 *			flag set, and all other flags clear, or
 *			CS_BAD_ATTRIBUTE will be returned
 *
 *	returns: CS_SUCCESS - if IRQ resources available for client
 *		 CS_BAD_IRQ - if IRQ can not be allocated
 *		 CS_BAD_HANDLE - client handle is invalid
 *		 CS_UNSUPPORTED_FUNCTION - if SS is trying to call us
 *		 CS_NO_CARD - if no card is in socket
 *		 CS_BAD_ATTRIBUTE - if any of the unsupported Attribute
 *					flags are set
 *		 CS_CONFIGURATION_LOCKED - a RequestConfiguration has
 *					already been done
 *		 CS_IN_USE - IRQ ports already in use or function has
 *					already been called
 *
 * Note: We only allow level-mode interrupts.
 */
static int
cs_request_irq(client_handle_t client_handle, irq_req_t *irqr)
{
	cs_socket_t *sp;
	client_t *client;
	set_irq_handler_t set_irq_handler;
	int error;
	int client_lock_acquired;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't support SS using this call.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_UNSUPPORTED_FUNCTION);

	/*
	 * Make sure that none of the unsupported or reserved flags are set.
	 */
	if ((irqr->Attributes &	(IRQ_TYPE_TIME | IRQ_TYPE_DYNAMIC_SHARING |
				IRQ_FIRST_SHARED | IRQ_PULSE_ALLOCATED |
				IRQ_FORCED_PULSE)) ||
		!(irqr->Attributes & IRQ_TYPE_EXCLUSIVE))
	    return (CS_BAD_ATTRIBUTE);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	/*
	 * If RequestConfiguration has already been done, we don't allow
	 *	this call.
	 */
	if (client->flags & REQ_CONFIGURATION_DONE) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_CONFIGURATION_LOCKED);
	}

	/*
	 * If RequestIRQ has already been done, we don't allow this call.
	 */
	if (client->flags & REQ_IRQ_DONE) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_IN_USE);
	}

	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED)) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_NO_CARD);
	}

	/*
	 * Set up the parameters and ask Socket Services to give us an IRQ
	 *	for this client.  We don't really do much, since the IRQ
	 *	resources are managed by SS and the kernel.  We also don't
	 *	care which IRQ level we are given.
	 */
	set_irq_handler.socket =
		CS_MAKE_SOCKET_NUMBER(GET_CLIENT_SOCKET(client_handle),
					GET_CLIENT_FUNCTION(client_handle));
	set_irq_handler.irq = IRQ_ANY;

	set_irq_handler.handler_id = client_handle;
	set_irq_handler.handler = (f_t *)irqr->irq_handler;
	set_irq_handler.arg1 = irqr->irq_handler_arg;
	set_irq_handler.arg2 = NULL;

	if ((error = SocketServices(SS_SetIRQHandler,
					&set_irq_handler)) != SUCCESS) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_IRQ);
	}

	irqr->iblk_cookie = set_irq_handler.iblk_cookie;
	irqr->idev_cookie = set_irq_handler.idev_cookie;

	/*
	 * Save the allocated IRQ information for this client.
	 */
	client->irq_alloc.Attributes = irqr->Attributes;
	client->irq_alloc.irq = set_irq_handler.irq;
	client->irq_alloc.handler_id = set_irq_handler.handler_id;
	client->irq_alloc.irq_handler = (f_t *)set_irq_handler.handler;
	client->irq_alloc.irq_handler_arg1 = set_irq_handler.arg1;
	client->irq_alloc.irq_handler_arg2 = set_irq_handler.arg2;

#ifdef	CS_DEBUG
	if (cs_debug > 0)
	    cmn_err(CE_CONT, "cs_request_irq: socket %d irqr->Attributes 0x%x "
						"set_irq_handler.irq 0x%x\n",
						sp->socket_num,
						(int)irqr->Attributes,
						set_irq_handler.irq);
#endif

	/*
	 * Mark this client as having done a successful RequestIRQ call.
	 */
	client->flags |= (REQ_IRQ_DONE | CLIENT_IRQ_ALLOCATED);

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	return (CS_SUCCESS);
}

/*
 * cs_release_irq - releases IRQ resources allocated by RequestIRQ; this is
 *			ReleaseIRQ
 *
 *	calling: cs_release_irq(client_handle_t, irq_req_t *)
 *
 *	returns: CS_SUCCESS - if IRQ resources sucessfully deallocated
 *		 CS_BAD_IRQ - if IRQ can not be deallocated
 *		 CS_BAD_HANDLE - client handle is invalid
 *		 CS_UNSUPPORTED_FUNCTION - if SS is trying to call us
 *		 CS_CONFIGURATION_LOCKED - a RequestConfiguration has been
 *				done without a ReleaseConfiguration
 *		 CS_IN_USE - no RequestIRQ has been done
 */
static int
cs_release_irq(client_handle_t client_handle, irq_req_t *irqr)
{
	cs_socket_t *sp;
	client_t *client;
	clear_irq_handler_t clear_irq_handler;
	int error;
	int client_lock_acquired;

#ifdef	lint
	irqr = NULL;
#endif

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't support SS using this call.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_UNSUPPORTED_FUNCTION);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	/*
	 * If RequestConfiguration has already been done, we don't allow
	 *	this call.
	 */
	if (client->flags & REQ_CONFIGURATION_DONE) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_CONFIGURATION_LOCKED);
	}

	/*
	 * If RequestIRQ has not been done, we don't allow this call.
	 */
	if (!(client->flags & REQ_IRQ_DONE)) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_IN_USE);
	}

	/*
	 * Tell Socket Services that we want to deregister this client's
	 *	IRQ handler.
	 */
	clear_irq_handler.socket =
		CS_MAKE_SOCKET_NUMBER(GET_CLIENT_SOCKET(client_handle),
				GET_CLIENT_FUNCTION(client_handle));
	clear_irq_handler.handler_id = client->irq_alloc.handler_id;
	clear_irq_handler.handler = (f_t *)client->irq_alloc.irq_handler;

	/*
	 * At this point, we should never fail this SS call; if we do, it
	 *	means that there is an internal consistancy error in either
	 *	Card Services or Socket Services.
	 */
	if ((error = SocketServices(SS_ClearIRQHandler, &clear_irq_handler)) !=
								SUCCESS) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_IRQ);
	}

	/*
	 * Mark the client as not having any IRQ resources allocated.
	 */
	client->flags &= ~(REQ_IRQ_DONE | CLIENT_IRQ_ALLOCATED);

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	return (CS_SUCCESS);
}

/*
 * ==== configuration handling functions ====
 */

/*
 * cs_request_configuration - sets up socket and card configuration on behalf
 *		of the client; this is RequestConfiguration
 *
 *	returns: CS_SUCCESS - if configuration sucessfully set
 *		 CS_BAD_SOCKET - if Socket Services returns an error
 *		 CS_UNSUPPORTED_FUNCTION - if SS is trying to call us
 *		 CS_BAD_ATTRIBUTE - if any unsupported or reserved flags
 *					are set
 *		 CS_BAD_TYPE - if the socket doesn't support a mem and IO
 *				interface (SOCKET_INTERFACE_MEMORY_AND_IO set)
 *		 CS_CONFIGURATION_LOCKED - a RequestConfiguration has
 *					already been done
 *		 CS_BAD_VCC - if Vcc value is not supported by socket
 *		 CS_BAD_VPP1 - if Vpp1 value is not supported by socket
 *		 CS_BAD_VPP2 - if Vpp2 value is not supported by socket
 *
 * Bug ID: 1193637 - Card Services RequestConfiguration does not conform
 *	to PCMCIA standard
 * We allow clients to do a RequestConfiguration even if they haven't
 *	done a RequestIO or RequestIRQ.
 */
static int
cs_request_configuration(client_handle_t client_handle, config_req_t *cr)
{
	cs_socket_t *sp;
	client_t *client;
	volatile config_regs_t *crt;
	set_socket_t set_socket;
	get_socket_t get_socket;
	acc_handle_t cis_handle;
	int error;
	uint32_t newoffset;
	int client_lock_acquired;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't support SS using this call.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_UNSUPPORTED_FUNCTION);

#ifdef	XXX
	/*
	 * If the client specifies Vcc = 0 and any non-zero value for
	 *	either of the Vpp members, that's an illegal condition.
	 */
	if (!(cr->Vcc) && (cr->Vpp1 || cr->Vpp2))
	    return (CS_BAD_VCC);
#endif

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	/*
	 * If the client is asking for a memory and IO interface on this
	 *	socket, then check the socket capabilities to be sure that
	 *	this socket supports this configuration.
	 */
	if (cr->IntType & SOCKET_INTERFACE_MEMORY_AND_IO) {
	    inquire_socket_t inquire_socket;

	    inquire_socket.socket = sp->socket_num;

	    if (SocketServices(SS_InquireSocket, &inquire_socket) != SUCCESS)
		return (CS_BAD_SOCKET);

	    if (!(inquire_socket.SocketCaps & IF_IO))
		return (CS_BAD_TYPE);

	} /* if (SOCKET_INTERFACE_MEMORY_AND_IO) */

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	/*
	 * If RequestConfiguration has already been done, we don't allow
	 *	this call.
	 */
	if (client->flags & REQ_CONFIGURATION_DONE) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_CONFIGURATION_LOCKED);
	}

	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED)) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_NO_CARD);
	}

	/*
	 * At this point, most of the client's calling parameters have been
	 *	validated, so we can go ahead and configure the socket and
	 *	the card.
	 */
	mutex_enter(&sp->cis_lock);

	/*
	 * Configure the socket with the interface type and voltages requested
	 *	by the client.
	 */
	get_socket.socket = sp->socket_num;

	if (SocketServices(SS_GetSocket, &get_socket) != SUCCESS) {
	    mutex_exit(&sp->cis_lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_SOCKET);
	}

#ifdef	CS_DEBUG
	if (cs_debug > 0)
	    cmn_err(CE_CONT, "cs_request_configuration: socket %d "
					"client->irq_alloc.irq 0x%x "
					"get_socket.IRQRouting 0x%x\n",
						sp->socket_num,
						(int)client->irq_alloc.irq,
						get_socket.IRQRouting);
#endif

	bzero(&set_socket, sizeof (set_socket));
	set_socket.socket = sp->socket_num;
	set_socket.IREQRouting = client->irq_alloc.irq & ~IRQ_ENABLE;

	set_socket.CtlInd = get_socket.CtlInd;
	set_socket.State = 0;	/* don't reset latched values */

	if (cs_convert_powerlevel(sp->socket_num, cr->Vcc, VCC,
					&set_socket.VccLevel) != CS_SUCCESS) {
	    mutex_exit(&sp->cis_lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_VCC);
	}

	if (cs_convert_powerlevel(sp->socket_num, cr->Vpp1, VPP1,
					&set_socket.Vpp1Level) != CS_SUCCESS) {
	    mutex_exit(&sp->cis_lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_VPP);
	}

	if (cs_convert_powerlevel(sp->socket_num, cr->Vpp2, VPP2,
					&set_socket.Vpp2Level) != CS_SUCCESS) {
	    mutex_exit(&sp->cis_lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_VPP);
	}

	if (!(cr->IntType & SOCKET_INTERFACE_MEMORY_AND_IO))
		set_socket.IFType = IF_MEMORY;
	else {
		set_socket.IFType = IF_IO;

		/*
		 * The Cirrus Logic PD6710/672X/others? adapters will write
		 * protect the CIS if the socket is in MEMORY mode and the
		 * WP/IOCS16 pin is true.  When this happens, the CIS registers
		 * will fail to be written.  Go ahead and set the socket,
		 * even though the event mask isn't complete yet, so we can
		 * configure the adapter.  Afterwards, set the socket again
		 * to make sure the event mask is correct.
		 */
		if (SocketServices(SS_SetSocket, &set_socket) != SUCCESS) {
			sp->flags &= ~SOCKET_IS_IO;
			mutex_exit(&sp->cis_lock);
			EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
			return (CS_BAD_SOCKET);
		}
	}

	if (cs_rc2_delay)
	    drv_usecwait(cs_rc2_delay * 1000);

	/*
	 * Get a pointer to a window that contains the configuration
	 *	registers.
	 */
	mutex_enter(&sp->lock);
	client->config_regs_offset = cr->ConfigBase;
	newoffset = client->config_regs_offset;
	mutex_exit(&sp->lock);
	if (cs_init_cis_window(sp, &newoffset, &cis_handle,
					CISTPLF_AM_SPACE) != CS_SUCCESS) {
	    mutex_exit(&sp->cis_lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    cmn_err(CE_CONT, "cs_request_configuration: socket %d can't init "
				"CIS window\n", sp->socket_num);
	    return (CS_GENERAL_FAILURE);
	}

	/*
	 * Setup the config register pointers.
	 * Note that these pointers are not the complete virtual address;
	 *	the complete address is constructed each time the registers
	 *	are accessed.
	 */
	mutex_enter(&sp->lock);
	crt = &client->config_regs;
	client->present = cr->Present;

	bzero((char *)crt, sizeof (config_regs_t));

	/* Configuration Option Register */
	if (client->present & CONFIG_OPTION_REG_PRESENT)
	    crt->cor_p = (newoffset + CONFIG_OPTION_REG_OFFSET);

	/* Configuration and Status Register */
	if (client->present & CONFIG_STATUS_REG_PRESENT)
	    crt->ccsr_p = (newoffset + CONFIG_STATUS_REG_OFFSET);

	/* Pin Replacement Register */
	if (client->present & CONFIG_PINREPL_REG_PRESENT)
	    crt->prr_p = (newoffset + CONFIG_PINREPL_REG_OFFSET);

	/* Socket and Copy Register */
	if (client->present & CONFIG_COPY_REG_PRESENT)
	    crt->scr_p = (newoffset + CONFIG_COPY_REG_OFFSET);

	/* Extended Status Register */
	if (client->present & CONFIG_EXSTAT_REG_PRESENT)
	    crt->exstat_p = (newoffset + CONFIG_EXSTAT_REG_OFFSET);

	/* IO Base 0 Register */
	if (client->present & CONFIG_IOBASE0_REG_PRESENT)
	    crt->iobase0_p = (newoffset + CONFIG_IOBASE0_REG_OFFSET);

	/* IO Base 1 Register */
	if (client->present & CONFIG_IOBASE1_REG_PRESENT)
	    crt->iobase1_p = (newoffset + CONFIG_IOBASE1_REG_OFFSET);

	/* IO Base 2 Register */
	if (client->present & CONFIG_IOBASE2_REG_PRESENT)
	    crt->iobase2_p = (newoffset + CONFIG_IOBASE2_REG_OFFSET);

	/* IO Base 3 Register */
	if (client->present & CONFIG_IOBASE3_REG_PRESENT)
	    crt->iobase3_p = (newoffset + CONFIG_IOBASE3_REG_OFFSET);

	/* IO Limit Register */
	if (client->present & CONFIG_IOLIMIT_REG_PRESENT)
	    crt->iolimit_p = (newoffset + CONFIG_IOLIMIT_REG_OFFSET);

	/*
	 * Setup the bits in the PRR mask that are valid; this is easy, just
	 *	copy the Pin value that the client gave us.  Note that for
	 *	this to work, the client must set both of the XXX_STATUS
	 *	and the XXX_EVENT bits in the Pin member.
	 */
	client->pin = cr->Pin;

#ifdef	CS_DEBUG
	if (cs_debug > 128)
	    cmn_err(CE_CONT, "cs_request_configuration: client->pin 0x%x "
		"client->config_regs_offset 0x%x newoffset 0x%x cor_p 0x%x "
		"ccsr_p 0x%x prr_p 0x%x scr_p 0x%x\n",
		client->pin, (int)client->config_regs_offset, newoffset,
		(int)crt->cor_p, (int)crt->ccsr_p, (int)crt->prr_p,
		(int)crt->scr_p);
#endif

	/*
	 * If the socket isn't in IO mode, WP is asserted,  and we're going to
	 * write any of the config registers, issue a warning.
	 */
	if ((client->present != 0) &&
	    (!(cr->IntType & SOCKET_INTERFACE_MEMORY_AND_IO)) &&
	    (get_socket.state & SBM_WP)) {
		cmn_err(CE_NOTE, "!cs_request_configuration: attempting to "
		    "write CIS config regs with WP set\n");
	}

	/*
	 * Write any configuration registers that the client tells us are
	 *	present to the card; save a copy of what we wrote so that we
	 *	can return them if the client calls GetConfigurationInfo.
	 * The order in which we write the configuration registers is
	 *	specified by the PCMCIA spec; we must write the socket/copy
	 *	register first (if it exists), and then we can write the
	 *	registers in any arbitrary order.
	 */
	/* Socket and Copy Register */
	if (client->present & CONFIG_COPY_REG_PRESENT) {
	    crt->scr = cr->Copy;
	    csx_Put8(cis_handle, crt->scr_p, crt->scr);
	}

	/* Pin Replacement Register */
	if (client->present & CONFIG_PINREPL_REG_PRESENT) {
	    crt->prr = cr->Pin;
	    csx_Put8(cis_handle, crt->prr_p, crt->prr);
	}

	/* Configuration and Status Register */
	/* XXX should we set CCSR_SIG_CHG in the CCSR? XXX */
	if (client->present & CONFIG_STATUS_REG_PRESENT) {
	    crt->ccsr = cr->Status;
	    csx_Put8(cis_handle, crt->ccsr_p, crt->ccsr);
	}

	/* Extended Status Register */
	if (client->present & CONFIG_EXSTAT_REG_PRESENT) {
	    crt->exstat = cr->ExtendedStatus;
	    csx_Put8(cis_handle, crt->exstat_p, crt->exstat);
	}

	/*
	 * If any IO base and limit registers exist, and this client
	 *	has done a RequestIO, setup the IO Base and IO Limit
	 *	registers.
	 */
	if (client->flags & REQ_IO_DONE) {
	    if (client->present & CONFIG_IOBASE0_REG_PRESENT) {
		uint32_t base = client->io_alloc.BasePort1.base;
		uint32_t present = (client->present &
					CONFIG_IOBASE_REG_MASK) >>
						CONFIG_IOBASE_REG_SHIFT;
		uint32_t reg = crt->iobase0_p;

		do {
		    csx_Put8(cis_handle, reg, base & 0x0ff);
		    reg = reg + 2;
		    base = base >> 8;
		    present = present >> 1;
		} while (present);
	    } /* CONFIG_IOBASE0_REG_PRESENT */

	    if (client->present & CONFIG_IOLIMIT_REG_PRESENT) {
		uint32_t np = client->io_alloc.NumPorts1 +
					client->io_alloc.NumPorts2;
		uint32_t limit, do_bit = 0;
		int lm;

		limit = (IONUMPORTS_FROBNITZ(np) - 1);

		for (lm = 7; lm >= 0; lm--) {
		    if (limit & (1 << lm))
			do_bit = 1;
		    if (do_bit)
			limit |= (1 << lm);
		} /* for */

		csx_Put8(cis_handle, crt->iolimit_p, limit);
	    } /* CONFIG_IOLIMIT_REG_PRESENT */
	} /* REQ_IO_DONE */

	/*
	 * Mark the socket as being in IO mode.
	 */
	if (cr->IntType & SOCKET_INTERFACE_MEMORY_AND_IO)
	    sp->flags |= SOCKET_IS_IO;

	mutex_exit(&sp->lock);

	/*
	 * Enable the interrupt if needed
	 */
	if (cr->Attributes & CONF_ENABLE_IRQ_STEERING)
	    set_socket.IREQRouting |= IRQ_ENABLE;

	/*
	 * Now that we know if the PRR is present and if it is, which
	 *	bits in the PRR are valid, we can construct the correct
	 *	socket event mask.
	 */
	set_socket.SCIntMask = cs_merge_event_masks(sp, client);

	/*
	 * Configuration Option Register - we handle this specially since
	 *	we don't allow the client to manipulate the RESET or
	 *	INTERRUPT bits (although a client can manipulate these
	 *	bits via an AccessConfigurationRegister call - explain
	 *	THAT logic to me).
	 * XXX - we force level-mode interrupts (COR_LEVEL_IRQ)
	 * XXX - we always enable the function on a multi-function card
	 */
	if (client->present & CONFIG_OPTION_REG_PRESENT) {
	    crt->cor = (cr->ConfigIndex & ~COR_SOFT_RESET) | COR_LEVEL_IRQ;
	    if (client->present & CONFIG_IOBASE0_REG_PRESENT)
		crt->cor |= COR_ENABLE_BASE_LIMIT;
	    if (sp->cis_flags & CW_MULTI_FUNCTION_CIS) {
		crt->cor |= COR_ENABLE_FUNCTION;
		crt->cor &= ~COR_ENABLE_IREQ_ROUTING;
		if (cr->Attributes & CONF_ENABLE_IRQ_STEERING)
		    crt->cor |= COR_ENABLE_IREQ_ROUTING;
	    } /* CW_MULTI_FUNCTION_CIS */

#ifdef  CS_DEBUG
	if (cs_debug > 0)
		cmn_err(CE_CONT, "cs_request_configuration "
		    "cor=x%x ConfigIndex=x%x Attributes=x%x flags=x%x\n"
		    "present=x%x cis_handle=%p cor_p=x%x\n",
		    crt->cor, cr->ConfigIndex, cr->Attributes, sp->cis_flags,
		    client->present, cis_handle, crt->cor_p);
#endif

	    csx_Put8(cis_handle, crt->cor_p, crt->cor);
	} /* CONFIG_OPTION_REG_PRESENT */

	if (cs_rc1_delay)
	    drv_usecwait(cs_rc1_delay * 1000);

	/*
	 * Set the socket to the parameters that the client requested.
	 */
	if (SocketServices(SS_SetSocket, &set_socket) != SUCCESS) {
	    if (client->present & CONFIG_OPTION_REG_PRESENT) {
		crt->cor = 0; /* XXX is 0 the right thing here? */
		csx_Put8(cis_handle, crt->cor_p, crt->cor);
	    }
	    sp->flags &= ~SOCKET_IS_IO;
	    mutex_exit(&sp->cis_lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_SOCKET);
	}

	if (cs_rc2_delay)
	    drv_usecwait(cs_rc2_delay * 1000);

	/*
	 * Mark this client as having done a successful RequestConfiguration
	 *	call.
	 */
	client->flags |= REQ_CONFIGURATION_DONE;

	mutex_exit(&sp->cis_lock);
	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	return (CS_SUCCESS);
}

/*
 * cs_release_configuration - releases configuration previously set via the
 *		RequestConfiguration call; this is ReleaseConfiguration
 *
 *	returns: CS_SUCCESS - if configuration sucessfully released
 *		 CS_UNSUPPORTED_FUNCTION - if SS is trying to call us
 *		 CS_BAD_SOCKET - if Socket Services returns an error
 *		 CS_BAD_HANDLE - a RequestConfiguration has not been done
 */
/*ARGSUSED*/
static int
cs_release_configuration(client_handle_t client_handle, release_config_t *rcfg)
{
	cs_socket_t *sp;
	client_t *client;
	volatile config_regs_t *crt;
	set_socket_t set_socket;
	get_socket_t get_socket;
	acc_handle_t cis_handle;
	int error;
	uint32_t newoffset;
	int client_lock_acquired;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't support SS using this call.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_UNSUPPORTED_FUNCTION);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	/*
	 * If RequestConfiguration has not been done, we don't allow
	 *	this call.
	 */
	if (!(client->flags & REQ_CONFIGURATION_DONE)) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_HANDLE);
	}

#ifdef  CS_DEBUG
	if (cs_debug > 0)
		cmn_err(CE_CONT, "cs_release_configuration: "
		    "flags=0x%x CW_MULTI_FUNCTION_CIS =0x%x \n",
		    sp->cis_flags, CW_MULTI_FUNCTION_CIS);

#endif
	mutex_enter(&sp->cis_lock);

	/*
	 * Set the card back to a memory-only interface byte writing a zero
	 *	to the COR.  Note that we don't update our soft copy of the
	 *	COR state since the PCMCIA spec only requires us to maintain
	 *	the last value that was written to that register during a
	 *	call to RequestConfiguration.
	 */
	crt = &client->config_regs;

	newoffset = client->config_regs_offset;
	if (cs_init_cis_window(sp, &newoffset, &cis_handle,
					CISTPLF_AM_SPACE) != CS_SUCCESS) {
	    mutex_exit(&sp->cis_lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    cmn_err(CE_CONT, "cs_release_configuration: socket %d can't init "
				"CIS window\n", sp->socket_num);
	    return (CS_GENERAL_FAILURE);
	}

	if (sp->cis_flags & CW_MULTI_FUNCTION_CIS) {
		/*
		 * For the Multifunction cards do not reset the socket
		 * to a memory only interface but do clear the
		 * Configuration Option Register and  mark this client
		 * as not having a configuration by clearing the
		 * REQ_CONFIGURATION_DONE flag.
		 */
		client->flags &= ~REQ_CONFIGURATION_DONE;
		csx_Put8(cis_handle, crt->cor_p, 0);

		mutex_exit(&sp->cis_lock);
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		return (CS_SUCCESS);
	}

	/*
	 * Set the socket back to a memory-only interface; don't change
	 *	any other parameter of the socket.
	 */
	get_socket.socket = sp->socket_num;

	if (SocketServices(SS_GetSocket, &get_socket) != SUCCESS) {
	    mutex_exit(&sp->cis_lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_SOCKET);
	}

	mutex_enter(&sp->lock);
	sp->flags &= ~SOCKET_IS_IO;
	set_socket.SCIntMask = cs_merge_event_masks(sp, client);
	mutex_exit(&sp->lock);

	set_socket.socket = sp->socket_num;
	set_socket.IREQRouting = 0;
	set_socket.CtlInd = get_socket.CtlInd;
	set_socket.State = 0;	/* don't reset latched values */
	set_socket.VccLevel = get_socket.VccLevel;
	set_socket.Vpp1Level = get_socket.Vpp1Level;
	set_socket.Vpp2Level = get_socket.Vpp2Level;
	set_socket.IFType = IF_MEMORY;

	if (client->present & CONFIG_OPTION_REG_PRESENT)
	    csx_Put8(cis_handle, crt->cor_p, 0);

	if (SocketServices(SS_SetSocket, &set_socket) != SUCCESS) {
	    mutex_exit(&sp->cis_lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_SOCKET);
	}

	/*
	 * Mark this client as not having a configuration.
	 */
	client->flags &= ~REQ_CONFIGURATION_DONE;

	mutex_exit(&sp->cis_lock);
	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	return (CS_SUCCESS);
}

/*
 * cs_modify_configuration - modifies a configuration established by
 *		RequestConfiguration; this is ModifyConfiguration
 *
 *	returns: CS_SUCCESS - if configuration sucessfully modified
 *		 CS_BAD_SOCKET - if Socket Services returns an error
 *		 CS_UNSUPPORTED_FUNCTION - if SS is trying to call us
 *		 CS_BAD_HANDLE - a RequestConfiguration has not been done
 *		 CS_NO_CARD - if no card in socket
 *		 CS_BAD_ATTRIBUTE - if any unsupported or reserved flags
 *					are set
 *		 CS_BAD_VCC - if Vcc value is not supported by socket
 *		 CS_BAD_VPP1 - if Vpp1 value is not supported by socket
 *		 CS_BAD_VPP2 - if Vpp2 value is not supported by socket
 */
static int
cs_modify_configuration(client_handle_t client_handle, modify_config_t *mc)
{
	cs_socket_t *sp;
	client_t *client;
	set_socket_t set_socket;
	get_socket_t get_socket;
	int error;
	int client_lock_acquired;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't support SS using this call.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_UNSUPPORTED_FUNCTION);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	/*
	 * If RequestConfiguration has not been done, we don't allow
	 *	this call.
	 */
	if (!(client->flags & REQ_CONFIGURATION_DONE)) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_HANDLE);
	}

	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED)) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_NO_CARD);
	}

	/*
	 * Get the current socket parameters so that we can modify them.
	 */
	get_socket.socket = sp->socket_num;

	if (SocketServices(SS_GetSocket, &get_socket) != SUCCESS) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_SOCKET);
	}

#ifdef	CS_DEBUG
	if (cs_debug > 0)
	    cmn_err(CE_CONT, "cs_modify_configuration: socket %d "
				"client->irq_alloc.irq 0x%x "
				"get_socket.IRQRouting 0x%x\n",
				sp->socket_num, (int)client->irq_alloc.irq,
				get_socket.IRQRouting);
#endif

	set_socket.socket = sp->socket_num;
	set_socket.SCIntMask = get_socket.SCIntMask;
	set_socket.CtlInd = get_socket.CtlInd;
	set_socket.State = 0;	/* don't reset latched values */
	set_socket.IFType = get_socket.IFType;

	set_socket.IREQRouting = get_socket.IRQRouting;

	/*
	 * Modify the IRQ routing if the client wants it modified.
	 */
	if (mc->Attributes & CONF_IRQ_CHANGE_VALID) {
	    set_socket.IREQRouting &= ~IRQ_ENABLE;

	    if ((sp->cis_flags & CW_MULTI_FUNCTION_CIS) &&
			(client->present & CONFIG_OPTION_REG_PRESENT)) {
		config_regs_t *crt = &client->config_regs;
		acc_handle_t cis_handle;
		uint32_t newoffset = client->config_regs_offset;

		/*
		 * Get a pointer to a window that contains the configuration
		 *	registers.
		 */
		if (cs_init_cis_window(sp, &newoffset, &cis_handle,
					CISTPLF_AM_SPACE) != CS_SUCCESS) {
		    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		    cmn_err(CE_CONT,
			"cs_modify_configuration: socket %d can't init "
			"CIS window\n", sp->socket_num);
		    return (CS_GENERAL_FAILURE);
		} /* cs_init_cis_window */

		crt->cor &= ~COR_ENABLE_IREQ_ROUTING;

		if (mc->Attributes & CONF_ENABLE_IRQ_STEERING)
		    crt->cor |= COR_ENABLE_IREQ_ROUTING;

#ifdef  CS_DEBUG
		if (cs_debug > 0)
			cmn_err(CE_CONT, "cs_modify_configuration:"
			    " cor_p=0x%x cor=0x%x\n",
			    crt->cor_p, crt->cor);
#endif
		csx_Put8(cis_handle, crt->cor_p, crt->cor);

	    } /* CW_MULTI_FUNCTION_CIS */

	    if (mc->Attributes & CONF_ENABLE_IRQ_STEERING)
		set_socket.IREQRouting |= IRQ_ENABLE;

	} /* CONF_IRQ_CHANGE_VALID */

	/*
	 * Modify the voltage levels that the client specifies.
	 */
	set_socket.VccLevel = get_socket.VccLevel;

	if (mc->Attributes & CONF_VPP1_CHANGE_VALID) {
	    if (cs_convert_powerlevel(sp->socket_num, mc->Vpp1, VPP1,
					&set_socket.Vpp1Level) != CS_SUCCESS) {
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		return (CS_BAD_VPP);
	    }
	} else {
	    set_socket.Vpp1Level = get_socket.Vpp1Level;
	}

	if (mc->Attributes & CONF_VPP2_CHANGE_VALID) {
	    if (cs_convert_powerlevel(sp->socket_num, mc->Vpp2, VPP2,
					&set_socket.Vpp2Level) != CS_SUCCESS) {
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		return (CS_BAD_VPP);
	    }
	} else {
	    set_socket.Vpp2Level = get_socket.Vpp2Level;
	}

	/*
	 * Setup the modified socket configuration.
	 */
	if (SocketServices(SS_SetSocket, &set_socket) != SUCCESS) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_BAD_SOCKET);
	}

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	return (CS_SUCCESS);
}

/*
 * cs_access_configuration_register - provides a client access to the card's
 *		configuration registers; this is AccessConfigurationRegister
 *
 *	returns: CS_SUCCESS - if register accessed successfully
 *		 CS_UNSUPPORTED_FUNCTION - if SS is trying to call us
 *		 CS_BAD_ARGS - if arguments are out of range
 *		 CS_NO_CARD - if no card in socket
 *		 CS_BAD_BASE - if no config registers base address
 *		 CS_UNSUPPORTED_MODE - if no RequestConfiguration has
 *				been done yet
 */
static int
cs_access_configuration_register(client_handle_t client_handle,
						access_config_reg_t *acr)
{
	cs_socket_t *sp;
	client_t *client;
	acc_handle_t cis_handle;
	int error;
	uint32_t newoffset;
	int client_lock_acquired;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't support SS using this call.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_UNSUPPORTED_FUNCTION);

	/*
	 * Make sure that the specifed offset is in range.
	 */
	if (acr->Offset > ((CISTPL_CONFIG_MAX_CONFIG_REGS * 2) - 2))
	    return (CS_BAD_ARGS);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED)) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_NO_CARD);
	}

	/*
	 * If RequestConfiguration has not been done, we don't allow
	 *	this call.
	 */
	if (!(client->flags & REQ_CONFIGURATION_DONE)) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_UNSUPPORTED_MODE);
	}

	mutex_enter(&sp->cis_lock);

	/*
	 * Get a pointer to the CIS window
	 */
	newoffset = client->config_regs_offset + acr->Offset;
	if (cs_init_cis_window(sp, &newoffset, &cis_handle,
					CISTPLF_AM_SPACE) != CS_SUCCESS) {
	    mutex_exit(&sp->cis_lock);
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    cmn_err(CE_CONT, "cs_ACR: socket %d can't init CIS window\n",
							sp->socket_num);
	    return (CS_GENERAL_FAILURE);
	}

	/*
	 * Create the address for the config register that the client
	 *	wants to access.
	 */
	mutex_enter(&sp->lock);

#ifdef	CS_DEBUG
	if (cs_debug > 1) {
	    cmn_err(CE_CONT, "cs_ACR: config_regs_offset 0x%x "
		"Offset 0x%x newoffset 0x%x\n",
		(int)client->config_regs_offset,
		(int)acr->Offset, newoffset);
	}
#endif

	/*
	 * Determine what the client wants us to do.  The client is
	 *	allowed to specify any valid offset, even if it would
	 *	cause an unimplemented configuration register to be
	 *	accessed.
	 */
	error = CS_SUCCESS;
	switch (acr->Action) {
	    case CONFIG_REG_READ:
		acr->Value = csx_Get8(cis_handle, newoffset);
		break;
	    case CONFIG_REG_WRITE:
		csx_Put8(cis_handle, newoffset, acr->Value);
		break;
	    default:
		error = CS_BAD_ARGS;
		break;
	} /* switch */

	mutex_exit(&sp->lock);
	mutex_exit(&sp->cis_lock);
	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	return (error);
}

/*
 * ==== RESET and general info functions ====
 */

/*
 * cs_reset_function - RESET the requested function on the card; this
 *			is ResetFunction
 *
 *    Note: We don't support this functionality yet, and the standard
 *		says it's OK to reutrn CS_IN_USE if we can't do this
 *		operation.
 */
/*ARGSUSED*/
static int
cs_reset_function(client_handle_t ch, reset_function_t *rf)
{
	return (CS_IN_USE);
}

/*
 * cs_get_configuration_info - return configuration info for the passed
 *				socket and function number to the caller;
 *				this is GetConfigurationInfo
 */
/*ARGSUSED*/
static int
cs_get_configuration_info(client_handle_t *chp, get_configuration_info_t *gci)
{
	cs_socket_t *sp;
	uint32_t fn;
	client_t *client;
	int client_lock_acquired;

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(CS_GET_SOCKET_NUMBER(gci->Socket))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);
	mutex_enter(&sp->lock);

	fn = CS_GET_FUNCTION_NUMBER(gci->Socket);

	client = sp->client_list;
	while (client) {

	    if (GET_CLIENT_FUNCTION(client->client_handle) == fn) {

		/*
		 * If there's no card in the socket or the card in the
		 *	socket is not for this client, then return
		 *	an error.
		 */
		if (!(client->flags & CLIENT_CARD_INSERTED)) {
		    mutex_exit(&sp->lock);
		    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		    return (CS_NO_CARD);
		}

		mutex_exit(&sp->lock);
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		return (CS_SUCCESS);

	    } /* GET_CLIENT_FUNCTION == fn */

	    client = client->next;
	} /* while (client) */

	mutex_exit(&sp->lock);
	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	return (CS_BAD_SOCKET);
}

/*
 * cs_get_cardservices_info - return info about Card Services to the
 *	caller; this is GetCardServicesInfo
 */
/*ARGSUSED*/
static int
cs_get_cardservices_info(client_handle_t ch, get_cardservices_info_t *gcsi)
{
	gcsi->Signature[0] = 'C';
	gcsi->Signature[1] = 'S';
	gcsi->NumSockets = cs_globals.num_sockets;
	gcsi->Revision = CS_INTERNAL_REVISION_LEVEL;
	gcsi->CSLevel = CS_VERSION;
	gcsi->FuncsPerSocket = CIS_MAX_FUNCTIONS;
	(void) strncpy(gcsi->VendorString,
					CS_GET_CARDSERVICES_INFO_VENDOR_STRING,
					CS_GET_CARDSERVICES_INFO_MAX_VS_LEN);

	return (CS_SUCCESS);
}

/*
 * cs_get_physical_adapter_info - returns information about the requested
 *					physical adapter; this is
 *					GetPhysicalAdapterInfo
 *
 *	calling: client_handle_t:
 *			NULL - use map_log_socket_t->LogSocket member
 *				to specify logical socket number
 *			!NULL - extract logical socket number from
 *				client_handle_t
 *
 *	returns: CS_SUCCESS
 *		 CS_BAD_SOCKET - if client_handle_t is NULL and invalid
 *					socket number is specified in
 *					map_log_socket_t->LogSocket
 *		 CS_BAD_HANDLE - if client_handle_t is !NULL and invalid
 *					client handle is specified
 */
static int
cs_get_physical_adapter_info(client_handle_t ch,
					get_physical_adapter_info_t *gpai)
{
	cs_socket_t *sp;
	int client_lock_acquired;

	if (ch == NULL)
	    gpai->PhySocket = CS_GET_SOCKET_NUMBER(gpai->LogSocket);
	else
	    gpai->PhySocket = GET_CLIENT_SOCKET(ch);

	/*
	 * Determine if the passed socket number is valid or not.
	 */
	if ((sp = cs_get_sp(CS_GET_SOCKET_NUMBER(gpai->PhySocket))) == NULL)
	    return ((ch == NULL) ? CS_BAD_SOCKET : CS_BAD_HANDLE);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 * If we were passed a client handle, determine if it's valid or not.
	 */
	if (ch != NULL) {
	    if (cs_find_client(ch, NULL) == NULL) {
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		return (CS_BAD_HANDLE);
	    } /* cs_find_client */
	} /* ch != NULL */

	gpai->flags = sp->adapter.flags;
	(void) strcpy(gpai->name, sp->adapter.name);
	gpai->major = sp->adapter.major;
	gpai->minor = sp->adapter.minor;
	gpai->instance = sp->adapter.instance;
	gpai->number = sp->adapter.number;
	gpai->num_sockets = sp->adapter.num_sockets;
	gpai->first_socket = sp->adapter.first_socket;

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	return (CS_SUCCESS);
}

/*
 * ==== general functions ====
 */

/*
 * cs_map_log_socket - returns the physical socket number associated with
 *			either the passed client handle or the passed
 *			logical socket number; this is MapLogSocket
 *
 *	calling: client_handle_t:
 *			NULL - use map_log_socket_t->LogSocket member
 *				to specify logical socket number
 *			!NULL - extract logical socket number from
 *				client_handle_t
 *
 *	returns: CS_SUCCESS
 *		 CS_BAD_SOCKET - if client_handle_t is NULL and invalid
 *					socket number is specified in
 *					map_log_socket_t->LogSocket
 *		 CS_BAD_HANDLE - if client_handle_t is !NULL and invalid
 *					client handle is specified
 *
 * Note: We provide this function since the instance number of a client
 *		driver doesn't necessary correspond to the physical
 *		socket number
 */
static int
cs_map_log_socket(client_handle_t ch, map_log_socket_t *mls)
{
	cs_socket_t *sp;
	int client_lock_acquired;

	if (ch == NULL)
	    mls->PhySocket = CS_GET_SOCKET_NUMBER(mls->LogSocket);
	else
	    mls->PhySocket = GET_CLIENT_SOCKET(ch);

	/*
	 * Determine if the passed socket number is valid or not.
	 */
	if ((sp = cs_get_sp(CS_GET_SOCKET_NUMBER(mls->PhySocket))) == NULL)
	    return ((ch == NULL) ? CS_BAD_SOCKET : CS_BAD_HANDLE);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 * If we were passed a client handle, determine if it's valid or not.
	 */
	if (ch != NULL) {
	    if (cs_find_client(ch, NULL) == NULL) {
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		return (CS_BAD_HANDLE);
	    } /* cs_find_client */
	} /* ch != NULL */

	mls->PhyAdapter = sp->adapter.number;

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);

	return (CS_SUCCESS);
}

/*
 * cs_convert_speed - convers nS to devspeed and devspeed to nS
 *
 * The actual function is is in the CIS parser module; this
 *	is only a wrapper.
 */
static int
cs_convert_speed(convert_speed_t *cs)
{
	return ((int)(uintptr_t)CIS_PARSER(CISP_CIS_CONV_DEVSPEED, cs));
}

/*
 * cs_convert_size - converts a devsize value to a size in bytes value
 *			or a size in bytes value to a devsize value
 *
 * The actual function is is in the CIS parser module; this
 *	is only a wrapper.
 */
static int
cs_convert_size(convert_size_t *cs)
{
	return ((int)(uintptr_t)CIS_PARSER(CISP_CIS_CONV_DEVSIZE, cs));
}

/*
 * cs_convert_powerlevel - converts a power level in tenths of a volt
 *			to a power table entry for the specified socket
 *
 *	returns: CS_SUCCESS - if volts converted to a valid power level
 *		 CS_BAD_ADAPTER - if SS_InquireAdapter fails
 *		 CS_BAD_ARGS - if volts are not supported on this socket
 *				and adapter
 */
static int
cs_convert_powerlevel(uint32_t sn, uint32_t volts, uint32_t flags, unsigned *pl)
{
	inquire_adapter_t inquire_adapter;
	int i;

#ifdef	lint
	if (sn == 0)
	    panic("lint panic");
#endif

	*pl = 0;

	if (SocketServices(SS_InquireAdapter, &inquire_adapter) != SUCCESS)
	    return (CS_BAD_ADAPTER);

	for (i = 0; (i < inquire_adapter.NumPower); i++) {
	    if ((inquire_adapter.power_entry[i].ValidSignals & flags) &&
		(inquire_adapter.power_entry[i].PowerLevel == volts)) {
		*pl = i;
		return (CS_SUCCESS);
	    }
	}

	return (CS_BAD_ARGS);
}

/*
 * cs_event2text - returns text string(s) associated with the event; this
 *			function supports the Event2Text CS call.
 *
 *	calling: event2text_t * - pointer to event2text struct
 *		 int event_source - specifies event type in event2text_t:
 *					0 - SS event
 *					1 - CS event
 *
 *	returns: CS_SUCCESS
 */
static int
cs_event2text(event2text_t *e2t, int event_source)
{
	event_t event;
	char *sepchar = "|";

	/*
	 * If event_source is 0, this is a SS event
	 */
	if (!event_source) {
	    for (event = 0; event < MAX_SS_EVENTS; event++) {
		if (cs_ss_event_text[event].ss_event == e2t->event) {
		    (void) strcpy(e2t->text, cs_ss_event_text[event].text);
		    return (CS_SUCCESS);
		}
	    }
	    (void) strcpy(e2t->text, cs_ss_event_text[MAX_CS_EVENTS].text);
	    return (CS_SUCCESS);
	} else {
		/*
		 * This is a CS event
		 */
	    e2t->text[0] = '\0';
	    for (event = 0; event < MAX_CS_EVENTS; event++) {
		if (cs_ss_event_text[event].cs_event & e2t->event) {
		    (void) strcat(e2t->text, cs_ss_event_text[event].text);
		    (void) strcat(e2t->text, sepchar);
		} /* if (cs_ss_event_text) */
	    } /* for (event) */
	    if (e2t->text[0])
		e2t->text[strlen(e2t->text)-1] = NULL;
	} /* if (!event_source) */

	return (CS_SUCCESS);
}

/*
 * cs_error2text - returns a pointer to a text string containing the name
 *			of the passed Card Services function or return code
 *
 *	This function supports the Error2Text CS call.
 */
static char *
cs_error2text(int function, int type)
{
	cs_csfunc2text_strings_t *cfs;
	int end_marker;

	if (type == CSFUN2TEXT_FUNCTION) {
	    cfs = cs_csfunc2text_funcstrings;
	    end_marker = CSFuncListEnd;
	} else {
	    cfs = cs_csfunc2text_returnstrings;
	    end_marker = CS_ERRORLIST_END;
	}

	while (cfs->item != end_marker) {
	    if (cfs->item == function)
		return (cfs->text);
	    cfs++;
	}

	return (cfs->text);
}

/*
 * cs_make_device_node - creates/removes device nodes on a client's behalf;
 *				this is MakeDeviceNode and RemoveDeviceNode
 *
 *	returns: CS_SUCCESS - if all device nodes successfully created/removed
 *		 CS_BAD_ATTRIBUTE - if NumDevNodes is not zero when Action
 *				is REMOVAL_ALL_DEVICES
 *		 CS_BAD_ARGS - if an invalid Action code is specified
 *		 CS_UNSUPPORTED_FUNCTION - if SS is trying to call us
 *		 CS_OUT_OF_RESOURCE - if can't create/remove device node
 */
static int
cs_make_device_node(client_handle_t client_handle, make_device_node_t *mdn)
{
	cs_socket_t *sp;
	client_t *client;
	ss_make_device_node_t ss_make_device_node;
	int error, i;
	int client_lock_acquired;

	/*
	 * Check to see if this is the Socket Services client handle; if it
	 *	is, we don't support SS using this call.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle))
	    return (CS_UNSUPPORTED_FUNCTION);

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	/*
	 *  Make sure that this is a valid client handle.
	 */
	if (!(client = cs_find_client(client_handle, &error))) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (error);
	}

#ifdef	XXX
	/*
	 * If there's no card in the socket or the card in the socket is not
	 *	for this client, then return an error.
	 */
	if (!(client->flags & CLIENT_CARD_INSERTED)) {
	    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	    return (CS_NO_CARD);
	}
#endif

	/*
	 * Setup the client's dip, since we use it later on.
	 */
	ss_make_device_node.dip = client->dip;

	/*
	 * Make sure that we're being given a valid Action.  Set the default
	 *	error code as well.
	 */
	error = CS_BAD_ARGS;	/* for default case */
	switch (mdn->Action) {
	    case CREATE_DEVICE_NODE:
	    case REMOVE_DEVICE_NODE:
		break;
	    case REMOVAL_ALL_DEVICE_NODES:
		if (mdn->NumDevNodes) {
		    error = CS_BAD_ATTRIBUTE;
		} else {
		    ss_make_device_node.flags = SS_CSINITDEV_REMOVE_DEVICE;
		    ss_make_device_node.name = NULL;
		    SocketServices(CSInitDev, &ss_make_device_node);
		    error = CS_SUCCESS;
		}
		/* FALLTHROUGH */
	    default:
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		return (error);
		/* NOTREACHED */
	} /* switch */

	/*
	 * Loop through the device node descriptions and create or destroy
	 *	the device node.
	 */
	for (i = 0; i < mdn->NumDevNodes; i++) {
	    devnode_desc_t *devnode_desc = &mdn->devnode_desc[i];

	    ss_make_device_node.name = devnode_desc->name;
	    ss_make_device_node.spec_type = devnode_desc->spec_type;
	    ss_make_device_node.minor_num = devnode_desc->minor_num;
	    ss_make_device_node.node_type = devnode_desc->node_type;

	/*
	 * Set the appropriate flag for the action that we want
	 *	SS to perform. Note that if we ever OR-in the flag
	 *	here, we need to be sure to clear the flags member
	 *	since we sometimes OR-in other flags below.
	 */
	    if (mdn->Action == CREATE_DEVICE_NODE) {
		ss_make_device_node.flags = SS_CSINITDEV_CREATE_DEVICE;
	    } else {
		ss_make_device_node.flags = SS_CSINITDEV_REMOVE_DEVICE;
	    }

	/*
	 * If this is not the last device to process, then we need
	 *	to tell SS that more device process requests are on
	 *	their way after this one.
	 */
	    if (i < (mdn->NumDevNodes - 1))
		ss_make_device_node.flags |= SS_CSINITDEV_MORE_DEVICES;

	    if (SocketServices(CSInitDev, &ss_make_device_node) != SUCCESS) {
		EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		return (CS_OUT_OF_RESOURCE);
	    } /* CSInitDev */
	} /* for (mdn->NumDevNodes) */

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	return (CS_SUCCESS);
}

/*
 * cs_remove_device_node - removes device nodes
 *
 *	(see cs_make_device_node for a description of the calling
 *		and return parameters)
 */
static int
cs_remove_device_node(client_handle_t client_handle, remove_device_node_t *rdn)
{

	/*
	 * XXX - Note the assumption here that the make_device_node_t and
	 *	remove_device_node_t structures are identical.
	 */
	return (cs_make_device_node(client_handle, (make_device_node_t *)rdn));
}

/*
 * cs_ddi_info - this function is used by clients that need to support
 *			the xxx_getinfo function; this is CS_DDI_Info
 */
static int
cs_ddi_info(cs_ddi_info_t *cdi)
{
	cs_socket_t *sp;
	client_t *client;
	int client_lock_acquired;

	if (cdi->driver_name == NULL)
	    return (CS_BAD_ATTRIBUTE);

#ifdef	CS_DEBUG
	if (cs_debug > 0) {
	    cmn_err(CE_CONT, "cs_ddi_info: socket %d client [%s]\n",
					(int)cdi->Socket, cdi->driver_name);
	}
#endif

	/*
	 * Check to see if the socket number is in range - the system
	 *	framework may cause a client driver to call us with
	 *	a socket number that used to be present but isn't
	 *	anymore. This is not a bug, and it's OK to return
	 *	an error if the socket number is out of range.
	 */
	if (!CHECK_SOCKET_NUM(cdi->Socket, cs_globals.max_socket_num)) {

#ifdef	CS_DEBUG
	    if (cs_debug > 0) {
		cmn_err(CE_CONT, "cs_ddi_info: socket %d client [%s] "
						"SOCKET IS OUT OF RANGE\n",
							(int)cdi->Socket,
							cdi->driver_name);
	    }
#endif

	    return (CS_BAD_SOCKET);
	} /* if (!CHECK_SOCKET_NUM) */

	/*
	 * Get a pointer to this client's socket structure.
	 */
	if ((sp = cs_get_sp(cdi->Socket)) == NULL)
	    return (CS_BAD_SOCKET);

	EVENT_THREAD_MUTEX_ENTER(client_lock_acquired, sp);

	client = sp->client_list;
	while (client) {

#ifdef	CS_DEBUG
	    if (cs_debug > 0) {
		cmn_err(CE_CONT, "cs_ddi_info: socket %d checking client [%s] "
							"handle 0x%x\n",
						(int)cdi->Socket,
						client->driver_name,
						(int)client->client_handle);
	    }
#endif

	    if (client->driver_name != NULL) {
		if (!(strcmp(client->driver_name, cdi->driver_name))) {
		    cdi->dip = client->dip;
		    cdi->instance = client->instance;

#ifdef	CS_DEBUG
		    if (cs_debug > 0) {
			cmn_err(CE_CONT, "cs_ddi_info: found client [%s] "
						"instance %d handle 0x%x\n",
					client->driver_name, client->instance,
					(int)client->client_handle);
		    }
#endif

		    EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
		    return (CS_SUCCESS);
		} /* strcmp */
	    } /* driver_name != NULL */
	    client = client->next;
	} /* while (client) */

	EVENT_THREAD_MUTEX_EXIT(client_lock_acquired, sp);
	return (CS_BAD_SOCKET);
}

/*
 * cs_sys_ctl - Card Services system control; this is CS_Sys_Ctl
 */
static int
cs_sys_ctl(cs_sys_ctl_t *csc)
{
	cs_socket_t *sp;
	client_t *cp;
	int sn, ret = CS_UNSUPPORTED_MODE;

	switch (csc->Action) {
	    case CS_SYS_CTL_SEND_EVENT:
		if (csc->Flags & CS_SYS_CTL_EVENT_SOCKET)
		    sn = CS_GET_SOCKET_NUMBER(csc->Socket);
		else
		    sn = GET_CLIENT_SOCKET(csc->client_handle);
		if ((sp = cs_get_sp(sn)) == NULL)
		    return (CS_BAD_SOCKET);
		mutex_enter(&sp->client_lock);
		mutex_enter(&sp->lock);
		csc->Events &= CS_EVENT_CLIENT_EVENTS_MASK;
		if (csc->Flags & CS_SYS_CTL_EVENT_SOCKET)
		    sp->events |= csc->Events;
		if (csc->Flags & CS_SYS_CTL_EVENT_CLIENT) {
		    if ((cp = cs_find_client(csc->client_handle, &ret)) ==
									NULL) {
			mutex_exit(&sp->lock);
			mutex_exit(&sp->client_lock);
			return (ret);
		    } /* cs_find_client */
			/*
			 * Setup the events that we want to send to the client.
			 */
		    cp->events |= (csc->Events &
					(cp->event_mask | cp->global_mask));
		} /* CS_SYS_CTL_EVENT_CLIENT */

		if (csc->Flags & CS_SYS_CTL_WAIT_SYNC) {
		    sp->thread_state |= SOCKET_WAIT_SYNC;
		    mutex_exit(&sp->lock);
		    cv_broadcast(&sp->thread_cv);
		    cv_wait(&sp->caller_cv, &sp->client_lock);
		} else {
		    mutex_exit(&sp->lock);
		    cv_broadcast(&sp->thread_cv);
		} /* CS_SYS_CTL_WAIT_SYNC */
		mutex_exit(&sp->client_lock);
		ret = CS_SUCCESS;
		break;
	    default:
		break;
	} /* switch */

	return (ret);
}

/*
 * cs_get_sp - returns pointer to per-socket structure for passed
 *		socket number
 *
 *	return:	(cs_socket_t *) - pointer to socket structure
 *		NULL - invalid socket number passed in
 */
static cs_socket_t *
cs_get_sp(uint32_t sn)
{
	cs_socket_t *sp = cs_globals.sp;

	if (!(cs_globals.init_state & GLOBAL_INIT_STATE_SS_READY))
	    return (NULL);

	if ((sp = cs_find_sp(sn)) == NULL)
	    return (NULL);

	if (sp->flags & SOCKET_IS_VALID)
	    return (sp);

	return (NULL);
}

/*
 * cs_find_sp - searches socket list and returns pointer to passed socket
 *			number
 *
 *	return:	(cs_socket_t *) - pointer to socket structure if found
 *		NULL - socket not found
 */
static cs_socket_t *
cs_find_sp(uint32_t sn)
{
	cs_socket_t *sp = cs_globals.sp;

	while (sp) {
	    if (sp->socket_num == CS_GET_SOCKET_NUMBER(sn))
		return (sp);
	    sp = sp->next;
	} /* while */

	return (NULL);
}

/*
 * cs_add_socket - add a socket
 *
 *	call:	sn - socket number to add
 *
 *	return:	CS_SUCCESS - operation sucessful
 *		CS_BAD_SOCKET - unable to add socket
 *		CS_BAD_WINDOW - unable to get CIS window for socket
 *
 * We get called here once for each socket that the framework wants to
 *	add. When we are called, the framework guarentees that until we
 *	complete this routine, no other adapter instances will be allowed
 *	to attach and thus no other PCE_ADD_SOCKET events will occur.
 *	It is safe to call SS_InquireAdapter to get the number of
 *	windows that the framework currently knows about.
 */
static uint32_t
cs_add_socket(uint32_t sn)
{
	cs_socket_t *sp;
	sservice_t sservice;
	get_cookies_and_dip_t *gcad;
	win_req_t win_req;
	convert_speed_t convert_speed;
	set_socket_t set_socket;
	cs_window_t *cw;
	inquire_adapter_t inquire_adapter;
	inquire_window_t inquire_window;
	int ret, added_windows;

	if (!(cs_globals.init_state & GLOBAL_INIT_STATE_SS_READY))
	    return (CS_BAD_SOCKET);

	/*
	 * See if this socket has already been added - if it has, we
	 *	fail this. If we can't find the socket, then allocate
	 *	a new socket structure. If we do find the socket, then
	 *	check to see if it's already added; if it is, then
	 *	this is an error and return CS_BAD_SOCKET; if not,
	 *	then traverse the socket structure list and add this
	 *	next socket strcture to the end of the list.
	 * XXX What about locking this list while we update it? Is
	 *	that necessary since we're using the SOCKET_IS_VALID
	 *	flag and since we never delete a socket from the
	 *	list once it's been added?
	 */
	if ((sp = cs_find_sp(sn)) == NULL) {
	    cs_socket_t *spp = cs_globals.sp;

	    sp = (cs_socket_t *)kmem_zalloc(sizeof (cs_socket_t), KM_SLEEP);

	    if (cs_globals.sp == NULL)
		cs_globals.sp = sp;
	    else
		while (spp) {
		    if (spp->next == NULL) {
			spp->next = sp;
			break;
		    } /* if */
		    spp = spp->next;
		} /* while */

	} else {
	    if (sp->flags & SOCKET_IS_VALID)
		return (CS_BAD_SOCKET);
	} /* cs_find_sp */

	/*
	 * Setup the socket number
	 */
	sp->socket_num = sn;

	/*
	 * Find out how many windows the framework knows about
	 *	so far. If this number of windows is greater
	 *	than our current window count, bump up our
	 *	current window count.
	 * XXX Note that there is a BIG assumption here and that
	 *	is that once the framework tells us that it has
	 *	a window (as reflected in the NumWindows
	 *	value) it can NEVER remove that window.
	 *	When we really get the drop socket and drop
	 *	window mechanism working correctly, we'll have
	 *	to revisit this.
	 */
	SocketServices(SS_InquireAdapter, &inquire_adapter);

	mutex_enter(&cs_globals.window_lock);
	added_windows = inquire_adapter.NumWindows - cs_globals.num_windows;
	if (added_windows > 0) {
	    if (cs_add_windows(added_windows,
				cs_globals.num_windows) != CS_SUCCESS) {
		mutex_exit(&cs_globals.window_lock);
		return (CS_BAD_WINDOW);
	    } /* cs_add_windows */

	    cs_globals.num_windows = inquire_adapter.NumWindows;

	} /* if (added_windows) */

	/*
	 * Find a window that we can use for this socket's CIS window.
	 */
	sp->cis_win_num = PCMCIA_MAX_WINDOWS;

	convert_speed.Attributes = CONVERT_NS_TO_DEVSPEED;
	convert_speed.nS = CIS_DEFAULT_SPEED;
	(void) cs_convert_speed(&convert_speed);

	win_req.win_params.AccessSpeed = convert_speed.devspeed;
	win_req.Attributes = (WIN_MEMORY_TYPE_AM | WIN_DATA_WIDTH_8);
	win_req.Attributes = (WIN_MEMORY_TYPE_AM | WIN_MEMORY_TYPE_CM);
	win_req.Base.base = 0;
	win_req.Size = 0;

	if ((ret = cs_find_mem_window(sp->socket_num, &win_req,
					&sp->cis_win_num)) != CS_SUCCESS) {
	    mutex_exit(&cs_globals.window_lock);
	    sp->cis_win_num = PCMCIA_MAX_WINDOWS;
	    cmn_err(CE_CONT, "cs_add_socket: socket %d can't get CIS "
						"window - error 0x%x\n",
						sp->socket_num, ret);
	    return (CS_BAD_WINDOW);
	} /* cs_find_mem_window */

	if ((cw = cs_get_wp(sp->cis_win_num)) == NULL) {
	    mutex_exit(&cs_globals.window_lock);
	    return (CS_BAD_WINDOW);
	}

	inquire_window.window = sp->cis_win_num;
	SocketServices(SS_InquireWindow, &inquire_window);

	/*
	 * If the CIS window is a variable sized window, then use
	 *	the size that cs_find_mem_window returned to us,
	 *	since this will be the minimum size that we can
	 *	set this window to. If the CIS window is a fixed
	 *	sized window, then use the system pagesize as the
	 *	CIS window size.
	 */
	if (inquire_window.mem_win_char.MemWndCaps & WC_SIZE) {
	    sp->cis_win_size = win_req.Size;
	} else {
	    sp->cis_win_size = PAGESIZE;
	}

	cw->state |= (CW_CIS | CW_ALLOCATED);
	cw->socket_num = sp->socket_num;

	mutex_exit(&cs_globals.window_lock);

#if defined(CS_DEBUG)
	    if (cs_debug > 1) {
		cmn_err(CE_CONT, "cs_add_socket: socket %d using CIS window %d "
					"size 0x%x\n", (int)sp->socket_num,
					(int)sp->cis_win_num,
					(int)sp->cis_win_size);
	    }
#endif

	/*
	 * Get the adapter information associated with this socket so
	 *	that we can initialize the mutexes, condition variables,
	 *	soft interrupt handler and per-socket adapter info.
	 */
	gcad = &sservice.get_cookies;
	gcad->socket = sp->socket_num;
	if (SocketServices(CSGetCookiesAndDip, &sservice) != SUCCESS) {
	    cmn_err(CE_CONT, "cs_add_socket: socket %d CSGetCookiesAndDip "
						"failure\n", sp->socket_num);
	    return (CS_BAD_SOCKET);
	} /* CSGetCookiesAndDip */

	/*
	 * Save the iblock and idev cookies for RegisterClient
	 */
	sp->iblk = gcad->iblock;
	sp->idev = gcad->idevice;

	/*
	 * Setup the per-socket adapter info
	 */
	sp->adapter.flags = 0;
	(void) strcpy(sp->adapter.name, gcad->adapter_info.name);
	sp->adapter.major = gcad->adapter_info.major;
	sp->adapter.minor = gcad->adapter_info.minor;
	sp->adapter.instance = ddi_get_instance(gcad->dip);
	sp->adapter.number = gcad->adapter_info.number;
	sp->adapter.num_sockets = gcad->adapter_info.num_sockets;
	sp->adapter.first_socket = gcad->adapter_info.first_socket;

	/* Setup for cs_event and cs_event_thread */
	mutex_init(&sp->lock, NULL, MUTEX_DRIVER, *(gcad->iblock));
	mutex_init(&sp->client_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sp->cis_lock, NULL, MUTEX_DRIVER, NULL);

	/* Setup for Socket Services work thread */
	mutex_init(&sp->ss_thread_lock, NULL, MUTEX_DRIVER, NULL);

	sp->init_state |= SOCKET_INIT_STATE_MUTEX;

	/* Setup for cs_event_thread */
	cv_init(&sp->thread_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sp->caller_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sp->reset_cv, NULL, CV_DRIVER, NULL);

	/* Setup for Socket Services work thread */
	cv_init(&sp->ss_thread_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sp->ss_caller_cv, NULL, CV_DRIVER, NULL);

	sp->init_state |= SOCKET_INIT_STATE_CV;

	/*
	 * If we haven't installed it yet, then install the soft interrupt
	 *	handler and save away the softint id.
	 */
	if (!(cs_globals.init_state & GLOBAL_INIT_STATE_SOFTINTR)) {
	    if (ddi_add_softintr(gcad->dip, DDI_SOFTINT_HIGH,
						&sp->softint_id,
						NULL, NULL,
						cs_socket_event_softintr,
						(caddr_t)NULL) != DDI_SUCCESS) {
		    cmn_err(CE_CONT, "cs_add_socket: socket %d can't add "
						"softintr\n", sp->socket_num);
		    return (CS_BAD_SOCKET);
	    } /* ddi_add_softintr */

	    mutex_enter(&cs_globals.global_lock);
	    cs_globals.softint_id = sp->softint_id;
	    cs_globals.init_state |= GLOBAL_INIT_STATE_SOFTINTR;
	    /* XXX this timer is hokey at best... */
	    cs_globals.sotfint_tmo = timeout(cs_event_softintr_timeout,
		NULL, SOFTINT_TIMEOUT_TIME);
	    mutex_exit(&cs_globals.global_lock);
	} else {
		/*
		 * We've already added the soft interrupt handler, so just
		 *	store away the softint id.
		 */
	    sp->softint_id = cs_globals.softint_id;
	} /* if (!GLOBAL_INIT_STATE_SOFTINTR) */

	/*
	 * While this next flag doesn't really describe a per-socket
	 *	resource, we still set it for each socket.  When the soft
	 *	interrupt handler finally gets removed in cs_deinit, this
	 *	flag will get cleared.
	 */
	sp->init_state |= SOCKET_INIT_STATE_SOFTINTR;

	/*
	 * Socket Services defaults all sockets to power off and
	 *	clears all event masks.  We want to receive at least
	 *	card insertion events, so enable them.  Turn off power
	 *	to the socket as well.  We will turn it on again when
	 *	we get a card insertion event.
	 */
	sp->event_mask = CS_EVENT_CARD_INSERTION;
	set_socket.socket = sp->socket_num;
	set_socket.SCIntMask = SBM_CD;
	set_socket.IREQRouting = 0;
	set_socket.IFType = IF_MEMORY;
	set_socket.CtlInd = 0; /* turn off controls and indicators */
	set_socket.State = (unsigned)~0;	/* clear latched state bits */

	(void) cs_convert_powerlevel(sp->socket_num, 0, VCC,
						&set_socket.VccLevel);
	(void) cs_convert_powerlevel(sp->socket_num, 0, VPP1,
						&set_socket.Vpp1Level);
	(void) cs_convert_powerlevel(sp->socket_num, 0, VPP2,
						&set_socket.Vpp2Level);

	if ((ret = SocketServices(SS_SetSocket, &set_socket)) != SUCCESS) {
	    cmn_err(CE_CONT, "cs_add_socket: socket %d SS_SetSocket "
					"failure %d\n", sp->socket_num, ret);
		return (CS_BAD_SOCKET);
	} /* SS_SetSocket */

	/*
	 * The various socket-specific variables are now set up, so
	 *	increment the global socket count and also mark the
	 *	socket as available. We need to set this before we
	 *	start any of the per-socket threads so that the threads
	 *	can get a valid socket pointer when they start.
	 */
	mutex_enter(&cs_globals.global_lock);
	cs_globals.num_sockets++;
	cs_globals.max_socket_num =
			max(cs_globals.max_socket_num, sp->socket_num + 1);
	mutex_exit(&cs_globals.global_lock);
	sp->flags = SOCKET_IS_VALID;

	/*
	 * Create the per-socket event handler thread.
	 */
	sp->event_thread = CREATE_SOCKET_EVENT_THREAD(cs_event_thread,
		(uintptr_t)sn);

	mutex_enter(&sp->lock);
	sp->init_state |= SOCKET_INIT_STATE_THREAD;
	mutex_exit(&sp->lock);

	/*
	 * Create the per-socket Socket Services work thread.
	 */
	sp->ss_thread = CREATE_SOCKET_EVENT_THREAD(cs_ss_thread,
		(uintptr_t)sn);

	mutex_enter(&sp->lock);
	sp->init_state |= (SOCKET_INIT_STATE_SS_THREAD |
						SOCKET_INIT_STATE_READY);
	sp->event_mask = CS_EVENT_CARD_INSERTION;
	mutex_exit(&sp->lock);

	return (CS_SUCCESS);
}

/*
 * cs_drop_socket - drop a socket
 *
 *	call:	sn - socket number to drop
 *
 *	return:	CS_SUCCESS - operation sucessful
 *		CS_BAD_SOCKET - unable to drop socket
 */
/*ARGSUSED*/
static uint32_t
cs_drop_socket(uint32_t sn)
{
#ifdef	XXX
	cs_socket_t *sp;

	/*
	 * Tell the socket event thread to exit and then wait for it
	 *	to do so.
	 */
	mutex_enter(&sp->client_lock);
	sp->thread_state |= SOCKET_THREAD_EXIT;
	cv_broadcast(&sp->thread_cv);
	cv_wait(&sp->caller_cv, &sp->client_lock);
	mutex_exit(&sp->client_lock);

	/*
	 * Tell the socket SS thread to exit and then wait for it
	 *	to do so.
	 */

	/*
	 * Mark the socket as dropped.
	 */
	sp->flags &= ~SOCKET_IS_VALID;

#endif	/* XXX */

	/* XXX for now don't allow dropping sockets XXX */
	return (CS_BAD_SOCKET);
}

/*
 * cs_get_socket - returns the socket and function numbers and a pointer
 *			to the socket structure
 *
 * calling:	client_handle_t client_handle - client handle to extract
 *						socket number from
 *		uint32_t *socket -  pointer to socket number to use if
 *					client_handle is for the SS client;
 *					this value will be filled in on
 *					return with the correct socket
 *					and function numbers if we
 *					return CS_SUCCESS
 *		uint32_t *function - pointer to return function number into
 *					if not NULL
 *		cs_socket_t **sp - pointer to a pointer where a pointer
 *					to the socket struct will be
 *					placed if this is non-NULL
 *		client_t **clp - pointer to a pointer where a pointer
 *					to the client struct will be
 *					placed if this is non-NULL
 *
 *    The socket and function numbers are derived as follows:
 *
 *	Client Type		Socket Number		Function Number
 *	PC card client		From client_handle	From client_handle
 *	Socket Services client	From *socket		From *socket
 *	CSI client		From client_handle	From *socket
 */
static uint32_t
cs_get_socket(client_handle_t client_handle, uint32_t *socket,
    uint32_t *function, cs_socket_t **csp, client_t **clp)
{
	cs_socket_t *sp;
	client_t *client;
	uint32_t sn, fn;
	int ret;

	sn = *socket;

	/*
	 * If this is the Socket Services client, then return the
	 *	socket and function numbers specified in the passed
	 *	socket number parameter, otherwise extract the socket
	 *	and function numbers from the client handle.
	 */
	if (CLIENT_HANDLE_IS_SS(client_handle)) {
	    fn = CS_GET_FUNCTION_NUMBER(sn);
	    sn = CS_GET_SOCKET_NUMBER(sn);
	} else {
	    fn = GET_CLIENT_FUNCTION(client_handle);
	    sn = GET_CLIENT_SOCKET(client_handle);
	}

	/*
	 * Check to be sure that the socket number is in range
	 */
	if (!(CHECK_SOCKET_NUM(sn, cs_globals.max_socket_num)))
	    return (CS_BAD_SOCKET);

	if ((sp = cs_get_sp(sn)) == NULL)
	    return (CS_BAD_SOCKET);

	/*
	 * If we were given a pointer, then fill it in with a pointer
	 *	to this socket.
	 */
	if (csp)
	    *csp = sp;

	/*
	 * Search for the client; if it's not found, return an error.
	 */
	mutex_enter(&sp->lock);
	if (!(client = cs_find_client(client_handle, &ret))) {
	    mutex_exit(&sp->lock);
	    return (ret);
	}

	/*
	 * If we're a CIS client, then extract the function number
	 *	from the socket number.
	 */
	if (client->flags & CLIENT_CSI_CLIENT)
	    fn = CS_GET_FUNCTION_NUMBER(*socket);

	mutex_exit(&sp->lock);

	/*
	 * Return the found client pointer if the caller wants it.
	 */
	if (clp)
	    *clp = client;

	/*
	 * Return a socket number that is made up of the socket number
	 *	and the function number.
	 */
	*socket = CS_MAKE_SOCKET_NUMBER(sn, fn);

	/*
	 * Return the function number if the caller wants it.
	 */
	if (function)
	    *function = fn;

	return (CS_SUCCESS);
}

/*
 * cs_get_wp - returns pointer to passed window number
 *
 *	return: (cs_window_t *) - pointer to window structure
 *		NULL - if invalid window number passed in
 */
static cs_window_t *
cs_get_wp(uint32_t wn)
{
	cs_window_t *cw;

	if (!(cs_globals.init_state & GLOBAL_INIT_STATE_SS_READY))
	    return (NULL);

	if ((cw = cs_find_wp(wn)) == NULL)
	    return (NULL);

	if (cw->state & CW_WINDOW_VALID)
	    return (cw);

#ifdef  CS_DEBUG
	if (cs_debug > 0) {
		cmn_err(CE_CONT, "cs_get_wp(): wn=%d  cw=%p\n",
		    (int)wn, (void *)cw);
	}
#endif

	return (NULL);
}

/*
 * cs_find_wp - searches window list and returns pointer to passed window
 *			number
 *
 *	return: (cs_window_t *) - pointer to window structure
 *		NULL - window not found
 */
static cs_window_t *
cs_find_wp(uint32_t wn)
{
	cs_window_t *cw = cs_globals.cw;

	while (cw) {
	    if (cw->window_num == wn)
		return (cw);
	    cw = cw->next;
	} /* while */

#ifdef  CS_DEBUG
	if (cs_debug > 0) {
		cmn_err(CE_CONT, "cs_find_wp(): wn=%d  window_num=%d cw=%p\n",
		    (int)wn, (int)cw->window_num, (void *)cw);
	}
#endif

	return (NULL);
}

/*
 * cs_add_windows - adds number of windows specified in "aw" to
 *			the global window list; start the window
 *			numbering at "bn"
 *
 *	return: CS_SUCCESS - if windows added sucessfully
 *		CS_BAD_WINDOW - if unable to add windows
 *
 * Note: The window list must be protected by a lock by the caller.
 */
static int
cs_add_windows(int aw, uint32_t bn)
{
	cs_window_t *cwp = cs_globals.cw;
	cs_window_t *cw, *cwpp;

	if (aw <= 0)
	    return (CS_BAD_WINDOW);

	while (cwp) {
	    cwpp = cwp;
	    cwp = cwp->next;
	}

	while (aw--) {
	    cw = (cs_window_t *)kmem_zalloc(sizeof (cs_window_t), KM_SLEEP);

	    if (cs_globals.cw == NULL) {
		cs_globals.cw = cw;
		cwpp = cs_globals.cw;
	    } else {
		cwpp->next = cw;
		cwpp = cwpp->next;
	    }

	    cwpp->window_num = bn++;
	    cwpp->state = CW_WINDOW_VALID;

	} /* while (aw) */

	return (CS_SUCCESS);
}

/*
 * cs_ss_init - initialize CS items that need to wait until we receive
 *			a PCE_SS_INIT_STATE/PCE_SS_STATE_INIT event
 *
 *	return: CS_SUCESS - if sucessfully initialized
 *		(various) if error initializing
 *
 *	At this point, we expect that Socket Services has setup the
 *	following global variables for us:
 *
 *		cs_socket_services - Socket Services entry point
 *		cis_parser - CIS parser entry point
 */
static uint32_t
cs_ss_init()
{
	cs_register_cardservices_t rcs;
	csregister_t csr;
	uint32_t ret;

	/*
	 * Fill out the parameters for CISP_CIS_SETUP
	 */
	csr.cs_magic = PCCS_MAGIC;
	csr.cs_version = PCCS_VERSION;
	csr.cs_card_services = CardServices;
	csr.cs_event = NULL;

	/*
	 * Call into the CIS module and tell it what the private
	 *	Card Services entry point is. The CIS module will
	 *	call us back at CardServices(CISRegister, ...)
	 *	with the address of various CIS-specific global
	 *	data structures.
	 */
	CIS_PARSER(CISP_CIS_SETUP, &csr);

	/*
	 * Register with the Card Services kernel stubs module
	 */
	rcs.magic = CS_STUBS_MAGIC;
	rcs.function = CS_ENTRY_REGISTER;
	rcs.cardservices = CardServices;

	if ((ret = csx_register_cardservices(&rcs)) != CS_SUCCESS) {
	    cmn_err(CE_CONT, "cs_ss_init: can't register with "
					"cs_stubs, retcode = 0x%x\n", ret);
		return (ret);
	} /* csx_register_cardservices */

	return (CS_SUCCESS);
}

/*
 * cs_create_cis - reads CIS on card in socket and creates CIS lists
 *
 * Most of the work is done in the CIS module in the CISP_CIS_LIST_CREATE
 *	function.
 *
 * This function returns:
 *
 *	CS_SUCCESS - if the CIS lists were created sucessfully
 *	CS_BAD_WINDOW or CS_GENERAL_FAILURE - if CIS window could
 *			not be setup
 *	CS_BAD_CIS - if error creating CIS chains
 *	CS_BAD_OFFSET - if the CIS parser tried to read past the
 *			boundries of the allocated CIS window
 */
static int
cs_create_cis(cs_socket_t *sp)
{
	uint32_t ret;

	ret = (uint32_t)(uintptr_t)CIS_PARSER(CISP_CIS_LIST_CREATE,
	    cis_cistpl_std_callout, sp);

#ifdef	CS_DEBUG
	if (ret == CS_NO_CIS) {
	    if (cs_debug > 0)
		cmn_err(CE_CONT, "cs_create_cis: socket %d has no CIS\n",
								sp->socket_num);
	} else if (ret != CS_SUCCESS) {
	    if (cs_debug > 0)
		cmn_err(CE_CONT, "cs_create_cis: socket %d ERROR = 0x%x\n",
							sp->socket_num, ret);
	    return (ret);
	}
#else
	if (ret != CS_NO_CIS)
	    if (ret != CS_SUCCESS)
		return (ret);
#endif

	/*
	 * If this card didn't have any CIS at all, there's not much
	 *	else for us to do.
	 */
	if (!(sp->cis_flags & CW_VALID_CIS))
	    return (CS_SUCCESS);

	/*
	 * If this is a single-function card, we need to move the CIS list
	 *	that is currently on CS_GLOBAL_CIS to the function zero
	 *	CIS list.
	 */
	if (!(sp->cis_flags & CW_MULTI_FUNCTION_CIS)) {
	    bcopy((caddr_t)&sp->cis[CS_GLOBAL_CIS],
				(caddr_t)&sp->cis[0], sizeof (cis_info_t));
	    bzero((caddr_t)&sp->cis[CS_GLOBAL_CIS], sizeof (cis_info_t));
	} /* !CW_MULTI_FUNCTION_CIS */

	return (CS_SUCCESS);
}

/*
 * cs_destroy_cis - destroys CIS list for socket
 */
static int
cs_destroy_cis(cs_socket_t *sp)
{
	CIS_PARSER(CISP_CIS_LIST_DESTROY, sp);

	return (CS_SUCCESS);
}

/*
 * cs_get_client_info - This function is GetClientInfo.
 *
 *    calling:	client_handle_t - client handle to get client info on
 *		client_info_t * - pointer to a client_info_t structure
 *					to return client information in
 *
 *    returns:	CS_SUCCESS - if client info retreived from client
 *		CS_BAD_SOCKET, CS_BAD_HANDLE - if invalid client
 *					handle passed in
 *		CS_NO_MORE_ITEMS - if client does not handle the
 *					CS_EVENT_CLIENT_INFO event
 *					or if invalid client info
 *					retreived from client
 */
static int
cs_get_client_info(client_handle_t client_handle, client_info_t *ci)
{
	cs_socket_t *sp;
	client_t *client;
	client_info_t *cinfo;
	int ret = CS_SUCCESS;

	if (CLIENT_HANDLE_IS_SS(client_handle)) {
	    ci->Attributes = (CS_CLIENT_INFO_SOCKET_SERVICES |
						CS_CLIENT_INFO_VALID);
	    return (CS_SUCCESS);
	} /* CLIENT_HANDLE_IS_SS */

	if ((sp = cs_get_sp(GET_CLIENT_SOCKET(client_handle))) == NULL)
	    return (CS_BAD_SOCKET);

	mutex_enter(&sp->client_lock);
	mutex_enter(&sp->lock);

	if ((client = cs_find_client(client_handle, &ret)) == NULL) {
	    mutex_exit(&sp->lock);
	    mutex_exit(&sp->client_lock);
	    return (ret);
	} /* cs_find_client */

	/*
	 * If this client is not handling CS_EVENT_CLIENT_INFO events,
	 *	then don't bother to even wake up the event thread.
	 */
	if (!((client->event_mask | client->global_mask) &
					CS_EVENT_CLIENT_INFO)) {
	    mutex_exit(&sp->lock);
	    mutex_exit(&sp->client_lock);
	    return (CS_NO_MORE_ITEMS);
	} /* !CS_EVENT_CLIENT_INFO */

	cinfo = &client->event_callback_args.client_info;

	bzero((caddr_t)cinfo, sizeof (client_info_t));
	cinfo->Attributes = (ci->Attributes & CS_CLIENT_INFO_SUBSVC_MASK);

	client->events |= CS_EVENT_CLIENT_INFO;

	sp->thread_state |= SOCKET_WAIT_SYNC;
	mutex_exit(&sp->lock);
	cv_broadcast(&sp->thread_cv);
	cv_wait(&sp->caller_cv, &sp->client_lock);

	if (cinfo->Attributes & CS_CLIENT_INFO_VALID) {
	    bcopy((caddr_t)cinfo, (caddr_t)ci, sizeof (client_info_t));
	    ci->Attributes &= (CS_CLIENT_INFO_FLAGS_MASK |
					CS_CLIENT_INFO_SUBSVC_MASK);
	    ci->Attributes &= ~(CS_CLIENT_INFO_CLIENT_MASK |
						INFO_CARD_FLAGS_MASK |
						CS_CLIENT_INFO_CLIENT_ACTIVE);
	    ci->Attributes |= (client->flags & (CS_CLIENT_INFO_CLIENT_MASK |
						INFO_CARD_FLAGS_MASK));
	    (void) strcpy(ci->DriverName, client->driver_name);
	    if (cs_card_for_client(client))
		ci->Attributes |= CS_CLIENT_INFO_CLIENT_ACTIVE;
	} else {
	    ret = CS_NO_MORE_ITEMS;
	} /* CS_CLIENT_INFO_VALID */

	mutex_exit(&sp->client_lock);

	return (ret);
}

/*
 * cs_get_firstnext_client - This function is GetFirstClient and
 *				GetNextClient
 *
 *    calling:	get_firstnext_client_t * - pointer to a get_firstnext_client_t
 *					structure to return client handle and
 *					attributes in
 *		flags - one of the following:
 *				CS_GET_FIRST_FLAG - get first client handle
 *				CS_GET_NEXT_FLAG - get next client handle
 *
 *    returns:	CS_SUCCESS - if client info retreived from client
 *		CS_BAD_SOCKET, CS_BAD_HANDLE - if invalid client
 *					handle passed in
 *		CS_NO_MORE_ITEMS - if client does not handle the
 *					CS_EVENT_CLIENT_INFO event
 *					or if invalid client info
 *					retreived from client
 */
static int
cs_get_firstnext_client(get_firstnext_client_t *fnc, uint32_t flags)
{
	cs_socket_t *sp;
	client_t *client;
	uint32_t sn = 0;
	int ret = CS_SUCCESS;

	switch (flags) {
	    case CS_GET_FIRST_FLAG:
		if (fnc->Attributes & CS_GET_FIRSTNEXT_CLIENT_ALL_CLIENTS) {
		    while (sn < cs_globals.max_socket_num) {
			if ((sp = cs_get_sp(sn)) != NULL) {
			    mutex_enter(&sp->client_lock);
			    if ((client = sp->client_list) != NULL)
				break;
			    mutex_exit(&sp->client_lock);
			} /* if */
			sn++;
		    } /* while */

		    if (sn == cs_globals.max_socket_num)
			return (CS_NO_MORE_ITEMS);
		} else if (fnc->Attributes &
					CS_GET_FIRSTNEXT_CLIENT_SOCKET_ONLY) {
		    if ((sp = cs_get_sp(CS_GET_SOCKET_NUMBER(fnc->Socket))) ==
									NULL)
			return (CS_BAD_SOCKET);
		    mutex_enter(&sp->client_lock);
		    if ((client = sp->client_list) == NULL) {
			mutex_exit(&sp->client_lock);
			return (CS_NO_MORE_ITEMS);
		    }
		} else {
		    return (CS_BAD_ATTRIBUTE);
		}

		fnc->client_handle = client->client_handle;
		fnc->num_clients = sp->num_clients;
		mutex_exit(&sp->client_lock);
		break;
	    case CS_GET_NEXT_FLAG:
		if (fnc->Attributes & CS_GET_FIRSTNEXT_CLIENT_ALL_CLIENTS) {
		    sn = GET_CLIENT_SOCKET(fnc->client_handle);

		    if ((sp = cs_get_sp(sn)) == NULL)
			return (CS_BAD_SOCKET);

		    mutex_enter(&sp->client_lock);
		    if ((client = cs_find_client(fnc->client_handle,
				&ret)) == NULL) {
			mutex_exit(&sp->client_lock);
			return (ret);
		    }
		    if ((client = client->next) == NULL) {
			mutex_exit(&sp->client_lock);
			sn++;
			while (sn < cs_globals.max_socket_num) {
			    if ((sp = cs_get_sp(sn)) != NULL) {
				mutex_enter(&sp->client_lock);
				if ((client = sp->client_list) != NULL)
				    break;
				mutex_exit(&sp->client_lock);
			    } /* if */
			    sn++;
			} /* while */

			if (sn == cs_globals.max_socket_num)
			    return (CS_NO_MORE_ITEMS);
		    } /* client = client->next */

		} else if (fnc->Attributes &
					CS_GET_FIRSTNEXT_CLIENT_SOCKET_ONLY) {
		    sp = cs_get_sp(GET_CLIENT_SOCKET(fnc->client_handle));
		    if (sp == NULL)
			return (CS_BAD_SOCKET);
		    mutex_enter(&sp->client_lock);
		    if ((client = cs_find_client(fnc->client_handle,
				&ret)) == NULL) {
			mutex_exit(&sp->client_lock);
			return (ret);
		    }
		    if ((client = client->next) == NULL) {
			mutex_exit(&sp->client_lock);
			return (CS_NO_MORE_ITEMS);
		    }
		} else {
		    return (CS_BAD_ATTRIBUTE);
		}

		fnc->client_handle = client->client_handle;
		fnc->num_clients = sp->num_clients;
		mutex_exit(&sp->client_lock);
		break;
	    default:
		ret = CS_BAD_ATTRIBUTE;
		break;

	} /* switch */

	return (ret);
}

/*
 * cs_set_acc_attributes - converts Card Services endianness and
 *				data ordering values to values
 *				that Socket Services understands
 *
 *	calling: *sw - pointer to a set_window_t to set attributes in
 *		 Attributes - CS attributes
 */
static void
cs_set_acc_attributes(set_window_t *sw, uint32_t Attributes)
{
	sw->attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;

	switch (Attributes & WIN_ACC_ENDIAN_MASK) {
	    case WIN_ACC_LITTLE_ENDIAN:
		sw->attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
		break;
	    case WIN_ACC_BIG_ENDIAN:
		sw->attr.devacc_attr_endian_flags = DDI_STRUCTURE_BE_ACC;
		break;
	    case WIN_ACC_NEVER_SWAP:
	    default:
		sw->attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
		break;
	} /* switch */

	switch (Attributes & WIN_ACC_ORDER_MASK) {
	    case WIN_ACC_UNORDERED_OK:
		sw->attr.devacc_attr_dataorder = DDI_UNORDERED_OK_ACC;
		break;
	    case WIN_ACC_MERGING_OK:
		sw->attr.devacc_attr_dataorder = DDI_MERGING_OK_ACC;
		break;
	    case WIN_ACC_LOADCACHING_OK:
		sw->attr.devacc_attr_dataorder = DDI_LOADCACHING_OK_ACC;
		break;
	    case WIN_ACC_STORECACHING_OK:
		sw->attr.devacc_attr_dataorder = DDI_STORECACHING_OK_ACC;
		break;
	    case WIN_ACC_STRICT_ORDER:
	    default:
		sw->attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
		break;
	} /* switch */
}
