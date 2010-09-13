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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This plugin checks the status of FC-AL disks periodically and
 * in response to PICL events. It adjusts the state of the FC-AL LEDs
 * to match the disk status.
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <alloca.h>
#include <syslog.h>
#include <string.h>
#include <libintl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/systeminfo.h>
#include <sys/param.h>
#include <poll.h>
#include <errno.h>
#include <libnvpair.h>
#include "fcal_leds.h"

static void fcal_leds_register(void);
static void fcal_leds_init(void);
static void fcal_leds_fini(void);
static void *fcal_poll_thread(void *args);
static FILE *open_config(void);
static int read_led_state(ptree_rarg_t *parg, void *buf);
static void add_led_refs(led_dtls_t *dtls);
static void delete_led_refs(led_dtls_t *dtls);
static void piclfcal_evhandler(const char *ename, const void *earg,
    size_t size, void *cookie);

/*
 * Global thread data
 */
led_dtls_t		*g_led_dtls = NULL;
pthread_cond_t		g_cv;
pthread_cond_t		g_cv_ack;
pthread_mutex_t		g_mutex;
volatile int		g_event_flag;
volatile boolean_t	g_finish_now = B_FALSE;
volatile boolean_t	g_leds_thread_ack = B_FALSE;

static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_NON_CRITICAL,
	"SUNW_fcal_leds",
	fcal_leds_init,
	fcal_leds_fini
};

static boolean_t	cvAndMutexInit = B_FALSE;
static pthread_t	ledsthr_tid;
static pthread_attr_t	ledsthr_attr;
static boolean_t	ledsthr_created = B_FALSE;
static pthread_t	pollthr_tid;
static pthread_attr_t	pollthr_attr;
static boolean_t	pollthr_created = B_FALSE;
static volatile boolean_t poll_thread_ack = B_FALSE;

/*
 * look up table for LED state
 */
static struct {
	const led_state_t	led_state;
	const char		*state_str;
} state_lookup[] = {
	{ LED_STATE_OFF,	FCAL_PICL_LED_OFF	},
	{ LED_STATE_ON,		FCAL_PICL_LED_ON	},
	{ LED_STATE_TEST,	FCAL_PICL_LED_TEST	}
};

#define	state_lkup_len	(sizeof (state_lookup) / sizeof (state_lookup[0]))

/*
 * executed as part of .init when the plugin is dlopen()ed
 */
#pragma	init(fcal_leds_register)

static void
fcal_leds_register(void)
{
	(void) picld_plugin_register(&my_reg_info);
}

/* ARGSUSED */
static void
piclfcal_evhandler(const char *ename, const void *earg, size_t size,
    void *cookie)
{
	int r;

	if (earg == NULL)
		return;

	r = pthread_mutex_lock(&g_mutex);

	if (r != 0) {
		SYSLOG(LOG_ERR, EM_MUTEX_FAIL, mystrerror(r));
		return;
	}
	g_event_flag |= FCAL_EV_CONFIG;
	(void) pthread_cond_signal(&g_cv);

	(void) pthread_mutex_unlock(&g_mutex);
}

/*
 * Locate and open relevant config file
 */
static FILE *
open_config(void)
{
	FILE	*fp = NULL;
	char	nmbuf[SYS_NMLN];
	char	fname[PATH_MAX];

	if (sysinfo(SI_PLATFORM, nmbuf, sizeof (nmbuf)) == -1)
		return (NULL);
	(void) snprintf(fname, sizeof (fname), PICLD_PLAT_PLUGIN_DIRF, nmbuf);
	(void) strlcat(fname, FCAL_LEDS_CONF_FILE, sizeof (fname));
	fp = fopen(fname, "r");
	if (fp == NULL) {
		SYSLOG(LOG_ERR, EM_CANT_OPEN, fname);
	}
	return (fp);
}

/*
 * read volatile property function for led State
 */
static int
read_led_state(ptree_rarg_t *parg, void *buf)
{
	led_dtls_t *dtls = g_led_dtls;
	picl_nodehdl_t nodeh = parg->nodeh;
	/*
	 * valbuf has space for a unit address at the end
	 */
	char valbuf[MAX_LEN_UNIT_ADDRESS];
	char *ptr;
	uint_t addr;
	int disk, led;
	led_state_t stat;
	/*
	 * each led-unit node has a UnitAddress property set to the bit
	 * value associated with the led. Read that property
	 */
	int r = ptree_get_propval_by_name(nodeh, PICL_PROP_UNIT_ADDRESS,
	    valbuf, sizeof (valbuf));
	if (r != PICL_SUCCESS)
		return (r);
	valbuf[sizeof (valbuf) - 1] = '\0';	/* ensure null terminated */
	/* UnitAddress is a string of hex digits, convert to an int */
	addr = strtoul(valbuf, &ptr, 16);
	if (dtls == NULL)
		return (PICL_PROPVALUNAVAILABLE);
	/*
	 * search the leds of each disk for a match with this UnitAddress
	 */
	for (disk = 0; disk < dtls->n_disks; disk++) {
		for (led = 0; led < FCAL_LED_CNT; led++) {
			if (addr == dtls->led_addr[led][disk])
				break;
		}
		if (led < FCAL_LED_CNT)
			break;
	}
	if (disk == dtls->n_disks)
		return (PICL_PROPVALUNAVAILABLE);
	stat = dtls->led_state[led][disk];
	/*
	 * state_lookup is a table relating led-state enums to equivalent
	 * text strings. Locate the string for the current state.
	 */
	for (r = 0; r < state_lkup_len; r++) {
		if (state_lookup[r].led_state == stat) {
			(void) strlcpy(buf, state_lookup[r].state_str,
			    MAX_LEN_LED_STATE);
			return (PICL_SUCCESS);
		}
	}
	return (PICL_PROPVALUNAVAILABLE);
}

int
find_disk_slot(led_dtls_t *dtls, int disk, picl_nodehdl_t *nodeh)
{
	int		r;
	int		unitlen;
	char		unitstr[MAXPATHLEN];

	if (dtls->disk_unit_parent == NULL) {
		return (PICL_NODENOTFOUND);
	}
	unitlen = strlen(dtls->disk_unit_parent);
	/*
	 * get search string buffer, allow space for address
	 */
	(void) strlcpy(unitstr, dtls->disk_unit_parent, MAXPATHLEN);
	(void) snprintf(unitstr + unitlen, MAXPATHLEN - unitlen, "%x", disk);
	r = ptree_get_node_by_path(unitstr, nodeh);
	return (r);
}

int
create_Device_table(picl_prophdl_t *tbl_h, picl_prophdl_t *tableh)
{
	int			r;
	ptree_propinfo_t	propinfo;

	r = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_TABLE, PICL_READ, sizeof (picl_prophdl_t),
	    PICL_PROP_DEVICES, NULL, NULL);
	if (r != PICL_SUCCESS) {
		return (r);
	}
	r = ptree_create_table(tbl_h);
	if (r != PICL_SUCCESS) {
		return (r);
	}
	r = ptree_create_prop(&propinfo, tbl_h, tableh);
	return (r);
}

/*
 * Locate disk-slot nodes and add DeviceTable of LED references
 * Also add a volatile State property to each LED node
 */
static void
add_led_refs(led_dtls_t *dtls)
{
	int		d, i, r;
	int		ledlen;
	char		ledstr[MAXPATHLEN];
	picl_nodehdl_t  slot_node;

	if (dtls->disk_led_nodes == NULL) {
		return;
	}
	ledlen = strlen(dtls->disk_led_nodes);
	/* set up search string in buffer with space to append address */
	(void) strlcpy(ledstr, dtls->disk_led_nodes, MAXPATHLEN);
	for (d = 0; d < dtls->n_disks; d++) {
		picl_prophdl_t tbl_hdl;
		picl_prophdl_t tbl_prop_hdl;
		picl_nodehdl_t led_node_hdl;
		picl_prophdl_t tbl_prop[FCAL_DEVTABLE_NCOLS];
		ptree_propinfo_t propinfo;

		r = create_Device_table(&tbl_hdl, &tbl_prop_hdl);
		if (r != PICL_SUCCESS)
			break;

		/*
		 * locate disk-slot node in frutree
		 */
		if (find_disk_slot(dtls, d, &slot_node) != PICL_SUCCESS)
			break;

		for (i = 0; i < FCAL_LED_CNT; i++) {
			/*
			 * For each disk-slot in frutree, add a device
			 * table of references to relevant LEDs.
			 * En passant, add a volatile State property to
			 * each LED node found.
			 */
			/*
			 * append led address to search string
			 */
			(void) snprintf(ledstr + ledlen, MAXPATHLEN - ledlen,
			    "%x", dtls->led_addr[i][d]);
			r = ptree_get_node_by_path(ledstr, &led_node_hdl);
			if (r != PICL_SUCCESS) {
				break;
			}
			r = ptree_init_propinfo(&propinfo,
			    PTREE_PROPINFO_VERSION, PICL_PTYPE_CHARSTRING,
			    PICL_READ | PICL_VOLATILE, MAX_LEN_LED_STATE,
			    PICL_PROP_STATE, read_led_state, NULL);
			if (r != PICL_SUCCESS) {
				break;
			}
			r = ptree_create_and_add_prop(led_node_hdl,
			    &propinfo, NULL, NULL);
			if (r != PICL_SUCCESS) {
				break;
			}
			r = ptree_init_propinfo(&propinfo,
			    PTREE_PROPINFO_VERSION, PICL_PTYPE_CHARSTRING,
			    PICL_READ, sizeof (PICL_CLASS_LED),
			    PICL_PROP_CLASS, NULL, NULL);
			if (r != PICL_SUCCESS) {
				break;
			}
			r = ptree_create_prop(&propinfo, PICL_CLASS_LED,
			    &tbl_prop[0]);
			if (r != PICL_SUCCESS) {
				break;
			}
			r = ptree_init_propinfo(&propinfo,
			    PTREE_PROPINFO_VERSION, PICL_PTYPE_REFERENCE,
			    PICL_READ, sizeof (picl_prophdl_t),
			    FCAL_PICL_LED_REF, NULL, NULL);
			if (r != PICL_SUCCESS) {
				break;
			}
			r = ptree_create_prop(&propinfo, &led_node_hdl,
			    &tbl_prop[1]);
			if (r != PICL_SUCCESS) {
				break;
			}
			r = ptree_add_row_to_table(tbl_hdl,
			    FCAL_DEVTABLE_NCOLS, tbl_prop);
			if (r != PICL_SUCCESS) {
				break;
			}
		}
		if (r != PICL_SUCCESS)
			break;
		(void) ptree_add_prop(slot_node, tbl_prop_hdl);
	}
}

/*
 * This is an undo function to match add_led_refs()
 * Locate disk-slot nodes and remove Devices table of LED references
 * Also remove volatile State property to each LED node
 */
static void
delete_led_refs(led_dtls_t *dtls)
{
	int		d;
	int		i;
	int		r;
	int		ledlen;
	picl_nodehdl_t  node_hdl;
	picl_prophdl_t	prop_hdl;
	char		ledstr[MAXPATHLEN];

	if (dtls->disk_led_nodes == NULL)
		return;

	for (d = 0; d < dtls->n_disks; d++) {
		if (find_disk_slot(dtls, d, &node_hdl) != PICL_SUCCESS)
			continue;
		if (ptree_get_prop_by_name(node_hdl, PICL_PROP_DEVICES,
		    &prop_hdl) != PICL_SUCCESS)
			continue;
		if (ptree_delete_prop(prop_hdl) != PICL_SUCCESS)
			continue;
		(void) ptree_destroy_prop(prop_hdl);
	}

	ledlen = strlen(dtls->disk_led_nodes);
	(void) strlcpy(ledstr, dtls->disk_led_nodes, MAXPATHLEN);

	for (d = 0; d < dtls->n_disks; d++) {
		for (i = 0; i < FCAL_LED_CNT; i++) {
			/*
			 * find each led node
			 */
			(void) snprintf(ledstr + ledlen, MAXPATHLEN - ledlen,
			    "%x", dtls->led_addr[i][d]);
			r = ptree_get_node_by_path(ledstr, &node_hdl);
			if (r != PICL_SUCCESS)
				continue;
			/*
			 * locate and delete the volatile State property
			 */
			if (ptree_get_prop_by_name(node_hdl,
			    PICL_PROP_STATE, &prop_hdl) != PICL_SUCCESS)
				continue;
			if (ptree_delete_prop(prop_hdl) != PICL_SUCCESS)
				continue;
			(void) ptree_destroy_prop(prop_hdl);
		}
	}
}

/*
 * Poll thread.
 * This thread sits on a poll() call for the fast poll interval.
 * At each wake up it determines if a time event should be passed on.
 * Poll seems to be reliable when the realtime clock is wound backwards,
 * whereas pthread_cond_timedwait() is not.
 */
/*ARGSUSED*/
static void *
fcal_poll_thread(void *args)
{
	led_dtls_t	*dtls = NULL;
	int		c;
	int		slow_poll_count;
	boolean_t	do_event;

	for (;;) {
		if (g_finish_now) {
			c = pthread_mutex_lock(&g_mutex);

			if (c != 0) {
				SYSLOG(LOG_ERR, EM_MUTEX_FAIL, mystrerror(c));
				break;
			}
			poll_thread_ack = B_TRUE;
			(void) pthread_cond_signal(&g_cv_ack);
			(void) pthread_cond_wait(&g_cv, &g_mutex);

			(void) pthread_mutex_unlock(&g_mutex);
			continue;
		}

		/*
		 * If picld has been recycled, or if this is the initial
		 * entry, dtls will not match g_led_dtls.
		 * In this case, do some resetting.
		 */
		if (dtls != g_led_dtls) {
			dtls = g_led_dtls;
			slow_poll_count = dtls->slow_poll_ticks;
			dtls->polling = B_TRUE;
		}

		c = poll(NULL, 0, dtls->fast_poll * 1000);
		if (c == -1) {
			SYSLOG(LOG_ERR, EM_POLL_FAIL, mystrerror(errno));
			break;
		}
		/*
		 * dtls->fast_poll_end is the number of fast poll times left
		 * before we revert to slow polling. If it is non-zero, the
		 * fcal_leds thread is do fast polling and we pass on every
		 * poll wakeup.
		 */
		do_event = (dtls->fast_poll_end != 0);
		/*
		 * If a LED test is underway, fast polling would normally be
		 * set also. Just in case the timers are configured unusually,
		 * pass on all poll wakeups while a LED test is current.
		 */
		if ((!do_event) && is_led_test(dtls))
			do_event = B_TRUE;
		if (!do_event) {
			/*
			 * If we get here, the fcal_leds thread is only doing
			 * slow polls. Count down the slow_poll_count and set
			 * an event if it expires.
			 */
			if (--slow_poll_count == 0) {
				slow_poll_count = dtls->slow_poll_ticks;
				do_event = B_TRUE;
			}
		}
		if (do_event) {
			c = pthread_mutex_lock(&g_mutex);

			if (c != 0) {
				SYSLOG(LOG_ERR, EM_MUTEX_FAIL, mystrerror(c));
				break;
			}
			/*
			 * indicate in the event flag that this is a time event
			 */
			g_event_flag |= FCAL_EV_POLL;
			(void) pthread_cond_signal(&g_cv);

			(void) pthread_mutex_unlock(&g_mutex);
		}
	}

	dtls->polling = B_FALSE;

	/*
	 * if picld restarted, allow this thread to be recreated
	 */
	pollthr_created = B_FALSE;

	return ((void *)errno);
}

/*
 * Init entry point of the plugin
 * Opens and parses config file.
 * Establishes an interrupt routine to catch DEVICE ADDED/REMOVED events
 * and starts a new thread for polling FC-AL disk status information.
 */
static void
fcal_leds_init(void)
{
	FILE *fp;
	int err = 0;

	if ((fp = open_config()) == NULL)
		return;
	if (fc_led_parse(fp, &g_led_dtls) != 0) {
		(void) fclose(fp);
		return;
	}
	(void) fclose(fp);
	g_finish_now = B_FALSE;
	g_event_flag = 0;

	if (!cvAndMutexInit) {
		if ((pthread_cond_init(&g_cv, NULL) == 0) &&
		    (pthread_cond_init(&g_cv_ack, NULL) == 0) &&
		    (pthread_mutex_init(&g_mutex, NULL) == 0)) {
			cvAndMutexInit = B_TRUE;
		} else {
			return;
		}
	}

	add_led_refs(g_led_dtls);

	(void) ptree_register_handler(PICLEVENT_SYSEVENT_DEVICE_ADDED,
	    piclfcal_evhandler, NULL);
	(void) ptree_register_handler(PICLEVENT_SYSEVENT_DEVICE_REMOVED,
	    piclfcal_evhandler, NULL);

	if (ledsthr_created || pollthr_created) {
		/*
		 * so this is a restart, wake up sleeping threads
		 */
		err = pthread_mutex_lock(&g_mutex);

		if (err != 0) {
			SYSLOG(LOG_ERR, EM_MUTEX_FAIL, mystrerror(err));
			return;
		}
		g_leds_thread_ack = B_FALSE;
		poll_thread_ack = B_FALSE;
		(void) pthread_cond_broadcast(&g_cv);

		(void) pthread_mutex_unlock(&g_mutex);
	}
	if (!ledsthr_created) {
		if ((pthread_attr_init(&ledsthr_attr) != 0) ||
		    (pthread_attr_setscope(&ledsthr_attr,
		    PTHREAD_SCOPE_SYSTEM) != 0))
			return;

		if ((err = pthread_create(&ledsthr_tid, &ledsthr_attr,
		    fcal_leds_thread, g_led_dtls)) != 0) {
			SYSLOG(LOG_ERR, EM_THREAD_CREATE_FAILED,
			    mystrerror(err));
			return;
		}

		ledsthr_created = B_TRUE;
	}

	if (pollthr_created == B_FALSE) {
		if ((pthread_attr_init(&pollthr_attr) != 0) ||
		    (pthread_attr_setscope(&pollthr_attr,
		    PTHREAD_SCOPE_SYSTEM) != 0))
			return;

		if ((err = pthread_create(&pollthr_tid, &pollthr_attr,
		    fcal_poll_thread, g_led_dtls)) != 0) {
			g_led_dtls->polling = B_FALSE;
			SYSLOG(LOG_ERR, EM_THREAD_CREATE_FAILED,
			    mystrerror(err));
			return;
		}

		pollthr_created = B_TRUE;
	}
}

/*
 * fini entry point of the plugin
 */
static void
fcal_leds_fini(void)
{
	int	c;

	/* unregister event handlers */
	(void) ptree_unregister_handler(PICLEVENT_SYSEVENT_DEVICE_ADDED,
	    piclfcal_evhandler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_SYSEVENT_DEVICE_REMOVED,
	    piclfcal_evhandler, NULL);
	/*
	 * it's very confusing to leave uncontrolled leds on, so clear them.
	 */
	if (g_led_dtls != NULL) {
		int ledNo;
		int diskNo;
		for (ledNo = 0; ledNo < FCAL_LED_CNT; ledNo++) {
			if ((g_led_dtls->led_addr[ledNo] == NULL) ||
			    (g_led_dtls->led_state[ledNo] == NULL)) {
				break;	/* incomplete setup */
			}
			for (diskNo = 0; diskNo < g_led_dtls->n_disks;
			    diskNo++) {
				clr_led(diskNo, LED_PROPS_START + 1 + ledNo,
				    g_led_dtls);
			}
		}
	}
	/*
	 * tell other threads to stop
	 */
	if (cvAndMutexInit && (ledsthr_created || pollthr_created)) {
		g_finish_now = B_TRUE;
		c = pthread_mutex_lock(&g_mutex);
		if (c != 0) {
			SYSLOG(LOG_ERR, EM_MUTEX_FAIL, mystrerror(c));
		} else {
			(void) pthread_cond_broadcast(&g_cv);
			(void) pthread_mutex_unlock(&g_mutex);

			/*
			 * and wait for them to acknowledge
			 */
			while ((ledsthr_created && !g_leds_thread_ack) ||
			    (pollthr_created && !poll_thread_ack)) {
				c = pthread_mutex_lock(&g_mutex);
				if (c != 0) {
					SYSLOG(LOG_ERR, EM_MUTEX_FAIL,
					    mystrerror(c));
					break;
				}
				(void) pthread_cond_wait(&g_cv_ack, &g_mutex);
				(void) pthread_mutex_unlock(&g_mutex);
			}
		}
	}
	/*
	 * remove picl nodes created by this plugin
	 */
	if (g_led_dtls != NULL) {
		for (c = 0; c < g_led_dtls->n_disks; c++) {
			/*
			 * remove all disk unit nodes from frutree
			 */
			delete_disk_unit(g_led_dtls, c);
		}
		/*
		 * remove Devices tables of references to leds
		 * and led State properties
		 */
		delete_led_refs(g_led_dtls);
		/*
		 * finally free the led details
		 */
		free_led_dtls(g_led_dtls);
		g_led_dtls = NULL;
	}
}
