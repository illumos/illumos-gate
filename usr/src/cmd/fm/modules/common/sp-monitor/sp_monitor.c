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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 */

/*
 * /dev/ipmi IPMI monitor
 *
 * The purpose of this module is to monitor the connection between the system
 * and the service processor attached via /dev/ipmi0.  The module assumes the SP
 * supports the Sun OEM uptime IPMI command.  If the BMC connection does not
 * exist, or the uptime function is not implemented, then the module unloads
 * without doing anything.
 *
 * When the module is first loaded, or a reset is detected, the module will
 * generate the ESC_PLATFORM_SP_RESET sysevent as a system-wide notification to
 * indicate that this event has occurred.
 *
 * Note that this event generation is not guaranteed to have a one-to-one
 * correspondence with an SP reset.  There is no persistence, so if fmd is
 * restarted we will generate this event again.  Thus the event only indicates
 * the possibility that the SP has been reset.  This could be enhanced using fmd
 * checkpoints to have some persistent state to avoid this scenario.  However,
 * it currently serves the useful dual purpose of notifying consumers of system
 * startup as well as SP reset through a single channel.
 */

#include <errno.h>
#include <libipmi.h>
#include <libsysevent.h>
#include <string.h>
#include <fm/fmd_api.h>
#include <sys/sysevent/eventdefs.h>

typedef struct sp_monitor {
	ipmi_handle_t	*sm_hdl;
	uint32_t	sm_seconds;
	uint32_t	sm_generation;
	hrtime_t	sm_interval;
} sp_monitor_t;

static void
sp_post_sysevent(fmd_hdl_t *hdl)
{
	sp_monitor_t *smp = fmd_hdl_getspecific(hdl);
	sysevent_id_t eid;

	fmd_hdl_debug(hdl, "SP reset detected, posting sysevent");

	if (sysevent_post_event(EC_PLATFORM, ESC_PLATFORM_SP_RESET,
	    SUNW_VENDOR, "fmd", NULL, &eid) != 0) {
		fmd_hdl_debug(hdl, "failed to send sysevent: %s",
		    strerror(errno));
		/*
		 * We reset the seconds and generation so that the next time
		 * through we will try to post the sysevent again.
		 */
		smp->sm_seconds = -1U;
		smp->sm_generation = -1U;
	}
}

/*ARGSUSED*/
static void
sp_timeout(fmd_hdl_t *hdl, id_t id, void *data)
{
	sp_monitor_t *smp = fmd_hdl_getspecific(hdl);
	uint32_t seconds, generation;

	if (ipmi_sunoem_uptime(smp->sm_hdl, &seconds, &generation) != 0) {
		/*
		 * Ignore uptime failures.  We will generate the appropriate
		 * event when it comes back online.
		 */
		fmd_hdl_debug(hdl, "failed to get uptime: %s",
		    ipmi_errmsg(smp->sm_hdl));
	} else {
		/*
		 * We want to catch cases where the generation number is
		 * explicitly reset, or when the SP configuration is reset after
		 * a reboot (and the generation number is 0).  We also post a
		 * sysevent when the module initially loads, since we can't be
		 * sure if we missed a SP reset or not.
		 */
		if (seconds < smp->sm_seconds ||
		    generation != smp->sm_generation ||
		    smp->sm_seconds == 0)
			sp_post_sysevent(hdl);

		smp->sm_seconds = seconds;
		smp->sm_generation = generation;
	}

	(void) fmd_timer_install(hdl, NULL, NULL, smp->sm_interval);
}

static const fmd_hdl_ops_t fmd_ops = {
	NULL,		/* fmdo_recv */
	sp_timeout,	/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
};

static const fmd_prop_t fmd_props[] = {
	{ "interval", FMD_TYPE_TIME, "60sec" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t fmd_info = {
	"Service Processor Monitor", "1.0", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	sp_monitor_t *smp;
	int error;
	char *msg;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return;

	smp = fmd_hdl_zalloc(hdl, sizeof (sp_monitor_t), FMD_SLEEP);
	fmd_hdl_setspecific(hdl, smp);

	if ((smp->sm_hdl = ipmi_open(&error, &msg, IPMI_TRANSPORT_BMC, NULL))
	    == NULL) {
		/*
		 * If /dev/ipmi0 doesn't exist on the system, then unload the
		 * module without doing anything.
		 */
		if (error != EIPMI_BMC_OPEN_FAILED)
			fmd_hdl_abort(hdl, "failed to initialize IPMI "
			    "connection: %s\n", msg);
		fmd_hdl_debug(hdl, "failed to load: no IPMI connection "
		    "present");
		fmd_hdl_free(hdl, smp, sizeof (sp_monitor_t));
		fmd_hdl_unregister(hdl);
		return;
	}

	/*
	 * Attempt an initial uptime() call.  If the IPMI command is
	 * unrecognized, then this is an unsupported platform and the module
	 * should be unloaded.  Any other error is treated is transient failure.
	 */
	if ((error = ipmi_sunoem_uptime(smp->sm_hdl, &smp->sm_seconds,
	    &smp->sm_generation)) != 0 &&
	    ipmi_errno(smp->sm_hdl) == EIPMI_INVALID_COMMAND) {
		fmd_hdl_debug(hdl, "failed to load: uptime command "
		    "not supported");
		ipmi_close(smp->sm_hdl);
		fmd_hdl_free(hdl, smp, sizeof (sp_monitor_t));
		fmd_hdl_unregister(hdl);
		return;
	}

	smp->sm_interval = fmd_prop_get_int64(hdl, "interval");

	if (error == 0)
		fmd_hdl_debug(hdl, "successfully loaded, uptime = %u seconds "
		    "(generation %u)", smp->sm_seconds, smp->sm_generation);
	else
		fmd_hdl_debug(hdl, "successfully loaded, but uptime call "
		    "failed: %s", ipmi_errmsg(smp->sm_hdl));

	/*
	 * Setup the recurring timer.
	 */
	(void) fmd_timer_install(hdl, NULL, NULL, 0);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	sp_monitor_t *smp = fmd_hdl_getspecific(hdl);

	if (smp) {
		ipmi_close(smp->sm_hdl);
		fmd_hdl_free(hdl, smp, sizeof (sp_monitor_t));
	}
}
