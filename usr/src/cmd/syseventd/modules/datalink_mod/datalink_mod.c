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
 * datalink syseventd module.
 *
 * The purpose of this module is to identify all datalink related events,
 * and react accordingly.
 */

#include <errno.h>
#include <sys/sysevent/eventdefs.h>
#include <string.h>
#include <libnvpair.h>
#include <librcm.h>
#include <libsysevent.h>

static rcm_handle_t *rcm_hdl = NULL;

/*ARGSUSED*/
static int
datalink_deliver_event(sysevent_t *ev, int unused)
{
	const char *class = sysevent_get_class_name(ev);
	const char *subclass = sysevent_get_subclass_name(ev);
	nvlist_t *nvl;
	int err = 0;

	if (strcmp(class, EC_DATALINK) != 0 ||
	    strcmp(subclass, ESC_DATALINK_PHYS_ADD) != 0) {
		return (0);
	}

	if (sysevent_get_attr_list(ev, &nvl) != 0)
		return (EINVAL);

	if (rcm_notify_event(rcm_hdl, RCM_RESOURCE_LINK_NEW, 0, nvl, NULL) !=
	    RCM_SUCCESS) {
		err = EINVAL;
	}

	nvlist_free(nvl);
	return (err);
}

static struct slm_mod_ops datalink_mod_ops = {
	SE_MAJOR_VERSION,
	SE_MINOR_VERSION,
	SE_MAX_RETRY_LIMIT,
	datalink_deliver_event
};

struct slm_mod_ops *
slm_init()
{
	if (rcm_alloc_handle(NULL, 0, NULL, &rcm_hdl) != RCM_SUCCESS)
		return (NULL);

	return (&datalink_mod_ops);
}

void
slm_fini()
{
	(void) rcm_free_handle(rcm_hdl);
	rcm_hdl = NULL;
}
