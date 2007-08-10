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

#include <sys/contract/device.h>
#include <sys/wait.h>
#include <sys/ctfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <libuutil.h>
#include <libintl.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include "libcontract_impl.h"
#include "libcontract_priv.h"

/*ARGSUSED*/
void
event_device(FILE *file, ct_evthdl_t ev, int verbose)
{
	uint_t type;
	char *device;
	char *s;
	ctid_t ctid;
	ct_stathdl_t stathdl;
	int statfd;

	type = ct_event_get_type(ev);
	ctid = ct_event_get_ctid(ev);

	statfd = contract_open(ctid, "device", "status", O_RDONLY);
	if (statfd == -1) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "[bad contract]\n"));
		return;
	}

	if (ct_status_read(statfd, CTD_ALL, &stathdl) != 0) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "[status error]\n"));
		return;
	}

	if (ct_dev_status_get_minor(stathdl, &device) != 0) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "[bad status]\n"));
		return;
	}


	switch (type) {
	case CT_DEV_EV_OFFLINE:
		s = dgettext(TEXT_DOMAIN, "device %s offlining\n");
		break;
	case CT_DEV_EV_DEGRADED:
		s = dgettext(TEXT_DOMAIN, "device %s degrading\n");
		break;
	case CT_DEV_EV_ONLINE:
		s = dgettext(TEXT_DOMAIN, "device %s online\n");
		break;
	case CT_EV_NEGEND:
		contract_negend_dump(file, ev);
		s = NULL;
		break;
	default:
		s = dgettext(TEXT_DOMAIN, "device %s sent an unknown event\n");
		break;
	}

	if (s) {
		/*LINTED*/
		(void) fprintf(file, s, device);
	}

	ct_status_free(stathdl);
	(void) close(statfd);
}
