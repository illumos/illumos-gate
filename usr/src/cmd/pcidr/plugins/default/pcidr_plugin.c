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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dr.h>
#include <syslog.h>
#include <libnvpair.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <pcidr.h>
#include <pcidr_cfga.h>


PCIDR_PLUGIN_PROTO(attrlistp, optp)
{
	char *fn = PCIDR_PLUGIN_SYMSTR;
	int rv = 0;
	char *cfga_errstr = NULL;
	char *str, *apid;
	cfga_list_data_t *cfga_listp = NULL;
	cfga_cmd_t cmd;
	int cfga_list_len;
	pcidr_attrs_t dr;

	pcidr_set_logopt(&optp->logopt);

	if (pcidr_get_attrs(attrlistp, &dr) != 0 ||
	    pcidr_check_attrs(&dr) != 0) {
		dprint(DWARN, "%s: invalid or missing attributes\n", fn);
		return (EINVAL);
	}

	/*
	 * get state of APID; enforce the cfgadm pci plugin implementation of
	 * returning one matching AP per supplied apid string
	 */
	rv = config_list_ext(1, &dr.dr_ap_id, &cfga_listp, &cfga_list_len,
	    NULL, NULL, &cfga_errstr, CFGA_FLAG_LIST_ALL);
	if (rv != CFGA_OK) {
		str = pcidr_cfga_err_name(rv);
		if (str == NULL)
			str = "unrecognized rv!";
		dprint(DDEBUG, "%s: config_list_ext() on apid = \"%s\" "
		    "failed: rv = %d (%s)", fn, dr.dr_ap_id, rv, str);

		if (cfga_errstr != NULL) {
			dprint(DDEBUG, ", error string = \"%s\"",
			    cfga_errstr);
			free(cfga_errstr);
		}
		dprint(DDEBUG, "\n");
		rv = EINVAL;
		goto OUT;
	}
	if (cfga_list_len != 1) {
		dprint(DWARN, "%s: invalid condition - more than one AP was "
		    "found for the APID \"%s\"\n", fn, dr.dr_ap_id);
		rv = EINVAL;
		goto OUT;
	}

	/*
	 * perform DR
	 */
	dprint(DINFO, "%s: showing info and performing DR on APID(s) "
	    "matching \"%s\"\n", fn, dr.dr_ap_id);

	cmd = CFGA_CMD_NONE;
	dprint(DINFO, "===========================================\n", fn);
	pcidr_print_cfga(DINFO, &cfga_listp[0], "  .. ");
	apid = cfga_listp[0].ap_phys_id;

	if (strcmp(dr.dr_req_type, DR_REQ_OUTGOING_RES) == 0) {
		cmd = CFGA_CMD_DISCONNECT;
		dprint(DINFO, "%s: disconnecting ...\n", fn, apid);

		rv = pcidr_cfga_do_cmd(cmd, &cfga_listp[0]);
		if (rv < 0) {
			dprint(DINFO, "%s: disconnect FAILED\n", fn);
			rv = EIO;
		}
		else
			dprint(DINFO, "%s: disconnect OK\n", fn);

		goto OUT;
	}
	if (strcmp(dr.dr_req_type, DR_REQ_INCOMING_RES) == 0) {
		cmd = CFGA_CMD_CONFIGURE;
		dprint(DINFO, "%s: configuring ...\n", fn, apid);

		rv = pcidr_cfga_do_cmd(cmd, &cfga_listp[0]);
		if (rv < 0) {
			dprint(DINFO, "%s: configure FAILED\n", fn);
			rv = EIO;
		} else
			dprint(DINFO, "%s: configure OK\n", fn);

		goto OUT;
	}

	/* we should not get here if pcidr_check_attrs() is correct */
	dprint(DWARN, "%s: invalid dr_req_type = %s\n", fn, dr.dr_req_type);
	assert(cmd != CFGA_CMD_NONE);
	return (EINVAL);
	/*NOTREACHED*/
OUT:
	if (cfga_listp != NULL)
		free(cfga_listp);
	return (rv);
}
