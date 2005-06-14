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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

#define	FCC_MAX_CELLS	10

int
fc_run_priv(common_data_t *cdp, char *service, int nin, int nout, ...)
{
	va_list ap;
	int i, error, no_err;
	fc_cell_t fc_req[FCC_FIXED_CELLS+FCC_MAX_CELLS];
	struct fc_client_interface *cip = (struct fc_client_interface *)fc_req;
	fc_cell_t *fcp;
	char *error_msg;

	no_err = nin & FCRP_NOERROR;
	nin &= ~FCRP_NOERROR;

	bzero(fc_req, sizeof (fc_req));
	if (nin + nout > FCC_MAX_CELLS) {
		log_message(MSG_ERROR, "%s: too many ins (%d) and outs (%d)\n",
		    service, nin, nout);
		nin = min(nin, FCC_MAX_CELLS);
		nout = FCC_MAX_CELLS - nin;
	}
	va_start(ap, nout);
	cip->svc_name = fc_ptr2cell(service);
	cip->nargs = fc_int2cell(nin);
	cip->nresults = fc_int2cell(nout);
	for (i = 0; i < nin; i++)
		fc_arg(cip, i) = va_arg(ap, fc_cell_t);
	error = ioctl(cdp->fcode_fd, FC_RUN_PRIV, cip);
	for (i = 0; i < nout; i++) {
		fcp = va_arg(ap, fc_cell_t *);
		*fcp = fc_result(cip, i);
	}
	va_end(ap);

	if (error)
		error_msg = strerror(errno);
	else if (cip->priv_error) {
		error_msg = "Priv violation";
		error = 1;
	} else if (cip->error) {
		error_msg = "Error";
		error = 1;
	}
	if ((error & !no_err) ||
	    (get_interpreter_debug_level() & DEBUG_REG_ACCESS)) {
		if (error)
			log_message(MSG_ERROR, "%s: FC_RUN_PRIV: %s: ",
			    cdp->Progname, error_msg);
		log_message(MSG_ERROR, "%s ( ", service);
		for (i = 0; i < nin; i++)
			log_message(MSG_ERROR, "%llx ",
			    (uint64_t)fc_arg(cip, i));
		log_message(MSG_ERROR, ")");
		if (error)
			;
		else if (nout) {
			log_message(MSG_ERROR, " ->");
			for (i = 0; i < nout; i++)
				log_message(MSG_ERROR, " %llx",
				    (uint64_t)fc_result(cip, i));
		} else
			log_message(MSG_ERROR, " OK");
		log_message(MSG_ERROR, "\n");
	}
	return (error);
}
