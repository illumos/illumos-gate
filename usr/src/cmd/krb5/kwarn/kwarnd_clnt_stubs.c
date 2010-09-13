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
 *  stub module for kwarnd.
 */

#include <stdio.h>
#include <stdlib.h>
#include "kwarnd.h"
#include <rpc/rpc.h>

#include <sys/types.h>
#include <sys/devops.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/uio.h>
#include <syslog.h>

extern CLIENT *getkwarnd_handle(void);
extern void resetkwarnd_handle(void);

OM_UINT32
kwarn_add_warning(WARNING_NAME_T warning_name, int cred_exp_time)
{
	kwarn_add_warning_arg args;
	kwarn_add_warning_res res;
	enum clnt_stat ret;
	boolean_t first = TRUE;
	CLIENT *clnt;

	/* check the input/output parameters */
	if (warning_name == NULL || cred_exp_time == 0)
		return (1);

rebind:
	/* get the client handle to kwarnd */
	if ((clnt = getkwarnd_handle()) == NULL) {
		/*
		 * Let app output if an error occurs but we'll syslog to
		 * DEBUG to get error details if needed.
		 */
		syslog(LOG_DEBUG, "%s",
		    clnt_spcreateerror("getkwarnd_handle"));
		return (1);
	}

	/* set the rpc parameters */
	args.cred_exp_time = cred_exp_time;
	args.warning_name = warning_name;

	/* call the remote procedure */
	memset(&res, 0, sizeof (res));
	ret = kwarn_add_warning_1(&args, &res, clnt);
	if (ret != RPC_SUCCESS) {
		/*
		 * Could have timed out due to the process restarting for
		 * various reasons. Should attempt to rebind in the case
		 * process is actually running.
		 */
		if (ret == RPC_TIMEDOUT && first) {
			resetkwarnd_handle();
			first = FALSE;
			goto rebind;
		}
		return (1);
	}

	/* nothing to free */

	return (res.status);
}

OM_UINT32
kwarn_del_warning(WARNING_NAME_T warning_name)
{
	kwarn_del_warning_arg args;
	kwarn_del_warning_res res;
	enum clnt_stat ret;
	boolean_t first = TRUE;
	CLIENT *clnt;

	/* check the output parameters */
	if (warning_name == NULL)
		return (1);

rebind:
	/* get the client GSSD handle */
	if ((clnt = getkwarnd_handle()) == NULL) {
		/*
		 * Let app output if an error occurs but we'll syslog to
		 * DEBUG to get error details if needed.
		 */
		syslog(LOG_DEBUG, "%s",
		    clnt_spcreateerror("getkwarnd_handle"));
		return (1);
	}

	/* set the input parameters */
	args.warning_name = warning_name;

	/* call the remote procedure */
	memset(&res, 0, sizeof (res));
	ret = kwarn_del_warning_1(&args, &res, clnt);
	if (ret != RPC_SUCCESS) {
		/*
		 * Could have timed out due to the process restarting for
		 * various reasons. Should attempt to rebind in the case
		 * process is actually running.
		 */
		if (ret == RPC_TIMEDOUT && first) {
			resetkwarnd_handle();
			first = FALSE;
			goto rebind;
		}
		return (1);
	}

	/* nothing to free */

	return (res.status);
}
