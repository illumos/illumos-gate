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

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <kstat.h>

#include "ii_stats.h"
#include "sdbc_stats.h"
#include "sndr_stats.h"

#include "multi_stats.h"

#include "dsstat.h"
#include "common.h"
#include "report.h"

/*
 * do_stats() - called by main() to start monitoring
 *
 */
int
do_stats()
{
	int error;
	int pass;

	/* Collection/reporting loop */
	for (pass = 0; ; pass++) { /* CSTYLED */
		if (iterations != -1 && pass >= iterations)
			return (0);

		error = discover();

		if (error == ENOMEM || error == EINVAL)
			return (error);

		if (error == EAGAIN && pass == 0)
			return (error);

		(void) sleep(interval);

		if ((error = update()) != 0)
			return (error);

		if (report())
			break;
	}

	/* No stats on this system */
	return (EAGAIN);
}

int
discover()
{
	int err = 0;

	int sdbc_err = 0;
	int sndr_err = 0;
	int ii_err = 0;

	kstat_ctl_t *kc;

	if ((kc = kstat_open()) == NULL)
		return (ENOMEM);

	if (mode & SDBC) {
	    sdbc_err = sdbc_discover(kc);
	    err = sdbc_err;
	    if (sdbc_err && !(mode & MULTI))
		goto fail;
	    if (sdbc_err && (mode & MULTI) && sdbc_err != EAGAIN)
		goto fail;
	}

	if (mode & SNDR) {
	    sndr_err = sndr_discover(kc);
	    err = sndr_err;
	    if (sndr_err && !(mode & MULTI))
		goto fail;
	    if (sndr_err && (mode & MULTI) && sndr_err != EAGAIN)
		goto fail;
	}

	if (mode & IIMG) {
	    ii_err = ii_discover(kc);
	    err = ii_err;
	    if (ii_err && !(mode & MULTI))
		goto fail;
	    if (ii_err && ii_err != EAGAIN && (mode & MULTI))
		goto fail;
	}

	(void) kstat_close(kc);
	if (sdbc_err && sndr_err && ii_err)
	    return (err);
	else
	    return (0);

fail:
	(void) kstat_close(kc);
	return (err);
}

int
update()
{
	int err = 0;

	int sdbc_err = 0;
	int sndr_err = 0;
	int ii_err = 0;

	kstat_ctl_t *kc;

	if ((kc = kstat_open()) == NULL)
		goto fail;

	if (mode & SDBC) {
		sdbc_err = sdbc_update(kc);
		err = sdbc_err;
		if (sdbc_err && !(mode & MULTI))
			goto fail;
		if (sdbc_err && (mode & MULTI) && sdbc_err != EAGAIN)
			goto fail;
	}

	if (mode & SNDR) {
		sndr_err = sndr_update(kc);
		err = sndr_err;
		if (sndr_err && !(mode & MULTI))
			goto fail;
		if (sndr_err && (mode & MULTI) && sndr_err != EAGAIN)
			goto fail;
	}

	if (mode & IIMG) {
		ii_err = ii_update(kc);
		err = ii_err;
		if (ii_err && !(mode & MULTI))
			goto fail;
		if (ii_err && (mode & MULTI) && ii_err != EAGAIN)
			goto fail;
	}

	(void) kstat_close(kc);
	if (sdbc_err && sndr_err && ii_err)
	    return (err);
	else
	    return (0);

fail:
	(void) kstat_close(kc);
	return (err);
}

int
report()
{
	int err = 0;

	int sdbc_err = 0;
	int sndr_err = 0;
	int ii_err = 0;

	hflags &= (HEADERS_EXL | HEADERS_ATT | HEADERS_BOR);

	if (mode & SNDR)
		if (sndr_err = sndr_report())
		    err = sndr_err;

	if (mode & IIMG)
		if (ii_err = ii_report())
		    err = ii_err;

	if ((mode & SDBC) && !(mode & MULTI))
		if (sdbc_err = sdbc_report())
		    err = sdbc_err;

	return (err);
}
