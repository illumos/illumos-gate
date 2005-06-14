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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libproc.h"
#include <alloca.h>
#include <string.h>

/*
 * Convenience wrapper to set the cred attributes of a victim process
 * to a set of new values. Caller must supply a prochandle and a
 * fully populated prcred structure.
 */
int
Psetcred(struct ps_prochandle *Pr, const prcred_t *credp)
{
	int ngrp;
	int ctlsize;
	struct {
		long cmd;
		prcred_t cred;
	} *ctlp;

	if (Pr == NULL || credp == NULL)
		return (-1);

	ngrp = credp->pr_ngroups;
	ctlsize = sizeof (prcred_t) + (ngrp - 1) * sizeof (gid_t);
	ctlp = alloca(ctlsize + sizeof (long));

	ctlp->cmd = PCSCREDX;
	(void) memcpy(&ctlp->cred, credp, ctlsize);

	if (write(Pctlfd(Pr), ctlp, sizeof (long) + ctlsize) < 0)
		return (-1);

	return (0);
}

/*
 * Convenience wrapper to set the zoneid attribute of a victim process to a new
 * value (only to and from GLOBAL_ZONEID makes sense).  Caller must supply a
 * prochandle and a valid zoneid.
 */
int
Psetzoneid(struct ps_prochandle *Pr, zoneid_t zoneid)
{
	struct {
		long cmd;
		long zoneid;
	} ctl;

	if (Pr == NULL)
		return (-1);

	ctl.zoneid = zoneid;
	ctl.cmd = PCSZONE;

	if (write(Pctlfd(Pr), &ctl, sizeof (ctl)) < 0)
		return (-1);
	return (0);
}
