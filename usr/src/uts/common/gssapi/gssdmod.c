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
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <gssapi/kgssapi_defs.h>

static struct modlmisc modlmisc = {
	&mod_miscops, "in-kernel GSSAPI"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

int
_init()
{
	int retval;

	mutex_init(&gssrpcb_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&__kgss_mech_lock, NULL, MUTEX_DEFAULT, NULL);
	zone_key_create(&gss_zone_key, gss_zone_init, NULL, gss_zone_fini);

	if ((retval = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&__kgss_mech_lock);
		mutex_destroy(&gssrpcb_lock);
	}

	return (retval);
}

int
_fini()
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
