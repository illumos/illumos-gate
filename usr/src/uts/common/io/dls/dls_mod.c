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
 * Data-Link Services Module
 */

#include	<sys/modctl.h>
#include	<sys/dld_impl.h>

static struct modlmisc		i_dls_modlmisc = {
	&mod_miscops,
	DLS_INFO
};

static struct modlinkage	i_dls_modlinkage = {
	MODREV_1,
	&i_dls_modlmisc,
	NULL
};

/*
 * Module initialization functions.
 */

static void
i_dls_mod_init(void)
{
	dls_link_init();
	dls_mgmt_init();
}

static int
i_dls_mod_fini(void)
{
	int	err;

	if ((err = dls_link_fini()) != 0)
		return (err);

	dls_mgmt_fini();
	return (0);
}

/*
 * modlinkage functions.
 */

int
_init(void)
{
	int	err;

	i_dls_mod_init();

	if ((err = mod_install(&i_dls_modlinkage)) != 0) {
		(void) i_dls_mod_fini();
		return (err);
	}

#ifdef	DEBUG
	cmn_err(CE_NOTE, "!%s loaded", DLS_INFO);
#endif	/* DEBUG */

	return (0);
}

int
_fini(void)
{
	int	err;

	if ((err = i_dls_mod_fini()) != 0)
		return (err);

	if ((err = mod_remove(&i_dls_modlinkage)) != 0)
		return (err);

#ifdef	DEBUG
	cmn_err(CE_NOTE, "!%s unloaded", DLS_INFO);
#endif	/* DEBUG */

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&i_dls_modlinkage, modinfop));
}
