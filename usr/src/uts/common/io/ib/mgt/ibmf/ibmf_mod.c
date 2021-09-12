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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file implements the _init(9e), _info(9e) and _fini(9e) functions.
 */

#include <sys/ib/mgt/ibmf/ibmf_impl.h>

/* Module Info */
static struct modlmisc ibmf_modlmisc = {
	&mod_miscops,
	"IB Agent Interfaces 2.0"
};

/* Module linkage */
static struct modlinkage ibmf_modlinkage = {
	MODREV_1,
	&ibmf_modlmisc,
	NULL
};

static ibmf_state_t		ibmf_state;
ibmf_state_t			*ibmf_statep;

extern int ibmf_init();
extern int ibmf_fini();
extern int ibmf_saa_impl_init();
extern int ibmf_saa_impl_fini();

int
_init()
{
	int status;

	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	ibmf_statep = &ibmf_state;

	/*
	 * call ibmf_saa_init first so it can set up subnet list before being
	 * contacted with ibt_async events
	 */
	status = ibmf_saa_impl_init();
	if (status != IBMF_SUCCESS) {
		return (EACCES);
	}

	status = ibmf_init();
	if (status != 0) {
		(void) ibmf_saa_impl_fini();

		return (EACCES);
	}

	status = mod_install(&ibmf_modlinkage);
	if (status != 0) {
		(void) ibmf_fini();
		ibmf_statep = NULL;
	}

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ibmf_modlinkage, modinfop));
}

int
_fini()
{
	int status;
	status = mod_remove(&ibmf_modlinkage);
	if (status != 0) {
		return (status);
	}

	status = ibmf_saa_impl_fini();
	if (status != 0) {
		return (status);
	}

	(void) ibmf_fini();
	ibmf_statep = NULL;
	return (status);
}
