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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#ifndef	NPROBE
extern int tnf_mod_load(void);
extern int tnf_mod_unload(struct modlinkage *mlp);
#endif

int
_init()
{
	int status;

	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

#ifndef	NPROBE
	(void) tnf_mod_load();
#endif
	ibmf_statep = &ibmf_state;

	/*
	 * call ibmf_saa_init first so it can set up subnet list before being
	 * contacted with ibt_async events
	 */
	status = ibmf_saa_impl_init();
	if (status != IBMF_SUCCESS) {
		TNF_PROBE_1(_init_error, IBMF_TNF_ERROR, "", tnf_string, msg,
		    "ibmf_saa_impl_init failed");

#ifndef	NPROBE
		(void) tnf_mod_unload(&ibmf_modlinkage);
#endif
		return (EACCES);
	}



	status = ibmf_init();
	if (status != 0) {
		TNF_PROBE_1(_init_error, IBMF_TNF_ERROR, "", tnf_string, msg,
		    "ibmf_init failed");

		(void) ibmf_saa_impl_fini();

#ifndef	NPROBE
		(void) tnf_mod_unload(&ibmf_modlinkage);
#endif
		return (EACCES);
	}

	status = mod_install(&ibmf_modlinkage);
	if (status != 0) {
		TNF_PROBE_2(_init_error, IBMF_TNF_ERROR, "", tnf_string, msg,
		    "mod_install failed", tnf_uint, status, status);
#ifndef NPROBE
		(void) tnf_mod_unload(&ibmf_modlinkage);
#endif
		(void) ibmf_fini();
		ibmf_statep = (ibmf_state_t *)NULL;
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
		TNF_PROBE_2(_fini_error, IBMF_TNF_ERROR, "", tnf_string, msg,
		    "mod_remove failed", tnf_uint, status, status);
		return (status);
	}

	status = ibmf_saa_impl_fini();
	if (status != 0) {

		TNF_PROBE_2(_fini_error, IBMF_TNF_ERROR, "", tnf_string, msg,
		    "ibmf_saa fini failed", tnf_uint, status, status);
		return (status);
	}

	(void) ibmf_fini();
	ibmf_statep = (ibmf_state_t *)NULL;
#ifndef	NPROBE
	(void) tnf_mod_unload(&ibmf_modlinkage);
#endif
	return (status);
}
