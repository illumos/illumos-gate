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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

/*
 * s1394.c
 *    1394 Services Layer Initialization and Cleanup Routines
 *    The routines do all initialization and cleanup for the Sevices Layer
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/tnf_probe.h>

#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>

/* Driver State Pointer */
s1394_state_t *s1394_statep;

/* Module Driver Info */
static struct modlmisc s1394_modlmisc = {
	&mod_miscops,
	"IEEE 1394 Services Library 1.0"
};

/* Module Linkage */
static struct modlinkage s1394_modlinkage = {
	MODREV_1,
	&s1394_modlmisc,
	NULL
};

static int s1394_init();
static void s1394_fini();

#ifndef NPROBE
extern int tnf_mod_load(void);
extern int tnf_mod_unload(struct modlinkage *mlp);
#endif

int
_init()
{
	int status;

#ifndef	NPROBE
	(void) tnf_mod_load();
#endif
	status = s1394_init();
	if (status != 0) {
		TNF_PROBE_1(_init_error, S1394_TNF_SL_ERROR, "",
		    tnf_string, msg, "s1394: failed in s1394_init");
#ifndef NPROBE
		(void) tnf_mod_unload(&s1394_modlinkage);
#endif
		return (status);
	}

	status = mod_install(&s1394_modlinkage);
	if (status != 0) {
		TNF_PROBE_1(_init_error, S1394_TNF_SL_ERROR, "",
		    tnf_string, msg, "s1394: failed in mod_install");
#ifndef NPROBE
		(void) tnf_mod_unload(&s1394_modlinkage);
#endif
	}
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&s1394_modlinkage, modinfop));
}

int
_fini()
{
	int status;

	status = mod_remove(&s1394_modlinkage);
	if (status != 0) {
		TNF_PROBE_1(_fini_error, S1394_TNF_SL_ERROR, "",
		    tnf_string, msg, "s1394: failed in mod_remove");
		return (status);
	}

	s1394_fini();
#ifndef NPROBE
	(void) tnf_mod_unload(&s1394_modlinkage);
#endif
	return (status);
}

/*
 * s1394_init()
 *    initializes the 1394 Software Framework's structures, i.e. the HAL list
 *    and associated mutex.
 */
static int
s1394_init()
{
	TNF_PROBE_0_DEBUG(s1394_init_enter, S1394_TNF_SL_STACK, "");

	s1394_statep = kmem_zalloc(sizeof (s1394_state_t), KM_SLEEP);

	s1394_statep->hal_head = NULL;
	s1394_statep->hal_tail = NULL;
	mutex_init(&s1394_statep->hal_list_mutex, NULL, MUTEX_DRIVER, NULL);

	TNF_PROBE_0_DEBUG(s1394_init_exit, S1394_TNF_SL_STACK, "");
	return (0);
}

/*
 * s1394_fini()
 *    cleans up the 1394 Software Framework's structures that were allocated
 *    in s1394_init().
 */
static void
s1394_fini()
{
	TNF_PROBE_0_DEBUG(s1394_fini_enter, S1394_TNF_SL_STACK, "");

	mutex_destroy(&s1394_statep->hal_list_mutex);

	kmem_free(s1394_statep, sizeof (s1394_state_t));

	TNF_PROBE_0_DEBUG(s1394_fini_exit, S1394_TNF_SL_STACK, "");
}
