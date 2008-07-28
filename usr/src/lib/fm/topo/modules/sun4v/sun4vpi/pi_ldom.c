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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Open connections to the LDOM and Machine Description libraries used during
 * enumeration.
 */

#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <sys/mdesc.h>
#include <sys/fm/ldom.h>
#include <sys/systeminfo.h>

#include "pi_impl.h"

static topo_mod_t *Pi_mod;

static void pi_free(void *, size_t);
static void * pi_alloc(size_t);

/*
 * Initialize a connection to the LDOM machine description interface.
 */
int
pi_ldompri_open(topo_mod_t *mod, pi_enum_t *pip)
{
	if (mod == NULL || pip == NULL) {
		return (-1);
	}

	/*
	 * Store the module pointer for this session.  This file-global
	 * is used by the allocators called by libldom and libmdesc.
	 */
	Pi_mod = mod;

	/* Initialize the LDOM connection */
	pip->ldomp = ldom_init(pi_alloc, pi_free);
	if (pip->ldomp == NULL) {
		topo_mod_dprintf(mod,
		    "sun4vpi failed to initialize LDOM layer.\n");
		Pi_mod = NULL;
		return (-1);
	}

	/* Initialize the machine description layer for this ldom instance */
	pip->ldom_bufsize = ldom_get_core_md(pip->ldomp, &(pip->ldom_bufp));
	if (pip->ldom_bufsize < 1) {
		topo_mod_dprintf(mod, "ldom_get_core_md error: bufsize = %d\n",
		    pip->ldom_bufsize);
		ldom_fini(pip->ldomp);
		Pi_mod = NULL;
		return (-1);
	}

	/* Initialize the machine description internal layer */
	pip->mdp = md_init_intern(pip->ldom_bufp, pi_alloc, pi_free);
	if (pip->mdp == NULL ||
	    (pip->md_nodes = md_node_count(pip->mdp)) < 1) {
		topo_mod_dprintf(mod, "md_init_intern error\n");
		pi_free(pip->ldom_bufp, pip->ldom_bufsize);
		ldom_fini(pip->ldomp);
		Pi_mod = NULL;
		return (-1);
	}

	return (0);
}


/* ARGSUSED */
void
pi_ldompri_close(topo_mod_t *mod, pi_enum_t *pip)
{
	if (pip == NULL) {
		return;
	}

	/* Close the machine description connection */
	(void) md_fini(pip->mdp);

	/* Close the connection to the LDOM layer */
	ldom_fini(pip->ldomp);

	/* Free the ldom connection data */
	pi_free(pip->ldom_bufp, pip->ldom_bufsize);

	/* Reset the file-global module pointer */
	Pi_mod = NULL;
}


static void *
pi_alloc(size_t size)
{
	if (Pi_mod == NULL) {
		/* Cannot allocate memory without a module pointer */
		return (NULL);
	}
	return (topo_mod_alloc(Pi_mod, size));
}


static void
pi_free(void *buf, size_t size)
{
	if (Pi_mod == NULL) {
		/* Cannot free memory without a module pointer */
		return;
	}
	topo_mod_free(Pi_mod, buf, size);
}
