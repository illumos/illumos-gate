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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SUNW,Sun-Fire platform ioboard topology enumerator
 */

#include <string.h>
#include <libdevinfo.h>
#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>

#include <ioboard.h>
#include <hostbridge.h>
#include <util.h>

#define	IOBOARD	"ioboard"
#define	LABEL	"IOBD"
#define	IOBDFRU	"hc:///component="LABEL
#define	ERIE	"SUNW,Sun-Fire-T1000"
#define	HB_MAX	1

/*ARGSUSED*/
int
platform_iob_label(tnode_t *node, nvlist_t *ignored, nvlist_t **out,
    topo_mod_t *mod)
{
	return (0);
}

static tnode_t *
iob_node_create(tnode_t *parent, topo_mod_t *mod)
{
	int err;
	tnode_t *ion;
	nvlist_t *fmri, *args = NULL, *pfmri = NULL;
	topo_hdl_t *thp = topo_mod_handle(mod);

	(void) topo_node_resource(parent, &pfmri, &err);
	if (pfmri != NULL) {
		if (topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0 ||
		    nvlist_add_nvlist(args, TOPO_METH_FMRI_ARG_PARENT, pfmri)
		    != 0) {
			nvlist_free(pfmri);
			nvlist_free(args);
			(void) topo_mod_seterrno(mod, EMOD_FMRI_NVL);
			return (NULL);
		}
		nvlist_free(pfmri);
	}

	if ((fmri = topo_fmri_create(thp, FM_FMRI_SCHEME_HC, IOBOARD, 0, args,
		&err)) == NULL) {
		topo_mod_dprintf(mod, "creation of tnode for ioboard=0 "
		    "failed: %s\n", topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		nvlist_free(args);
		return (NULL);
	}
	nvlist_free(args);
	ion = topo_node_bind(mod, parent, IOBOARD, 0, fmri, NULL);
	if (ion == NULL) {
		nvlist_free(fmri);
		topo_mod_dprintf(mod, "unable to bind ioboard=0: %s",
		    topo_strerror(topo_mod_errno(mod)));
		return (NULL); /* mod_errno already set */
	}
	nvlist_free(fmri);

	if (topo_fmri_str2nvl(thp, IOBDFRU, &fmri, &err) == 0) {
		(void) topo_node_fru_set(ion, fmri, 0, &err);
		nvlist_free(fmri);
	}
	(void) topo_node_label_set(ion, "IOBD", &err);

	return (ion);
}

/*ARGSUSED*/
int
platform_iob_enum(tnode_t *parent, topo_instance_t imin, topo_instance_t imax,
    did_hash_t *didhash, di_prom_handle_t promtree, topo_mod_t *mod)
{
	int err;
	tnode_t *ion;
	char *plat;

	if (topo_prop_get_string(parent,
	    TOPO_PGROUP_SYSTEM, TOPO_PROP_PLATFORM, &plat, &err) < 0) {
		return (topo_mod_seterrno(mod, err));
	}

	/*
	 * The SUNW,SunFireT1000 (Erie) platform links in the SUNW,SunFireT200
	 * (Ontario) top-level /usr/platform/SUNW,SunFireT200 and its
	 * hc-topology. Unfortunately, the SUNW,SunFireT1000 does not contain an
	 * ioboard.  For SUNW,SunFireT1000 systems, we must begin the I/O
	 * topology directly below the motherboard.
	 *
	 * To further the mess, on the SUNW,SunFireT200 (Ontario) platform, a
	 * mistake was made with the topology defintion.  The ioboard was made
	 * a peer to the motherboard.  This is incorrect in terms of
	 * what we allow for an hc topology according the Fault
	 * Managed Resources specification and what is physically
	 * possible in the system.  Nevertheless, a change to
	 * the topology will result in mis-diagnoses for systems
	 * that have already shipped. In the interest of backward
	 * compatibility, we continue to allow the
	 * ioboard to be a peer to the motherboard SUNW,SunFireT200 systems.
	 */
	if (strcmp(plat, ERIE) == 0) {
		if (strcmp(topo_node_name(parent), "motherboard") != 0) {
			topo_mod_strfree(mod, plat);
			return (0);
		}
		ion = parent;
	} else if (strcmp(topo_node_name(parent), "motherboard") == 0) {
		topo_mod_strfree(mod, plat);
		return (0);
	} else {
		ion = iob_node_create(parent, mod);
	}

	topo_mod_strfree(mod, plat);

	if (ion == NULL) {
		topo_mod_dprintf(mod, "Enumeration of ioboard failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		return (-1); /* mod_errno already set */
	}

	if (child_range_add(mod, ion, HOSTBRIDGE, 0, HB_MAX) < 0 ||
	    topo_mod_enumerate(mod, ion, HOSTBRIDGE, HOSTBRIDGE, 0, HB_MAX)
	    < 0) {
		topo_mod_dprintf(mod, "Enumeration of %s=%d "
		    "failed: %s\n", HOSTBRIDGE, 0,
		    topo_strerror(topo_mod_errno(mod)));
		return (-1); /* mod_errno already set */
	}

	return (0);
}
