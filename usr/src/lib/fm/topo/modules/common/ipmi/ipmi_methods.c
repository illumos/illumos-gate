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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <fm/topo_mod.h>

#define	BUFSZ	128

static char *
get_fmtstr(topo_mod_t *mod, nvlist_t *in)
{
	char *fmtstr;
	nvlist_t *args;
	int ret;

	topo_mod_dprintf(mod, "get_fmtstr() called\n");

	if ((ret = nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'args' list (%s)\n",
		    strerror(ret));
		(void) topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		return (NULL);
	}
	if ((ret = nvlist_lookup_string(args, "format", &fmtstr)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'format' arg (%s)\n",
		    strerror(ret));
		(void) topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		return (NULL);
	}
	return (fmtstr);
}

static int
store_prop_val(topo_mod_t *mod, void *buf, char *propname, topo_type_t type,
    nvlist_t **out)
{
	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	if (nvlist_add_string(*out, TOPO_PROP_VAL_NAME, propname) != 0) {
		topo_mod_dprintf(mod, "Failed to set '%s'\n",
		    TOPO_PROP_VAL_NAME);
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if (nvlist_add_uint32(*out, TOPO_PROP_VAL_TYPE, type)
	    != 0) {
		topo_mod_dprintf(mod, "Failed to set '%s'\n",
		    TOPO_PROP_VAL_TYPE);
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if (type == TOPO_TYPE_STRING) {
		if (nvlist_add_string(*out, TOPO_PROP_VAL_VAL, (char *)buf)
		    != 0) {
			topo_mod_dprintf(mod, "Failed to set '%s'\n",
			    TOPO_PROP_VAL_VAL);
			nvlist_free(*out);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}
	} else if (type == TOPO_TYPE_FMRI) {
		if (nvlist_add_nvlist(*out, TOPO_PROP_VAL_VAL, (nvlist_t *)buf)
		    != 0) {
			topo_mod_dprintf(mod, "Failed to set '%s'\n",
			    TOPO_PROP_VAL_VAL);
			nvlist_free(*out);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}
	} else if (type == TOPO_TYPE_UINT32) {
		if (nvlist_add_uint32(*out, TOPO_PROP_VAL_VAL, *(uint32_t *)buf)
		    != 0) {
			topo_mod_dprintf(mod, "Failed to set '%s'\n",
			    TOPO_PROP_VAL_VAL);
			nvlist_free(*out);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}
	}
	return (0);
}

/*
 * This is a somewhat generic property method for labelling the PSU and fan
 * FRU's that we're enumerating.  It takes the following three arguments:
 *
 * format:	a string containing a printf-like format with a two %d tokens
 *              for the cpu and dimm slot label numbers, which this method
 *              computes
 *
 *              i.e.: Fan %d
 *
 * offset:      a numeric offset that we'll number the FRU's from.  This is to
 *              allow for the fact that some systems may number the FRU's
 *              from zero while others may start from one
 */
/* ARGSUSED */
int
ipmi_fru_label(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *fmtstr, buf[BUFSZ];
	int ret;
	uint32_t offset;
	nvlist_t *args;

	topo_mod_dprintf(mod, "ipmi_fru_label() called\n");
	if ((ret = nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'args' list (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if ((ret = nvlist_lookup_uint32(args, "offset", &offset)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'offset' arg (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if ((fmtstr = get_fmtstr(mod, in)) == NULL) {
		topo_mod_dprintf(mod, "Failed to retrieve 'format' arg\n");
		/* topo errno already set */
		return (-1);
	}

	/* LINTED: E_SEC_PRINTF_VAR_FMT */
	(void) snprintf(buf, BUFSZ, fmtstr,
	    (topo_node_instance(node) + offset));

	if (store_prop_val(mod, (void *)buf, "label", TOPO_TYPE_STRING, out)
	    != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		/* topo errno already set */
		return (-1);
	}

	return (0);
}
/*
 * This is a somewhat generic property method for attaching a FRU fmri onto
 * a power supply or fan based on the assumption that the FRU will either be
 * the fan/psu itself or the parent node.
 *
 * entity:	either "self" or "parent"
 */
/* ARGSUSED */
int
ipmi_fru_fmri(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *entity;
	int ret, err;
	nvlist_t *args, *fru;

	topo_mod_dprintf(mod, "ipmi_fru_fmri() called\n");
	if ((ret = nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'args' list (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if ((ret = nvlist_lookup_string(args, "entity", &entity)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'entity' arg (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if (strcasecmp(entity, "self") == 0) {
		if (topo_node_resource(node, &fru, &err) != 0)
			return (-1);
	} else if (strcasecmp(entity, "parent") == 0) {
		if (topo_node_resource(topo_node_parent(node), &fru, &err) != 0)
			return (-1);
	} else {
		topo_mod_dprintf(mod, "Invalid 'entity' value\n");
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if (store_prop_val(mod, (void *)fru, "FRU", TOPO_TYPE_FMRI, out) != 0) {
		nvlist_free(fru);
		topo_mod_dprintf(mod, "Failed to set FRU\n");
		/* topo errno already set */
		return (-1);
	}

	nvlist_free(fru);

	return (0);
}
