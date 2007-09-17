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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
get_fmtstr(topo_mod_t *mod, nvlist_t *in, int *err)
{
	char *fmtstr;
	nvlist_t *args;

	topo_mod_dprintf(mod, "get_fmtstr() called\n");

	if (nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'args' list (%s)\n",
		    strerror(errno));
		*err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		return (NULL);
	}
	if (nvlist_lookup_string(args, "format", &fmtstr) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'format' arg (%s)\n",
		    strerror(errno));
		*err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		nvlist_free(args);
		return (NULL);
	}
	return (fmtstr);
}

static int
store_prop_val(topo_mod_t *mod, char *buf, char *propname, nvlist_t **out)
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
	if (nvlist_add_uint32(*out, TOPO_PROP_VAL_TYPE, TOPO_TYPE_STRING)
	    != 0) {
		topo_mod_dprintf(mod, "Failed to set '%s'\n",
		    TOPO_PROP_VAL_TYPE);
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if (nvlist_add_string(*out, TOPO_PROP_VAL_VAL, buf) != 0) {
		topo_mod_dprintf(mod, "Failed to set '%s'\n",
		    TOPO_PROP_VAL_VAL);
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	return (0);
}

/*
 * This is a somewhat generic property method for labelling the dimm slots on
 * uni-socket x86/x64 platforms.  This method assumes a direct linear
 * correlation between the dimm topo node instance number and the dimm slot
 * label number.  It takes the following two arguments:
 *
 * format:	a string containing a printf-like format with a single %d token
 *              which this method computes
 *
 *              i.e.: DIMM %d
 *
 * offset:      a numeric offset that we'll number the dimms from.  This is to
 *              allow for the fact that some systems number the dimm slots
 *              from zero and others start from one (like the Ultra 20)
 */
/* ARGSUSED */
int
simple_dimm_label(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *fmtstr, buf[BUFSZ];
	int err;
	uint32_t offset;
	nvlist_t *args;

	topo_mod_dprintf(mod, "simple_dimm_label() called\n");
	if (nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'args' list (%s)\n",
		    strerror(errno));
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		return (err);
	}
	if (nvlist_lookup_uint32(args, "offset", &offset) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'offset' arg (%s)\n",
		    strerror(errno));
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		nvlist_free(args);
		return (err);
	}

	if ((fmtstr = get_fmtstr(mod, in, &err)) == NULL) {
		topo_mod_dprintf(mod, "Failed to retrieve format arg\n");
		nvlist_free(args);
		return (err);
	}

	/* LINTED: E_SEC_PRINTF_VAR_FMT */
	(void) snprintf(buf, BUFSZ, fmtstr,
	    (topo_node_instance(node) + offset));

	if ((err = store_prop_val(mod, buf, "label", out)) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		nvlist_free(args);
		return (err);
	}

	return (0);
}


/*
 * This is a somewhat generic property method for labelling the dimm slots on
 * multi-socket x86/x64 platforms.  It takes the following two arguments:
 *
 * format:	a string containing a printf-like format with a two %d tokens
 *              for the cpu and dimm slot label numbers, which this method
 *              computes
 *
 *              i.e.: CPU %d DIMM %d
 *
 * offset:      a numeric offset that we'll number the dimms from.  This is to
 *              allow for the fact that some systems number the dimm slots
 *              from zero while others may start from one
 *
 * order:	"reverse" or "forward" - sets the direction of the correlation
 *              between dimm topo node instance number and DIMM slot number
 *
 * dimms_per_chip:  the number of DIMM slots per chip
 */
/* ARGSUSED */
int
simple_dimm_label_mp(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *fmtstr, *order, buf[BUFSZ];
	tnode_t *chip;
	int err;
	uint32_t offset, dimms_per_chip;
	nvlist_t *args;

	topo_mod_dprintf(mod, "simple_dimm_label_mp() called\n");

	if (nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'args' list (%s)\n",
		    strerror(errno));
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		return (err);
	}
	if (nvlist_lookup_uint32(args, "offset", &offset) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'offset' arg (%s)\n",
		    strerror(errno));
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		nvlist_free(args);
		return (err);
	}
	if (nvlist_lookup_uint32(args, "dimms_per_chip", &dimms_per_chip)
	    != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'dimms_per_chip' arg "
		    "(%s)\n", strerror(errno));
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		nvlist_free(args);
		return (err);
	}
	if (nvlist_lookup_string(args, "order", &order) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'order' arg (%s)\n",
		    strerror(errno));
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		nvlist_free(args);
		return (err);
	}
	if ((fmtstr = get_fmtstr(mod, in, &err)) == NULL) {
		topo_mod_dprintf(mod, "Failed to retrieve 'format' arg\n");
		topo_mod_free(mod, order, BUFSZ);
		nvlist_free(args);
		return (err);
	}

	chip = topo_node_parent(topo_node_parent(node));

	if (strcasecmp(order, "forward") == 0)
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		(void) snprintf(buf, BUFSZ, fmtstr, topo_node_instance(chip),
		    (topo_node_instance(node) + offset));
	else if (strcasecmp(order, "reverse") == 0)
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		(void) snprintf(buf, BUFSZ, fmtstr, topo_node_instance(chip),
		    (((topo_node_instance(chip) + 1) * dimms_per_chip)
		    - (topo_node_instance(node)) - 1 + offset));
	else {
		topo_mod_dprintf(mod, "Invalid value for order arg\n");
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		topo_mod_free(mod, order, BUFSZ);
		nvlist_free(args);
		return (err);
	}

	if ((err = store_prop_val(mod, buf, "label", out)) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		topo_mod_free(mod, order, BUFSZ);
		nvlist_free(args);
		return (err);
	}

	return (0);
}

/*
 * This method assumes a correspondence between the dimm topo node instance
 * number and the dimm slot label number, but unlike simple_chip_label_mp, the
 * slot numbers aren't reused between CPU's.  This method assumes there
 * are 4 DIMM slots per chip.  It takes the following two arguments:
 *
 * format:	a string containing a printf-like format with a single %d token
 *              which this method computes
 *
 *              i.e.: DIMM %d
 *
 * offset:      a numeric offset that we'll number the dimms from.  This is to
 *              allow for the fact that some systems number the dimm slots
 *              from zero and others may start from one
 *
 * order:	"reverse" or "forward" - sets the direction of the correlation
 *              between dimm topo node instance number and DIMM slot number
 */
/* ARGSUSED */
int
seq_dimm_label(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *fmtstr, *order, buf[BUFSZ];
	int err;
	uint32_t offset;
	nvlist_t *args;
	tnode_t *chip;

	topo_mod_dprintf(mod, "seq_dimm_label() called\n");
	if (nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'args' list (%s)\n",
		    strerror(errno));
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		return (err);
	}
	if (nvlist_lookup_uint32(args, "offset", &offset) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'offset' arg (%s)\n",
		    strerror(errno));
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		nvlist_free(args);
		return (err);
	}
	if (nvlist_lookup_string(args, "order", &order) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'order' arg (%s)\n",
		    strerror(errno));
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		nvlist_free(args);
		return (err);
	}

	if ((fmtstr = get_fmtstr(mod, in, &err)) == NULL) {
		topo_mod_dprintf(mod, "Failed to retrieve 'fmtstr' arg\n");
		topo_mod_free(mod, order, BUFSZ);
		nvlist_free(args);
		return (err);
	}

	chip = topo_node_parent(topo_node_parent(node));

	if (strcasecmp(order, "forward") == 0)
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		(void) snprintf(buf, BUFSZ, fmtstr, ((topo_node_instance(node))
		    + (topo_node_instance(chip) * 4) + offset));
	else if (strcasecmp(order, "reverse") == 0)
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		(void) snprintf(buf, BUFSZ, fmtstr,
		    (((topo_node_instance(chip) + 1) * 4)
		    - (topo_node_instance(node)) - 1 + offset));
	else {
		topo_mod_dprintf(mod, "Invalid value for order arg\n");
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		topo_mod_free(mod, order, BUFSZ);
		nvlist_free(args);
		return (err);
	}

	if ((err = store_prop_val(mod, buf, "label", out)) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		topo_mod_free(mod, order, BUFSZ);
		nvlist_free(args);
		return (err);
	}

	return (0);
}


/*
 * This is a somewhat generic property method for labelling the CPU sockets on
 * x86/x64 platforms.  This method assumes a correspondence between
 * the chip topo node instance number and the CPU socket label number.  It takes
 * the following two arguments:
 *
 * format:	a string containing a printf-like format with a single %d token
 *              which this method computes
 *
 *              i.e.: CPU %d
 *
 * offset:      a numeric offset that we'll number the CPU's from.  This is to
 *              allow for the fact that some systems number the CPU sockets
 *              from zero and others start from one (like the X4X00-M2 systems)
 */
/* ARGSUSED */
int
simple_chip_label(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *fmtstr, buf[BUFSZ];
	int err;
	uint32_t offset;
	nvlist_t *args;

	topo_mod_dprintf(mod, "simple_chip_label() called\n");
	if (nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'args' list (%s)\n",
		    strerror(errno));
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		return (err);
	}
	if (nvlist_lookup_uint32(args, "offset", &offset) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'offset' arg (%s)\n",
		    strerror(errno));
		err = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		nvlist_free(args);
		return (err);
	}

	if ((fmtstr = get_fmtstr(mod, in, &err)) == NULL) {
		topo_mod_dprintf(mod, "Failed to retrieve format arg\n");
		nvlist_free(args);
		return (err);
	}

	/* LINTED: E_SEC_PRINTF_VAR_FMT */
	(void) snprintf(buf, BUFSZ, fmtstr,
	    (topo_node_instance(node) + offset));

	if ((err = store_prop_val(mod, buf, "label", out)) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		nvlist_free(args);
		return (err);
	}

	return (0);
}


/*
 * This is a custom property method for generating the CPU slot label for the
 * Galaxy 4E/4F platforms.
 *
 * format:	a string containing a printf-like format with a single %c token
 *              which this method computes
 *
 *              i.e.: CPU %c
 */
/* ARGSUSED */
int
g4_chip_label(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *fmtstr, buf[BUFSZ], slot_id;
	int err, htid, mapidx;
	uint32_t num_nodes;
	/*
	 * G4 HT node ID to FRU label translation.  The g4map array
	 * is indexed by (number of coherent nodes) / 2 - 1.
	 * The value for a given number of nodes is a char array
	 * indexed by node ID.
	 */
	const char *g4map[] = {
	    "AB",	/* 2 nodes */
	    "ADEH",	/* 4 nodes */
	    "ABDEFH",	/* 6 nodes */
	    "ACBDEFGH"	/* 8 nodes */
	};

	topo_mod_dprintf(mod, "g4_chip_label() called\n");
	if ((fmtstr = get_fmtstr(mod, in, &err)) == NULL) {
		topo_mod_dprintf(mod, "Failed to retrieve 'format' arg\n");
		return (err);
	}

	if (topo_prop_get_uint32(node, "chip-properties", "CoherentNodes",
	    &num_nodes, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'CoherentNodes'"
		    "property\n");
		return (err);
	}

	mapidx = num_nodes / 2 - 1;
	htid = topo_node_instance(node);

	/* HT nodes must number 0 .. num_nodes - 1 */
	if (htid >= num_nodes) {
		topo_mod_dprintf(mod, "chip node instance range check failed:"
		    "num_nodes=%d, instance=%d\n", num_nodes, htid);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	switch (num_nodes) {
		case (2):
		case (4):
		case (6):
		case (8):
			/* htid is already range-checked */
			mapidx = num_nodes / 2 - 1;
			slot_id = g4map[mapidx][htid];
			break;
		default:
			topo_mod_dprintf(mod, "Invalid number of CoherentNodes:"
			    " %d\n", num_nodes);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	/* LINTED: E_SEC_PRINTF_VAR_FMT */
	(void) snprintf(buf, BUFSZ, fmtstr, slot_id);

	if ((err = store_prop_val(mod, buf, "label", out)) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		return (err);
	}

	return (0);
}
