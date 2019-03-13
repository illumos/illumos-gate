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
 *
 * Copyright 2019, Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <libnvpair.h>
#include <kstat.h>
#include <unistd.h>
#include <sys/types.h>
#include <fm/topo_mod.h>
#include <sys/devfm.h>
#include <fm/fmd_agent.h>

#define	BUFSZ	128

char *
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

int
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
	int ret;
	uint32_t offset;
	nvlist_t *args;

	topo_mod_dprintf(mod, "simple_dimm_label() called\n");
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

	if (store_prop_val(mod, buf, "label", out) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		/* topo errno already set */
		return (-1);
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
	int ret;
	uint32_t offset, dimms_per_chip;
	nvlist_t *args;

	topo_mod_dprintf(mod, "simple_dimm_label_mp() called\n");

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
	if ((ret = nvlist_lookup_uint32(args, "dimms_per_chip",
	    &dimms_per_chip)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'dimms_per_chip' arg "
		    "(%s)\n", strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if ((ret = nvlist_lookup_string(args, "order", &order)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'order' arg (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if ((fmtstr = get_fmtstr(mod, in)) == NULL) {
		topo_mod_dprintf(mod, "Failed to retrieve 'format' arg\n");
		topo_mod_free(mod, order, BUFSZ);
		/* topo errno already set */
		return (-1);
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
		topo_mod_free(mod, order, BUFSZ);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if (store_prop_val(mod, buf, "label", out) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		topo_mod_free(mod, order, BUFSZ);
		/* topo errno already set */
		return (-1);
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
	int ret;
	uint32_t offset;
	nvlist_t *args;
	tnode_t *chip;

	topo_mod_dprintf(mod, "seq_dimm_label() called\n");
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
	if ((ret = nvlist_lookup_string(args, "order", &order)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'order' arg (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if ((fmtstr = get_fmtstr(mod, in)) == NULL) {
		topo_mod_dprintf(mod, "Failed to retrieve 'format' arg\n");
		topo_mod_free(mod, order, BUFSZ);
		/* topo errno already set */
		return (-1);
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
		topo_mod_free(mod, order, BUFSZ);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if (store_prop_val(mod, buf, "label", out) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		topo_mod_free(mod, order, BUFSZ);
		/* topo errno already set */
		return (-1);
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
	int ret;
	uint32_t offset;
	nvlist_t *args;

	topo_mod_dprintf(mod, "simple_chip_label() called\n");
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

	if (store_prop_val(mod, buf, "label", out) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		/* topo errno already set */
		return (-1);
	}

	return (0);
}


/*
 * This is a somewhat generic property method for labelling the CPU sockets on
 * x86/x64 platforms.  This method assumes a correspondence between
 * the chip topo node instance number and the CPU socket label number.  It takes
 * the following argument:
 *
 * format:	a string containing a printf-like format with a single %d token
 *              which this method computes
 *
 *              i.e.: CPU %d
 *
 * offset:      a numeric offset that we'll number the CPU's from.  This is to
 *              allow for the fact that some systems number the CPU sockets
 *              from zero and others start from one (like the X8450 systems)
 */
/* ARGSUSED */
int
fsb2_chip_label(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *fmtstr, buf[BUFSZ];
	int ret;
	uint32_t offset;
	nvlist_t *args;

	topo_mod_dprintf(mod, "fsb2_chip_label() called\n");
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
	    ((topo_node_instance(node) / 2) + offset));

	if (store_prop_val(mod, buf, "label", out) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		/* topo errno already set */
		return (-1);
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
	if ((fmtstr = get_fmtstr(mod, in)) == NULL) {
		topo_mod_dprintf(mod, "Failed to retrieve 'format' arg\n");
		/* topo errno already set */
		return (-1);
	}
	/*
	 * The chip-properties property will not exist if this platform has
	 * AMD family 0x10 modules.  In that case we don't want to treat it as a
	 * fatal error as that will cause calls like topo_prop_getprops to fail
	 * to return any properties on this node.  Therefore, if the topo errno
	 * is set to ETOPO_PROP_NOENT, then we'll just set an empty label
	 * and return 0.  If the topo errno is set to anything else we'll
	 * return -1.
	 */
	if (topo_prop_get_uint32(node, "chip-properties", "CoherentNodes",
	    &num_nodes, &err) != 0) {
		if (err == ETOPO_PROP_NOENT) {
			if (store_prop_val(mod, "", "label", out) != 0) {
				topo_mod_dprintf(mod, "Failed to set label\n");
				/* topo errno already set */
				return (-1);
			}
			return (0);
		} else {
			topo_mod_dprintf(mod, "Failed to lookup 'CoherentNodes'"
			    "property\n");
			return (topo_mod_seterrno(mod, err));
		}
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

	if (store_prop_val(mod, buf, "label", out) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		/* topo errno already set */
		return (-1);
	}

	return (0);
}

/*
 * Utility function used by a4fplus_chip_label to determine the number of chips
 * (as opposed to processors) that are installed in the system by counting
 * the unique chipids.
 */
static int
get_num_chips(topo_mod_t *mod)
{
	fmd_agent_hdl_t *hdl;
	nvlist_t **cpus;
	uint_t ncpu;
	int i, nchip = 0;
	int32_t chipid;
	uint64_t bitmap = 0;

	if ((hdl = fmd_agent_open(FMD_AGENT_VERSION)) == NULL)
		return (-1);
	if (fmd_agent_physcpu_info(hdl, &cpus, &ncpu) == -1) {
		topo_mod_dprintf(mod, "get physcpu info failed:%s\n",
		    fmd_agent_errmsg(hdl));
		fmd_agent_close(hdl);
		return (-1);
	}
	fmd_agent_close(hdl);

	for (i = 0; i < ncpu; i++) {
		if (nvlist_lookup_int32(cpus[i], FM_PHYSCPU_INFO_CHIP_ID,
		    &chipid) != 0 || chipid >= 64) {
			topo_mod_dprintf(mod, "lookup chipid failed\n");
			nchip = -1;
			break;
		}
		if ((bitmap & (1ULL << chipid)) != 0) {
			bitmap |= (1ULL << chipid);
			nchip++;
		}
	}

	for (i = 0; i < ncpu; i++)
		nvlist_free(cpus[i]);
	umem_free(cpus, sizeof (nvlist_t *) * ncpu);

	return (nchip);
}

/*
 * This is a custom property method for generating the CPU slot label for the
 * Andromeda Fplus platforms.
 *
 * format:	a string containing a printf-like format with a single %d token
 *              which this method computes
 *
 *              i.e.: CPU %d
 */
/* ARGSUSED */
int
a4fplus_chip_label(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *fmtstr, buf[BUFSZ];
	int num_nodes;

	topo_mod_dprintf(mod, "a4fplus_chip_label() called\n");
	if ((fmtstr = get_fmtstr(mod, in)) == NULL) {
		topo_mod_dprintf(mod, "Failed to retrieve 'format' arg\n");
		/* topo errno already set */
		return (-1);
	}

	/*
	 * Normally we'd figure out the total number of chip nodes by looking
	 * at the CoherentNodes property.  However, due to the lack of a memory
	 * controller driver for family 0x10, this property wont exist on the
	 * chip nodes on A4Fplus.
	 */
	if ((num_nodes = get_num_chips(mod)) < 0) {
		topo_mod_dprintf(mod, "Failed to determine number of chip "
		    "nodes\n");
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}
	switch (num_nodes) {
		case (2):
			/* LINTED: E_SEC_PRINTF_VAR_FMT */
			(void) snprintf(buf, BUFSZ, fmtstr,
			    topo_node_instance(node) + 2);
			break;
		case (4):
			/* LINTED: E_SEC_PRINTF_VAR_FMT */
			(void) snprintf(buf, BUFSZ, fmtstr,
			    topo_node_instance(node));
			break;
		default:
			topo_mod_dprintf(mod, "Invalid number of chip nodes:"
			    " %d\n", num_nodes);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}


	if (store_prop_val(mod, buf, "label", out) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		/* topo errno already set */
		return (-1);
	}

	return (0);
}

/*
 * This is a somewhat generic property method for labelling the chip-select
 * nodes on multi-socket AMD family 0x10 platforms.  This is necessary because
 * these platforms are not supported by the current AMD memory controller driver
 * and therefore we're not able to discover the memory topology on AMD family
 * 0x10 systems.  As a result, instead of enumerating the installed dimms and
 * their ranks, the chip enumerator generically enumerates all of the possible
 * chip-selects beneath each dram channel.
 *
 * When we diagnose a dimm fault, the FRU fmri will be for the chip-select node,
 * so we need to attach FRU labels to the chip-select nodes.
 *
 * format:	a string containing a printf-like format with a two %d tokens
 *              for the cpu and dimm slot label numbers, which this method
 *              computes
 *
 *              i.e.: CPU %d DIMM %d
 *
 * offset:      a numeric offset that we'll number the dimms from.  This is to
 *              allow for the fact that some systems may number the dimm slots
 *              from zero while others may start from one
 *
 * This function computes the DIMM slot number using the following formula:
 *
 *	slot = cs - (cs % 2) + channel + offset
 */
/* ARGSUSED */
int
simple_cs_label_mp(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *fmtstr, buf[BUFSZ];
	tnode_t *chip, *chan;
	int dimm_num, ret;
	uint32_t offset;
	nvlist_t *args;

	topo_mod_dprintf(mod, "simple_cs_label_mp() called\n");

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

	chip = topo_node_parent(topo_node_parent(topo_node_parent(node)));
	chan = topo_node_parent(node);

	dimm_num = topo_node_instance(node) - (topo_node_instance(node) % 2)
	    + topo_node_instance(chan) + offset;
	/* LINTED: E_SEC_PRINTF_VAR_FMT */
	(void) snprintf(buf, BUFSZ, fmtstr, topo_node_instance(chip),
	    dimm_num);

	if (store_prop_val(mod, buf, "label", out) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		/* topo errno already set */
		return (-1);
	}

	return (0);
}

/* ARGSUSED */
int
g4_dimm_label(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *fmtstr, *chip_lbl, buf[BUFSZ];
	tnode_t *chip;
	int ret, err = 0;
	uint32_t offset;
	nvlist_t *args;

	topo_mod_dprintf(mod, "g4_dimm_label() called\n");

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

	/*
	 * The 4600/4600M2 have a weird way of labeling the chip nodes, so
	 * instead of trying to recompute it, we'll simply look it up and
	 * prepend it to our dimm label.
	 */
	chip = topo_node_parent(topo_node_parent(node));
	if (topo_prop_get_string(chip, TOPO_PGROUP_PROTOCOL, "label", &chip_lbl,
	    &err) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup label prop on %s=%d\n",
		    topo_node_name(chip), topo_node_instance(chip),
		    topo_strerror(err));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	/* LINTED: E_SEC_PRINTF_VAR_FMT */
	(void) snprintf(buf, BUFSZ, fmtstr, chip_lbl,
	    (topo_node_instance(node) + offset));

	topo_mod_strfree(mod, chip_lbl);

	if (store_prop_val(mod, buf, "label", out) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		/* topo errno already set */
		return (-1);
	}

	return (0);
}

/*
 * This method is used to compute the labels for DIMM slots on the Galaxy 1F and
 * 2F platforms.  It results in following dimm node label assignments:
 *
 * chip/dimm instances      label
 * -------------------      -----
 * chip=0/dimm=0            CPU 1 DIMM A0
 * chip=0/dimm=1            CPU 1 DIMM B0
 * chip=0/dimm=2            CPU 1 DIMM A1
 * chip=0/dimm=3            CPU 1 DIMM B1
 *
 * chip=1/dimm=0            CPU 2 DIMM A0
 * chip=1/dimm=1            CPU 2 DIMM B0
 * chip=1/dimm=2            CPU 2 DIMM A1
 * chip=1/dimm=3            CPU 2 DIMM B1
 */
/* ARGSUSED */
int
g12f_dimm_label(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *fmtstr, buf[BUFSZ], chan;
	tnode_t *chip;
	int ret, dimm_inst, slot_num;
	nvlist_t *args;

	topo_mod_dprintf(mod, "g12f_dimm_label() called\n");

	if ((ret = nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'args' list (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if ((fmtstr = get_fmtstr(mod, in)) == NULL) {
		topo_mod_dprintf(mod, "Failed to retrieve 'format' arg\n");
		/* topo errno already set */
		return (-1);
	}

	chip = topo_node_parent(topo_node_parent(node));
	dimm_inst = topo_node_instance(node);
	chan = dimm_inst == 0 || dimm_inst == 2 ? 'A': 'B';
	slot_num = (dimm_inst <= 1 ? 0 : 1);

	/* LINTED: E_SEC_PRINTF_VAR_FMT */
	(void) snprintf(buf, BUFSZ, fmtstr, topo_node_instance(chip) + 1, chan,
	    slot_num);

	if (store_prop_val(mod, buf, "label", out) != 0) {
		topo_mod_dprintf(mod, "Failed to set label\n");
		/* topo errno already set */
		return (-1);
	}

	return (0);
}
