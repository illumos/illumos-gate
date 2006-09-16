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

#include <mdb/mdb_modapi.h>

#include <libuutil.h>
#include <libuutil_impl.h>

#include <librestart_priv.h>		/* instance_data_t */
#include <startd.h>


/*
 * To count the elements of a uu_list_t without knowing its implementation, we
 * must walk & count them.
 */
/* ARGSUSED */
static int
inc_sz(uintptr_t addr, const void *unknown, void *data)
{
	size_t *sz = data;

	++(*sz);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
startd_status(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uu_list_t *dgraphp;
	restarter_instance_list_t ril;
	u_longlong_t ns_total;
	u_longlong_t lookups;
	u_longlong_t dep_inserts, dep_cycle_ns, dep_insert_ns;
	size_t graph_num, restarter_num;

	if (mdb_readvar(&lookups, "dictionary_lookups") == -1) {
		mdb_warn("failed to read 'dictionary_lookups' value\n");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&ns_total, "dictionary_ns_total") == -1) {
		mdb_warn("failed to read 'dictionary_ns_total' value\n");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&dep_inserts, "dep_inserts") == -1) {
		mdb_warn("failed to read 'dep_inserts' value\n");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&dep_cycle_ns, "dep_cycle_ns") == -1) {
		mdb_warn("failed to read 'dep_cycle_ns' value\n");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&dep_insert_ns, "dep_insert_ns") == -1) {
		mdb_warn("failed to read 'dep_insert_ns' value\n");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&dgraphp, "dgraph") == -1) {
		mdb_warn("failed to read 'dgraph' value\n");
		return (DCMD_ERR);
	}

	graph_num = 0;
	if (mdb_pwalk("uu_list_node", inc_sz, &graph_num,
	    (uintptr_t)dgraphp) == -1) {
		mdb_warn("failed to read uu_list\n");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&ril, "instance_list") == -1) {
		mdb_warn("failed to read 'instance_list' value\n");
		return (DCMD_ERR);
	}

	restarter_num = 0;
	if (mdb_pwalk("uu_list_node", inc_sz, &restarter_num,
	    (uintptr_t)ril.ril_instance_list) == -1) {
		mdb_warn("failed to read uu_list\n");
		return (DCMD_ERR);
	}

	mdb_printf(
	    "         dictionary lookups: %llu\n"
	    "        average lookup time: %llu us\n"
	    "graph dependency insertions: %llu\n"
	    "   average cycle-check time: %llu us\n"
	    " avg dependency insert time: %llu us\n"
	    "number of nodes in dgraph: %llu\n"
	    "number of nodes in instance_list: %llu\n", lookups,
	    lookups ? ns_total / (1000 * lookups) : 0, dep_inserts,
	    dep_inserts ? dep_cycle_ns / (1000 * dep_inserts) : 0,
	    dep_inserts ? dep_insert_ns / (1000 * dep_inserts) : 0,
	    (u_longlong_t)graph_num, (u_longlong_t)restarter_num);

	return (DCMD_OK);
}

static char
xstate2chr(restarter_instance_state_t s)
{
	switch (s) {
	case RESTARTER_STATE_UNINIT:	return ('u');
	case RESTARTER_STATE_DISABLED:	return ('d');
	case RESTARTER_STATE_OFFLINE:	return ('0');
	case RESTARTER_STATE_DEGRADED:	return ('D');
	case RESTARTER_STATE_ONLINE:	return ('1');
	case RESTARTER_STATE_MAINT:	return ('m');
	case RESTARTER_STATE_NONE:	return ('n');
	default:			return ('?');
	}
}

/*ARGSUSED*/
static int
pr_instance(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	restarter_instance_list_t ril;
	restarter_inst_t ri;
	char *iname;
	char statechr = '-';
	char typechr;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_readvar(&ril, "instance_list") == -1) {
			mdb_warn("failed to read 'instance_list' value\n");
			return (DCMD_ERR);
		}

		if (mdb_pwalk_dcmd("uu_list_node", "instance", 0, NULL,
		    (uintptr_t)ril.ril_instance_list) == -1) {
			mdb_warn("can't walk instances\n");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	if (mdb_vread(&ri, sizeof (restarter_inst_t), addr) == -1) {
		mdb_warn("couldn't read instance at %a\n");
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%-10s %-3s %1s %1s %4s\n", "ADDR", "ID", "T", "S",
		    "FMRI");

	iname = mdb_alloc(1024, UM_SLEEP | UM_GC);

	if (mdb_readstr(iname, 1024, (uintptr_t)ri.ri_i.i_fmri) == -1) {
		mdb_warn("couldn't read instance name\n");
		strcpy(iname, "-");
	}

	statechr = xstate2chr(ri.ri_i.i_state);
	typechr = (ri.ri_i.i_enabled) ? 'I' : 'i';

	mdb_printf("%-10a %3x %c %c %s\n", addr, ri.ri_id, typechr, statechr,
	    iname);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
pr_vertex(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uu_list_t *dgraphp;
	graph_vertex_t gv;
	char *vname;
	int id;
	char typechr;
	char statechr = '-';

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_readvar(&dgraphp, "dgraph") == -1) {
			mdb_warn("failed to read 'dgraph' value\n");
			return (DCMD_ERR);
		}

		if (mdb_pwalk_dcmd("uu_list_node", "vertex", 0, NULL,
		    (uintptr_t)dgraphp) == -1) {
			mdb_warn("can't walk vertices");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	if (mdb_vread(&gv, sizeof (graph_vertex_t), addr) == -1) {
		mdb_warn("couldn't read vertex at %a\n");
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%-10s %-3s %1s %1s %4s\n", "ADDR", "ID", "T", "S",
		    "FMRI");

	vname = mdb_alloc(1024, UM_SLEEP | UM_GC);

	if (mdb_readstr(vname, 1024, (uintptr_t)gv.gv_name) == -1) {
		mdb_warn("couldn't read vertex name\n");
		strcpy(vname, "-");
	}

	id = gv.gv_id;

	switch (gv.gv_type) {
	case GVT_FILE:
		typechr = 'f';
		break;
	case GVT_GROUP:
		switch (gv.gv_depgroup) {
		case DEPGRP_REQUIRE_ANY:
			typechr = 'r';
			break;
		case DEPGRP_REQUIRE_ALL:
			typechr = 'R';
			break;
		case DEPGRP_EXCLUDE_ALL:
			typechr = 'X';
			break;
		case DEPGRP_OPTIONAL_ALL:
			typechr = 'o';
			break;
		default:
			typechr = '?';
			break;
		}
		break;
	case GVT_INST:
		typechr = (gv.gv_flags & GV_ENABLED) ? 'I' : 'i';
		statechr = xstate2chr(gv.gv_state);
		break;
	case GVT_SVC:
		typechr = 's';
		break;
	default:
		typechr = '?';
		break;
	}

	mdb_printf("%-10a %3x %c %c %s\n", addr, id, typechr, statechr, vname);

	return (DCMD_OK);
}

/* ARGSUSED */
static int
logbuf(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	GElf_Sym sym;
	char *buf;
	char *cp;

	if (mdb_lookup_by_name("logbuf", &sym) == -1) {
		mdb_warn("The 'logbuf' symbol is missing.\n");
		return (DCMD_ERR);
	}

	buf = mdb_alloc(sym.st_size, UM_SLEEP | UM_GC);

	if (mdb_vread(buf, sym.st_size, sym.st_value) == -1) {
		mdb_warn("failed to read 'logbuf'\n");
		return (DCMD_ERR);
	}

	cp = strchr(buf, '\0');

	if (cp == buf)
		/* Empty */
		return (DCMD_OK);

	if (cp >= buf + sym.st_size ||
	    strchr(cp + 1, '\0') >= buf + sym.st_size) {
		mdb_warn("'logbuf' is corrupt\n");
		return (DCMD_ERR);
	}

	mdb_printf("%s", cp + 1);
	mdb_printf("%s", buf);

	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "instance", NULL, "display svc.startd restarter instance",
	    pr_instance },
	{ "startd_log", NULL, "display svc.startd debug message buffer",
	    logbuf },
	{ "startd_status", NULL, "svc.startd status summary", startd_status },
	{ "vertex", NULL, "display svc.startd dependency graph vertex",
	    pr_vertex },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
