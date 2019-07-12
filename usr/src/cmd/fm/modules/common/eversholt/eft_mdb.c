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

#include <sys/mdb_modapi.h>

#include <lut.h>
#include <itree.h>
#include "ipath_impl.h"
#include "lut_impl.h"
#include "config_impl.h"
#include "stats_impl.h"

#define	LUT_SIZE_INIT	300
#define	LUT_SIZE_INCR	100

struct lut_cp {
	uintptr_t lutcp_addr;
	struct lut lutcp_lut;
};

#define	LCPSZ	sizeof (struct lut_cp)

struct lut_dump_desc {
	struct lut_cp *ld_array;
	int ld_arraysz;
	int ld_nents;
};

static void
lut_dump_array_alloc(struct lut_dump_desc *lddp)
{
	struct lut_cp *new;

	if (lddp->ld_array == NULL) {
		lddp->ld_arraysz = LUT_SIZE_INIT;
		lddp->ld_array = mdb_zalloc(LUT_SIZE_INIT * LCPSZ, UM_SLEEP);
		return;
	}

	new = mdb_zalloc((lddp->ld_arraysz + LUT_SIZE_INCR) * LCPSZ, UM_SLEEP);
	bcopy(lddp->ld_array, new, lddp->ld_arraysz * LCPSZ);
	mdb_free(lddp->ld_array, lddp->ld_arraysz * LCPSZ);
	lddp->ld_array = new;
	lddp->ld_arraysz += LUT_SIZE_INCR;
}

static void
lut_dump_array_free(struct lut_dump_desc *lddp)
{
	if (lddp->ld_array != NULL) {
		mdb_free(lddp->ld_array, lddp->ld_arraysz * LCPSZ);
		lddp->ld_array = NULL;
	}
}

static void
lut_collect_addent(uintptr_t addr, struct lut *ent, struct lut_dump_desc *lddp)
{
	struct lut_cp *lcp;

	if (lddp->ld_nents == lddp->ld_arraysz)
		lut_dump_array_alloc(lddp);

	lcp = &lddp->ld_array[lddp->ld_nents++];

	lcp->lutcp_addr = addr;
	bcopy(ent, &lcp->lutcp_lut, sizeof (struct lut));
}

static int
eft_lut_walk(uintptr_t root, struct lut_dump_desc *lddp)
{
	struct lut lutent;

	if (root) {
		if (mdb_vread(&lutent, sizeof (struct lut), root) !=
		    sizeof (struct lut)) {
			mdb_warn("failed to read struct lut at %p", root);
			return (WALK_ERR);
		}

		if (eft_lut_walk((uintptr_t)lutent.lut_left, lddp) != WALK_NEXT)
			return (WALK_ERR);

		lut_collect_addent(root, &lutent, lddp);

		if (eft_lut_walk((uintptr_t)lutent.lut_right, lddp) !=
		    WALK_NEXT)
			return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static int
lut_collect(uintptr_t addr, struct lut_dump_desc *lddp)
{
	lut_dump_array_alloc(lddp);

	if (eft_lut_walk(addr, lddp) != WALK_NEXT) {
		lut_dump_array_free(lddp);
		return (WALK_ERR);
	} else {
		return (WALK_NEXT);	/* caller must free dump array */
	}
}

static int
lut_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("lut walker requires a lut table address\n");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_zalloc(sizeof (struct lut_dump_desc), UM_SLEEP);
	wsp->walk_arg = 0;

	if (lut_collect(wsp->walk_addr, wsp->walk_data) == WALK_NEXT) {
		return (WALK_NEXT);
	} else {
		mdb_warn("failed to suck in full lut\n");
		mdb_free(wsp->walk_data, sizeof (struct lut_dump_desc));
		return (WALK_ERR);
	}
}

static int
lut_walk_step(mdb_walk_state_t *wsp)
{
	struct lut_dump_desc *lddp = wsp->walk_data;
	int *ip = (int *)&wsp->walk_arg;
	struct lut_cp *lcp = &lddp->ld_array[*ip];

	if (*ip == lddp->ld_nents)
		return (WALK_DONE);

	++*ip;

	return (wsp->walk_callback(lcp->lutcp_addr, &lcp->lutcp_lut,
	    wsp->walk_cbdata));
}

static int
ipath_walk_init(mdb_walk_state_t *wsp)
{
	struct ipath *ipath;

	ipath = mdb_alloc(sizeof (struct ipath), UM_SLEEP);

	if (mdb_vread((void *)ipath, sizeof (struct ipath),
	    wsp->walk_addr) != sizeof (struct ipath)) {
		mdb_warn("failed to read struct ipath at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	wsp->walk_data = (void *)ipath;

	if (ipath->s == NULL)
		return (WALK_DONE);
	else
		return (WALK_NEXT);
}

static void
ipath_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct ipath));
}

static int
ipath_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	struct ipath *ipath = (struct ipath *)wsp->walk_data;
	struct ipath *ip = (struct ipath *)wsp->walk_addr;

	if (ip == NULL || ipath->s == NULL)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(ip + 1);

	if (mdb_vread(wsp->walk_data, sizeof (struct ipath),
	    wsp->walk_addr) != sizeof (struct ipath)) {
		mdb_warn("failed to read struct ipath at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	return (status);
}

static void
lut_walk_fini(mdb_walk_state_t *wsp)
{
	struct lut_dump_desc *lddp = wsp->walk_data;

	lut_dump_array_free(lddp);
	mdb_free(lddp, sizeof (struct lut_dump_desc));
}

/*ARGSUSED*/
static int
ipath_node(uintptr_t addr, const void *data, void *arg)
{
	struct ipath *ipath = (struct ipath *)data;
	char buf[128];

	if (mdb_readstr(buf, (size_t)sizeof (buf), (uintptr_t)ipath->s) < 0)
		(void) mdb_snprintf(buf, (size_t)sizeof (buf), "<%p>",
		    ipath->s);

	mdb_printf("/%s=%d", buf, ipath->i);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
ipath(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc)
		return (DCMD_USAGE);
	if (!(flags & DCMD_ADDRSPEC))
		addr = mdb_get_dot();
	if (mdb_pwalk("eft_ipath", ipath_node, NULL, addr) != 0)
		return (DCMD_ERR);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
eft_count(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct lut lut;
	struct istat_entry istat_entry;
	struct stats count;
	GElf_Sym sym;
	char buf[128];

	if (argc)
		return (DCMD_USAGE);
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_lookup_by_obj(MDB_OBJ_EVERY, "Istats", &sym) == -1 ||
		    sym.st_size != sizeof (addr))
			return (DCMD_ERR);
		if (mdb_vread(&addr, sizeof (addr),
		    (uintptr_t)sym.st_value) != sizeof (addr))
			return (DCMD_ERR);
		if (addr == 0)
			return (DCMD_OK);
		if (mdb_pwalk_dcmd("lut", "eft_count", argc, argv, addr) != 0)
			return (DCMD_ERR);
		return (DCMD_OK);
	}

	if (mdb_vread(&lut, sizeof (struct lut), addr) != sizeof (struct lut)) {
		mdb_warn("failed to read struct lut at %p", addr);
		return (DCMD_ERR);
	}
	if (mdb_vread(&istat_entry, sizeof (struct istat_entry),
	    (uintptr_t)lut.lut_lhs) != sizeof (struct istat_entry)) {
		mdb_warn("failed to read struct istat_entry at %p", addr);
		return (DCMD_ERR);
	}
	if (mdb_vread(&count, sizeof (struct stats),
	    (uintptr_t)lut.lut_rhs) != sizeof (struct stats)) {
		mdb_warn("failed to read struct stats at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_readstr(buf, (size_t)sizeof (buf),
	    (uintptr_t)istat_entry.ename) < 0)
		(void) mdb_snprintf(buf, (size_t)sizeof (buf), "<%p>",
		    istat_entry.ename);

	mdb_printf("%s@", buf);
	(void) ipath((uintptr_t)istat_entry.ipath, DCMD_ADDRSPEC, 0, NULL);
	mdb_printf(" %d\n", count.fmd_stats.fmds_value.i32);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
eft_time(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	unsigned long long val;
	unsigned long long ull;
	int opt_p = 0;

	if (!(flags & DCMD_ADDRSPEC))
		addr = mdb_get_dot();
	ull = addr;
	if (argc) {
		if (mdb_getopts(argc, argv,
		    'l', MDB_OPT_UINT64, &ull,
		    'p', MDB_OPT_SETBITS, TRUE, &opt_p,
		    MDB_OPT_UINT64) != argc) {
			return (DCMD_USAGE);
		}
	}
	if (opt_p) {
		if (mdb_vread(&ull, sizeof (ull), addr) != sizeof (ull)) {
			mdb_warn("failed to read timeval at %p", addr);
			return (DCMD_ERR);
		}
	}
#define	NOREMAINDER(den, num, val) (((val) = ((den) / (num))) * (num) == (den))
	if (ull == 0)
		mdb_printf("0us");
	else if (ull >= TIMEVAL_EVENTUALLY)
		mdb_printf("infinity");
	else if (NOREMAINDER(ull, 1000000000ULL*60*60*24*365, val))
		mdb_printf("%lluyear%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(ull, 1000000000ULL*60*60*24*30, val))
		mdb_printf("%llumonth%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(ull, 1000000000ULL*60*60*24*7, val))
		mdb_printf("%lluweek%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(ull, 1000000000ULL*60*60*24, val))
		mdb_printf("%lluday%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(ull, 1000000000ULL*60*60, val))
		mdb_printf("%lluhour%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(ull, 1000000000ULL*60, val))
		mdb_printf("%lluminute%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(ull, 1000000000ULL, val))
		mdb_printf("%llusecond%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(ull, 1000000ULL, val))
		mdb_printf("%llums", val);
	else if (NOREMAINDER(ull, 1000ULL, val))
		mdb_printf("%lluus", val);
	else
		mdb_printf("%lluns", ull);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
eft_node(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct node node;
	int opt_v = 0;
	char buf[128];

	if (!(flags & DCMD_ADDRSPEC))
		addr = mdb_get_dot();
	if (argc) {
		if (mdb_getopts(argc, argv,
		    'v', MDB_OPT_SETBITS, TRUE, &opt_v,
		    NULL) != argc) {
			return (DCMD_USAGE);
		}
	}
	if (addr == 0)
		return (DCMD_OK);
	if (mdb_vread(&node, sizeof (node), addr) != sizeof (node)) {
		mdb_warn("failed to read struct node at %p", addr);
		return (DCMD_ERR);
	}
	if (opt_v) {
		if (mdb_readstr(buf, (size_t)sizeof (buf),
		    (uintptr_t)node.file) < 0)
			(void) mdb_snprintf(buf, (size_t)sizeof (buf), "<%p>",
			    node.file);

		mdb_printf("%s len %d\n", buf, node.line);
	}
	switch (node.t) {
	case T_NOTHING:			/* used to keep going on error cases */
		mdb_printf("nothing");
		break;
	case T_NAME:			/* identifiers, sometimes chained */
		if (mdb_readstr(buf, (size_t)sizeof (buf),
		    (uintptr_t)node.u.name.s) < 0)
			(void) mdb_snprintf(buf, (size_t)sizeof (buf), "<%p>",
			    node.u.name.s);

		mdb_printf("%s", buf);
		if (node.u.name.cp) {
			struct config cp;
			if (mdb_vread(&cp, sizeof (cp),
			    (uintptr_t)node.u.name.cp) != sizeof (cp)) {
				mdb_warn("failed to read struct config at %p",
				    node.u.name.cp);
				return (DCMD_ERR);
			}
			mdb_printf("%d", cp.num);
		} else if (node.u.name.it == IT_HORIZONTAL) {
			if (node.u.name.child && !node.u.name.childgen) {
				mdb_printf("<");
				(void) eft_node((uintptr_t)node.u.name.child,
				    DCMD_ADDRSPEC, 0, NULL);
				mdb_printf(">");
			} else {
				mdb_printf("<> ");
			}
		} else if (node.u.name.child) {
			mdb_printf("[");
			(void) eft_node((uintptr_t)node.u.name.child,
			    DCMD_ADDRSPEC, 0, NULL);
			mdb_printf("]");
		}
		if (node.u.name.next) {
			if (node.u.name.it == IT_ENAME)
				mdb_printf(".");
			else
				mdb_printf("/");
			(void) eft_node((uintptr_t)node.u.name.next,
			    DCMD_ADDRSPEC, 0, NULL);
		}
		break;
	case T_GLOBID:			/* globals (e.g. $a) */
		if (mdb_readstr(buf, (size_t)sizeof (buf),
		    (uintptr_t)node.u.globid.s) < 0)
			(void) mdb_snprintf(buf, (size_t)sizeof (buf), "<%p>",
			    node.u.globid.s);

		mdb_printf("$%s", buf);
		break;
	case T_EVENT:			/* class@path{expr} */
		(void) eft_node((uintptr_t)node.u.event.ename, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf("@");
		(void) eft_node((uintptr_t)node.u.event.epname, DCMD_ADDRSPEC,
		    0, NULL);
		if (node.u.event.eexprlist) {
			mdb_printf(" { ");
			(void) eft_node((uintptr_t)node.u.event.eexprlist,
			    DCMD_ADDRSPEC, 0, NULL);
			mdb_printf(" }");
		}
		break;
	case T_ENGINE:			/* upset threshold engine (e.g. SERD) */
		mdb_printf("engine ");
		(void) eft_node((uintptr_t)node.u.event.ename, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_ASRU:			/* ASRU declaration */
		mdb_printf("asru ");
		(void) eft_node((uintptr_t)node.u.stmt.np, DCMD_ADDRSPEC, 0,
		    NULL);
		if (node.u.stmt.nvpairs) {
			mdb_printf(" ");
			(void) eft_node((uintptr_t)node.u.stmt.nvpairs,
			    DCMD_ADDRSPEC, 0, NULL);

		}
		break;
	case T_FRU:			/* FRU declaration */
		mdb_printf("fru ");
		(void) eft_node((uintptr_t)node.u.stmt.np, DCMD_ADDRSPEC, 0,
		    NULL);
		if (node.u.stmt.nvpairs) {
			mdb_printf(" ");
			(void) eft_node((uintptr_t)node.u.stmt.nvpairs,
			    DCMD_ADDRSPEC, 0, NULL);

		}
		break;
	case T_TIMEVAL:			/* num w/time suffix (ns internally) */
		{
			mdb_arg_t mdb_arg[2];
			mdb_arg[0].a_type = MDB_TYPE_STRING;
			mdb_arg[0].a_un.a_str = "-l";
			mdb_arg[1].a_type = MDB_TYPE_IMMEDIATE;
			mdb_arg[1].a_un.a_val = node.u.ull;
			(void) eft_time((uintptr_t)0, 0, 2, mdb_arg);
			break;
		}
	case T_NUM:			/* num (ull internally) */
		mdb_printf("%llu", node.u.ull);
		break;
	case T_QUOTE:			/* quoted string */
		if (mdb_readstr(buf, (size_t)sizeof (buf),
		    (uintptr_t)node.u.quote.s) < 0)
			(void) mdb_snprintf(buf, (size_t)sizeof (buf), "<%p>",
			    node.u.quote.s);

		mdb_printf("\"%s\"", buf);
		break;
	case T_FUNC:			/* func(arglist) */
		if (mdb_readstr(buf, (size_t)sizeof (buf),
		    (uintptr_t)node.u.func.s) < 0)
			(void) mdb_snprintf(buf, (size_t)sizeof (buf), "<%p>",
			    node.u.func.s);

		mdb_printf("%s(", buf);
		(void) eft_node((uintptr_t)node.u.func.arglist, DCMD_ADDRSPEC,
		    0, NULL);
		mdb_printf(")");
		break;
	case T_NVPAIR:			/* name=value pair in decl */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" = ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_ASSIGN:			/* assignment statement */
		mdb_printf("(");
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" = ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(")");
		break;
	case T_CONDIF:			/* a and T_CONDELSE in (a ? b : c ) */
		mdb_printf("(");
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" ? ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(")");
		break;
	case T_CONDELSE:		/* lists b and c in (a ? b : c ) */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" : ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_NOT:			/* boolean ! operator */
		mdb_printf("!");
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_AND:			/* boolean && operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" && ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_OR:			/* boolean || operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" || ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_EQ:			/* boolean == operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" == ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_NE:			/* boolean != operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" != ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_SUB:			/* integer - operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" - ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_ADD:			/* integer + operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" + ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_MUL:			/* integer * operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" * ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_DIV:			/* integer / operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" / ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_MOD:			/* integer % operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" % ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_LT:			/* boolean < operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" < ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_LE:			/* boolean <= operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" <= ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_GT:			/* boolean > operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" > ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_GE:			/* boolean >= operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" >= ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_BITAND:			/* bitwise & operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" & ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_BITOR:			/* bitwise | operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" | ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_BITXOR:			/* bitwise ^ operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" ^ ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_BITNOT:			/* bitwise ~ operator */
		mdb_printf(" ~");
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_LSHIFT:			/* bitwise << operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" << ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_RSHIFT:			/* bitwise >> operator */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(" >> ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_ARROW:			/* lhs (N)->(K) rhs */
		(void) eft_node((uintptr_t)node.u.arrow.lhs, DCMD_ADDRSPEC, 0,
		    NULL);
		if (node.u.arrow.nnp) {
			mdb_printf("(");
			(void) eft_node((uintptr_t)node.u.arrow.nnp,
			    DCMD_ADDRSPEC, 0, NULL);
			mdb_printf(")");
		}
		mdb_printf("->");
		if (node.u.arrow.knp) {
			mdb_printf("(");
			(void) eft_node((uintptr_t)node.u.arrow.knp,
			    DCMD_ADDRSPEC, 0, NULL);
			mdb_printf(")");
		}
		(void) eft_node((uintptr_t)node.u.arrow.rhs, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_LIST:			/* comma-separated list */
		(void) eft_node((uintptr_t)node.u.expr.left, DCMD_ADDRSPEC, 0,
		    NULL);
		mdb_printf(", ");
		(void) eft_node((uintptr_t)node.u.expr.right, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_FAULT:			/* fault declaration */
		mdb_printf("fault.");
		(void) eft_node((uintptr_t)node.u.stmt.np, DCMD_ADDRSPEC, 0,
		    NULL);
		if (node.u.stmt.nvpairs) {
			mdb_printf(" ");
			(void) eft_node((uintptr_t)node.u.stmt.nvpairs,
			    DCMD_ADDRSPEC, 0, NULL);

		}
		break;
	case T_UPSET:			/* upset declaration */
		mdb_printf("upset.");
		(void) eft_node((uintptr_t)node.u.stmt.np, DCMD_ADDRSPEC, 0,
		    NULL);
		if (node.u.stmt.nvpairs) {
			mdb_printf(" ");
			(void) eft_node((uintptr_t)node.u.stmt.nvpairs,
			    DCMD_ADDRSPEC, 0, NULL);

		}
		break;
	case T_DEFECT:			/* defect declaration */
		mdb_printf("defect.");
		(void) eft_node((uintptr_t)node.u.stmt.np, DCMD_ADDRSPEC, 0,
		    NULL);
		if (node.u.stmt.nvpairs) {
			mdb_printf(" ");
			(void) eft_node((uintptr_t)node.u.stmt.nvpairs,
			    DCMD_ADDRSPEC, 0, NULL);

		}
		break;
	case T_ERROR:			/* error declaration */
		mdb_printf("error.");
		(void) eft_node((uintptr_t)node.u.stmt.np, DCMD_ADDRSPEC, 0,
		    NULL);
		if (node.u.stmt.nvpairs) {
			mdb_printf(" ");
			(void) eft_node((uintptr_t)node.u.stmt.nvpairs,
			    DCMD_ADDRSPEC, 0, NULL);

		}
		break;
	case T_EREPORT:			/* ereport declaration */
		mdb_printf("ereport.");
		(void) eft_node((uintptr_t)node.u.stmt.np, DCMD_ADDRSPEC, 0,
		    NULL);
		if (node.u.stmt.nvpairs) {
			mdb_printf(" ");
			(void) eft_node((uintptr_t)node.u.stmt.nvpairs,
			    DCMD_ADDRSPEC, 0, NULL);

		}
		break;
	case T_SERD:			/* SERD engine declaration */
		mdb_printf("serd.");
		(void) eft_node((uintptr_t)node.u.stmt.np, DCMD_ADDRSPEC, 0,
		    NULL);
		if (node.u.stmt.nvpairs) {
			mdb_printf(" ");
			(void) eft_node((uintptr_t)node.u.stmt.nvpairs,
			    DCMD_ADDRSPEC, 0, NULL);

		} else if (node.u.stmt.lutp) {
			if (mdb_pwalk_dcmd("lut", "eft_node", 0, NULL,
			    (uintptr_t)node.u.stmt.lutp) != 0)
				return (DCMD_ERR);
		}
		break;
	case T_STAT:			/* STAT engine declaration */
		mdb_printf("stat.");
		(void) eft_node((uintptr_t)node.u.stmt.np, DCMD_ADDRSPEC, 0,
		    NULL);
		if (node.u.stmt.nvpairs) {
			mdb_printf(" ");
			(void) eft_node((uintptr_t)node.u.stmt.nvpairs,
			    DCMD_ADDRSPEC, 0, NULL);

		} else if (node.u.stmt.lutp) {
			if (mdb_pwalk_dcmd("lut", "eft_node", 0, NULL,
			    (uintptr_t)node.u.stmt.lutp) != 0)
				return (DCMD_ERR);
		}
		break;
	case T_PROP:			/* prop statement */
		mdb_printf("prop ");
		(void) eft_node((uintptr_t)node.u.stmt.np, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_MASK:			/* mask statement */
		mdb_printf("mask ");
		(void) eft_node((uintptr_t)node.u.stmt.np, DCMD_ADDRSPEC, 0,
		    NULL);
		break;
	case T_CONFIG:			/* config statement */
		mdb_printf("config ");
		(void) eft_node((uintptr_t)node.u.stmt.np, DCMD_ADDRSPEC, 0,
		    NULL);
		if (node.u.stmt.nvpairs) {
			mdb_printf(" ");
			(void) eft_node((uintptr_t)node.u.stmt.nvpairs,
			    DCMD_ADDRSPEC, 0, NULL);

		}
		break;
	default:
		mdb_printf("not a eversholt node\n");
		break;
	}
	return (DCMD_OK);
}

static const mdb_walker_t walkers[] = {
	{ "lut", "walk a lookup table", lut_walk_init, lut_walk_step,
	    lut_walk_fini, NULL },
	{ "eft_ipath", "walk ipath", ipath_walk_init, ipath_walk_step,
	    ipath_walk_fini, NULL },
	{ NULL, NULL, NULL, NULL, NULL, NULL }
};

static const mdb_dcmd_t dcmds[] = {
	{ "eft_ipath", "?", "print an ipath", ipath },
	{ "eft_count", "?", "print eversholt stats", eft_count },
	{ "eft_node", "?[-v]", "print eversholt node", eft_node },
	{ "eft_time", "?[-p][-l time]", "print eversholt timeval", eft_time },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
