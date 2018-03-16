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
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */


#include <sys/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netsmb/smb_conn.h>
#include <netsmb/smb_rq.h>
#include <netsmb/smb_pass.h>

#ifdef _KERNEL
#define	NSMB_OBJNAME	"nsmb"
#else
#define	NSMB_OBJNAME	"libfknsmb.so.1"
#endif

#define	OPT_VERBOSE	0x0001	/* Be [-v]erbose in dcmd's */
#define	OPT_RECURSE	0x0002	/* recursive display */

/*
 * We need to read in a private copy
 * of every string we want to print out.
 */
void
print_str(uintptr_t addr)
{
	char buf[32];
	int len, mx = sizeof (buf) - 4;

	if ((len = mdb_readstr(buf, sizeof (buf), addr)) <= 0) {
		mdb_printf(" (%p)", addr);
	} else {
		if (len > mx)
			strcpy(&buf[mx], "...");
		mdb_printf(" %s", buf);
	}
}


/*
 * Walker for smb_connobj_t structures, including
 * smb_vc_t and smb_share_t which "inherit" from it.
 * Tricky: Exploit the "inheritance" of smb_connobj_t
 * with common functions for walk_init, walk_next.
 */
typedef struct smb_co_walk_data {
	uintptr_t	pp;
	int level;		/* SMBL_SM, SMBL_VC, SMBL_SHARE, ...  */
	int size;		/* sizeof (union member) */
	union co_u {
		smb_connobj_t	co;	/* copy of the list element */
		smb_vc_t	vc;
		smb_share_t	ss;
		smb_fh_t	fh;
	} u;
} smb_co_walk_data_t;

/*
 * Common walk_init for walking structs inherited
 * from smb_connobj_t (smb_vc_t, smb_share_t)
 */
int
smb_co_walk_init(mdb_walk_state_t *wsp, int level)
{
	smb_co_walk_data_t *smbw;
	size_t psz;

	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	smbw = mdb_alloc(sizeof (*smbw), UM_SLEEP | UM_GC);
	wsp->walk_data = smbw;

	/*
	 * Save the parent pointer for later checks, and
	 * the level so we know which union member it is.
	 * Also the size of this union member.
	 */
	smbw->pp = wsp->walk_addr;
	smbw->level = level;
	switch (level) {
	case SMBL_SM:
		smbw->size = sizeof (smbw->u.co);
		break;
	case SMBL_VC:
		smbw->size = sizeof (smbw->u.vc);
		break;
	case SMBL_SHARE:
		smbw->size = sizeof (smbw->u.ss);
		break;
	case SMBL_FH:
		smbw->size = sizeof (smbw->u.fh);
		break;
	default:
		smbw->size = sizeof (smbw->u);
		break;
	}

	/*
	 * Read in the parent object.  Just need the
	 * invariant part (smb_connobj_t) so we can
	 * get the list of children below it.
	 */
	psz = sizeof (smbw->u.co);
	if (mdb_vread(&smbw->u.co, psz, smbw->pp) != psz) {
		mdb_warn("cannot read connobj from %p", smbw->pp);
		return (WALK_ERR);
	}

	/*
	 * Finally, setup to walk the list of children.
	 */
	wsp->walk_addr = (uintptr_t)smbw->u.co.co_children.slh_first;

	return (WALK_NEXT);
}

/*
 * Walk the (global) VC list.
 */
int
smb_vc_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;

	if (wsp->walk_addr != NULL) {
		mdb_warn("::walk smb_vc only supports global walks\n");
		return (WALK_ERR);
	}

	/* Locate the VC list head. */
	if (mdb_lookup_by_obj(NSMB_OBJNAME, "smb_vclist", &sym)) {
		mdb_warn("failed to lookup `smb_vclist'\n");
		return (WALK_ERR);
	}
	wsp->walk_addr = sym.st_value;

	return (smb_co_walk_init(wsp, SMBL_VC));
}

/*
 * Walk the share list below some VC.
 */
int
smb_ss_walk_init(mdb_walk_state_t *wsp)
{

	/*
	 * Initial walk_addr is address of parent (VC)
	 */
	if (wsp->walk_addr == 0) {
		mdb_warn("::walk smb_ss does not support global walks\n");
		return (WALK_ERR);
	}

	return (smb_co_walk_init(wsp, SMBL_SHARE));
}

/*
 * Walk the file hande list below some share.
 */
int
smb_fh_walk_init(mdb_walk_state_t *wsp)
{

	/*
	 * Initial walk_addr is address of parent (share)
	 */
	if (wsp->walk_addr == 0) {
		mdb_warn("::walk smb_fh does not support global walks\n");
		return (WALK_ERR);
	}

	return (smb_co_walk_init(wsp, SMBL_FH));
}

/*
 * Common walk_step for walking structs inherited
 * from smb_connobj_t (smb_vc_t, smb_share_t)
 */
int
smb_co_walk_step(mdb_walk_state_t *wsp)
{
	smb_co_walk_data_t *smbw = wsp->walk_data;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&smbw->u, smbw->size, wsp->walk_addr)
	    != smbw->size) {
		mdb_warn("cannot read connobj from %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	/* XXX: Sanity check level? parent pointer? */

	status = wsp->walk_callback(wsp->walk_addr, &smbw->u,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)smbw->u.co.co_next.sle_next;

	return (status);
}


/*
 * Dcmd (and callback function) to print a summary of
 * all VCs, and optionally all shares under each VC.
 */

typedef struct smb_co_cbdata {
	int flags;		/* OPT_...  */
	int printed_header;
	mdb_ctf_id_t ctf_id;
} smb_co_cbdata_t;

/*
 * Call-back function for walking a file handle list.
 */
/* ARGSUSED */
int
smb_fh_cb(uintptr_t addr, const void *data, void *arg)
{
	const smb_fh_t *fhp = data;
	// smb_co_cbdata_t *cbd = arg;

	mdb_inc_indent(2);
	mdb_printf(" %-p", addr);
	if (fhp->fh_fid2.fid_volatile != 0) {
		mdb_printf("\t0x%llx\n",
		    (long long) fhp->fh_fid2.fid_volatile);
	} else {
		mdb_printf("\t0x%x\n", fhp->fh_fid1);
	}

	mdb_dec_indent(2);

	return (WALK_NEXT);
}

/*
 * Call-back function for walking a share list.
 */
int
smb_ss_cb(uintptr_t addr, const void *data, void *arg)
{
	const smb_share_t *ssp = data;
	smb_co_cbdata_t *cbd = arg;
	uint32_t tid;

	tid = ssp->ss2_tree_id;
	if (tid == 0)
		tid = ssp->ss_tid;

	mdb_printf(" %-p\t0x%x\t%s\n", addr, tid, ssp->ss_name);

	if (cbd->flags & OPT_RECURSE) {
		mdb_inc_indent(2);
		if (mdb_pwalk("nsmb_fh", smb_fh_cb, cbd, addr) < 0) {
			mdb_warn("failed to walk 'nsmb_fh'");
			/* Don't: return (WALK_ERR); */
		}
		mdb_dec_indent(2);
	}

	return (WALK_NEXT);
}

static const char *
vcstate_str(smb_co_cbdata_t *cbd, int stval)
{
	static const char prefix[] = "SMBIOD_ST_";
	int prefix_len = sizeof (prefix) - 1;
	mdb_ctf_id_t vcst_enum;
	const char *cp;

	/* Got this in smb_vc_dcmd. */
	vcst_enum = cbd->ctf_id;

	/* Get the name for the enum value. */
	if ((cp = mdb_ctf_enum_name(vcst_enum, stval)) == NULL)
		return ("?");

	/* Skip the prefix part. */
	if (strncmp(cp, prefix, prefix_len) == 0)
		cp += prefix_len;

	return (cp);
}

/*
 * Call-back function for walking the VC list.
 */
int
smb_vc_cb(uintptr_t addr, const void *data, void *arg)
{
	const smb_vc_t *vcp = data;
	smb_co_cbdata_t *cbd = arg;

	if (cbd->printed_header == 0) {
		cbd->printed_header = 1;
		mdb_printf("// smb_vc_t  uid  server  \tuser\t\tstate\n");
	}

	mdb_printf("%-p", addr);
	mdb_printf(" %7d", vcp->vc_owner);

	switch (vcp->vc_srvaddr.sa.sa_family) {
	case AF_INET:
		mdb_printf(" %I", vcp->vc_srvaddr.sin.sin_addr);
		break;
	case AF_INET6:
		mdb_printf(" %N", &vcp->vc_srvaddr.sin6.sin6_addr);
		break;
	default:
		mdb_printf(" %15s", "(bad af)");
		break;
	}

	if (vcp->vc_username[0] != '\0')
		mdb_printf("\t%s", vcp->vc_username);
	else
		mdb_printf("\t%s", "(?)");

	if (vcp->vc_domain[0] != '\0')
		mdb_printf("@%s", vcp->vc_domain);

	mdb_printf("\t%s\n", vcstate_str(cbd, vcp->vc_state));

	if (cbd->flags & OPT_RECURSE) {
		mdb_inc_indent(2);
		if (mdb_pwalk("nsmb_ss", smb_ss_cb, cbd, addr) < 0) {
			mdb_warn("failed to walk 'nsmb_ss'");
			/* Don't: return (WALK_ERR); */
		}
		mdb_dec_indent(2);
	}

	return (WALK_NEXT);
}

int
smb_vc_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_co_cbdata_t cbd;
	smb_vc_t *vcp;
	size_t vcsz;

	memset(&cbd, 0, sizeof (cbd));

	if (mdb_getopts(argc, argv,
	    'r', MDB_OPT_SETBITS, OPT_RECURSE, &cbd.flags,
	    'v', MDB_OPT_SETBITS, OPT_VERBOSE, &cbd.flags,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (mdb_ctf_lookup_by_name("enum smbiod_state", &cbd.ctf_id) == -1) {
		mdb_warn("Could not find enum smbiod_state");
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk("nsmb_vc", smb_vc_cb, &cbd) == -1) {
			mdb_warn("failed to walk 'nsmb_vc'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	vcsz = sizeof (*vcp);
	vcp = mdb_alloc(vcsz, UM_SLEEP | UM_GC);
	if (mdb_vread(vcp, vcsz, addr) != vcsz) {
		mdb_warn("cannot read VC from %p", addr);
		return (DCMD_ERR);
	}
	smb_vc_cb(addr, vcp, &cbd);

	return (DCMD_OK);
}

void
smb_vc_help(void)
{
	mdb_printf("Options:\n"
	    "  -r           recursive display of share lists\n"
	    "  -v           be verbose when displaying smb_vc\n");
}

/*
 * Walker for the request list on a VC,
 * and dcmd to show a summary.
 */
int
rqlist_walk_init(mdb_walk_state_t *wsp)
{
	struct smb_rqhead rqh;
	uintptr_t addr;

	/*
	 * Initial walk_addr is the address of the VC.
	 * Add offsetof(iod_rqlist) to get the rqhead.
	 */
	if (wsp->walk_addr == 0) {
		mdb_warn("::walk smb_ss does not support global walks\n");
		return (WALK_ERR);
	}
	addr = wsp->walk_addr;
	addr += OFFSETOF(smb_vc_t, iod_rqlist);

	if (mdb_vread(&rqh, sizeof (rqh), addr) == -1) {
		mdb_warn("failed to read smb_rqhead at %p", addr);
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)rqh.tqh_first;

	return (WALK_NEXT);
}

int
rqlist_walk_step(mdb_walk_state_t *wsp)
{
	smb_rq_t rq;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&rq, sizeof (rq), wsp->walk_addr) == -1) {
		mdb_warn("cannot read smb_rq from %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &rq,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)rq.sr_link.tqe_next;

	return (status);
}

typedef struct rqlist_cbdata {
	int printed_header;
	int vcflags;
	uintptr_t uid;		/* optional filtering by UID */
} rqlist_cbdata_t;

int
rqlist_cb(uintptr_t addr, const void *data, void *arg)
{
	const smb_rq_t *rq = data;
	rqlist_cbdata_t *cbd = arg;

	if (cbd->printed_header == 0) {
		cbd->printed_header = 1;
		mdb_printf("// smb_rq_t MID cmd sr_state sr_flags\n");
	}

	mdb_printf(" %-p", addr);	/* smb_rq_t */
	if ((cbd->vcflags & SMBV_SMB2) != 0) {
		mdb_printf(" x%04llx", (long long)rq->sr2_messageid);
		mdb_printf(" x%02x", rq->sr2_command);
	} else {
		mdb_printf(" x%04x", rq->sr_mid);
		mdb_printf(" x%02x", rq->sr_cmd);
	}
	mdb_printf(" %d", rq->sr_state);
	mdb_printf(" x%x", rq->sr_flags);
	mdb_printf("\n");

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
rqlist_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rqlist_cbdata_t cbd;
	smb_vc_t *vcp;
	size_t vcsz;

	memset(&cbd, 0, sizeof (cbd));

	/* Need the VC again to get  */
	vcsz = sizeof (*vcp);
	vcp = mdb_alloc(vcsz, UM_SLEEP | UM_GC);
	if (mdb_vread(vcp, vcsz, addr) != vcsz) {
		mdb_warn("cannot read VC from %p", addr);
		return (DCMD_ERR);
	}
	cbd.vcflags = vcp->vc_flags;

	/*
	 * Initial walk_addr is address of parent (VC)
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("address required\n");
		return (DCMD_ERR);
	}

	if (mdb_pwalk("nsmb_rqlist", rqlist_cb, &cbd, addr) == -1) {
		mdb_warn("failed to walk 'nsmb_rqlist'");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}


/*
 * AVL walker for the passwords AVL tree,
 * and dcmd to show a summary.
 */
static int
pwtree_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;

	if (wsp->walk_addr != NULL) {
		mdb_warn("pwtree walk only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_lookup_by_obj(NSMB_OBJNAME, "smb_ptd", &sym) == -1) {
		mdb_warn("failed to find symbol 'smb_ptd'");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)sym.st_value;

	if (mdb_layered_walk("avl", wsp) == -1) {
		mdb_warn("failed to walk 'avl'\n");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
pwtree_walk_step(mdb_walk_state_t *wsp)
{
	smb_passid_t	ptnode;

	if (mdb_vread(&ptnode, sizeof (ptnode), wsp->walk_addr) == -1) {
		mdb_warn("failed to read smb_passid_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(wsp->walk_addr, &ptnode, wsp->walk_cbdata));
}

typedef struct pwtree_cbdata {
	int printed_header;
	uid_t uid;		/* optional filtering by UID */
} pwtree_cbdata_t;

int
pwtree_cb(uintptr_t addr, const void *data, void *arg)
{
	const smb_passid_t *ptn = data;
	pwtree_cbdata_t *cbd = arg;

	/* Optional filtering by UID. */
	if (cbd->uid != (uid_t)-1 && cbd->uid != ptn->uid) {
		return (WALK_NEXT);
	}

	if (cbd->printed_header == 0) {
		cbd->printed_header = 1;
		mdb_printf("// smb_passid_t UID domain user\n");
	}

	mdb_printf(" %-p", addr);	/* smb_passid_t */
	mdb_printf(" %d", (uintptr_t)ptn->uid);
	print_str((uintptr_t)ptn->srvdom);
	print_str((uintptr_t)ptn->username);
	mdb_printf("\n");

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
pwtree_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pwtree_cbdata_t cbd;
	char *uid_str = NULL;
	char buf[32];

	memset(&cbd, 0, sizeof (cbd));

	if (mdb_getopts(argc, argv,
	    'u', MDB_OPT_STR, &uid_str, NULL) != argc) {
		return (DCMD_USAGE);
	}
	if (uid_str) {
		/*
		 * Want the the default radix to be 10 here.
		 * If the string has some kind of radix prefix,
		 * just use that as-is, otherwise prepend "0t".
		 * Cheating on the "not a digit" test, but
		 * mdb_strtoull will do a real syntax check.
		 */
		if (uid_str[0] == '0' && uid_str[1] > '9') {
			cbd.uid = (uid_t)mdb_strtoull(uid_str);
		} else {
			strcpy(buf, "0t");
			strlcat(buf, uid_str, sizeof (buf));
			cbd.uid = (uid_t)mdb_strtoull(buf);
		}
	} else
		cbd.uid = (uid_t)-1;

	if (flags & DCMD_ADDRSPEC) {
		mdb_warn("address not allowed\n");
		return (DCMD_ERR);
	}

	if (mdb_pwalk("nsmb_pwtree", pwtree_cb, &cbd, 0) == -1) {
		mdb_warn("failed to walk 'nsmb_pwtree'");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

void
pwtree_help(void)
{
	mdb_printf("Options:\n"
	    "  -u uid       show only entries belonging to uid (decimal)\n");
}


static const mdb_dcmd_t dcmds[] = {
	{ "nsmb_vc", "?[-rv]",
		"show smb_vc (or list)",
		smb_vc_dcmd, smb_vc_help },
	{ "nsmb_rqlist", ":",
		"show smb_rq list on a VC",
		rqlist_dcmd, NULL },
	{ "nsmb_pwtree", "?[-u uid]",
		"list smb_passid_t (password tree)",
		pwtree_dcmd, pwtree_help },
	{NULL}
};

static const mdb_walker_t walkers[] = {
	{ "nsmb_vc", "walk nsmb VC list",
		smb_vc_walk_init, smb_co_walk_step, NULL },
	{ "nsmb_ss", "walk nsmb share list for some VC",
		smb_ss_walk_init, smb_co_walk_step, NULL },
	{ "nsmb_fh", "walk nsmb share list for some VC",
		smb_fh_walk_init, smb_co_walk_step, NULL },
	{ "nsmb_rqlist", "walk request list for some VC",
		rqlist_walk_init, rqlist_walk_step, NULL },
	{ "nsmb_pwtree", "walk passord AVL tree",
		pwtree_walk_init, pwtree_walk_step, NULL },
	{NULL}
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION,
	dcmds,
	walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
