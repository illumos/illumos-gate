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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/time.h>
#include <ipp/ipp.h>
#include <ipp/ipp_impl.h>
#include <mdb/mdb_modapi.h>

static uintptr_t	ipp_mod_byid;
static uintptr_t	ipp_action_byid;

static int	byid_walk_init(mdb_walk_state_t *);
static int	byid_walk_step(mdb_walk_state_t *);
static void	byid_walk_fini(mdb_walk_state_t *);

static int	action(uintptr_t, uint_t, int, const mdb_arg_t *);
static int	action_format(uintptr_t, const void *, void *);
static int	action_dump(uintptr_t, ipp_action_t *, boolean_t);
static int	action_summary(uintptr_t, ipp_action_t *, boolean_t);

static int	cfglock(uintptr_t, uint_t, int, const mdb_arg_t *);

static int	mod(uintptr_t, uint_t, int, const mdb_arg_t *);
static int	mod_format(uintptr_t, const void *, void *);
static int	mod_dump(uintptr_t, ipp_mod_t *, boolean_t);
static int	mod_summary(uintptr_t, ipp_mod_t *, boolean_t);
static int	cfglock(uintptr_t, uint_t, int, const mdb_arg_t *);

static int	ippops(uintptr_t, uint_t, int, const mdb_arg_t *);

static int	packet(uintptr_t, uint_t, int, const mdb_arg_t *);
static void	dump_classes(uintptr_t, uint_t);
static void	dump_log(uintptr_t, uint_t);
static void	aid2aname(ipp_action_id_t, char *);

static int	ref_walk_init(mdb_walk_state_t *);
static int	ref_walk_step(mdb_walk_state_t *);
static void	ref_walk_fini(mdb_walk_state_t *);

typedef	struct afdata {
	boolean_t	af_banner;
	uint_t		af_flags;
} afdata_t;

#define	AF_VERBOSE	1

typedef	struct mfdata {
	boolean_t	mf_banner;
	uint_t		mf_flags;
} mfdata_t;

#define	MF_VERBOSE	1

/*
 * walker. Skips entries that are NULL.
 */

static int
byid_walk_init(
	mdb_walk_state_t *wsp)
{
	uintptr_t	start;

	if (mdb_vread(&start, sizeof (uintptr_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read from address %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = start;

	return (WALK_NEXT);
}

static int
byid_walk_step(
	mdb_walk_state_t *wsp)
{
	int		status;
	void		*ptr;

	if (mdb_vread(&ptr, sizeof (void *), wsp->walk_addr) == -1) {
		mdb_warn("failed to read from address %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if (ptr == (void *)-1) {
		status = WALK_DONE;
	} else if (ptr == NULL) {
		status = WALK_NEXT;
	} else {
		status = wsp->walk_callback((uintptr_t)ptr, NULL,
		    wsp->walk_cbdata);
	}

	wsp->walk_addr += sizeof (void *);

	return (status);
}

/*ARGSUSED*/
static void
byid_walk_fini(
	mdb_walk_state_t *wsp)
{
}


/*ARGSUSED*/
static int
action(
	uintptr_t	addr,
	uint_t		flags,
	int		argc,
	const mdb_arg_t	*argv)
{
	int		status;
	int		rc = DCMD_OK;
	afdata_t	*afp;

	afp = mdb_zalloc(sizeof (afdata_t), UM_SLEEP);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, AF_VERBOSE, &afp->af_flags,
	    NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP))
		afp->af_banner = B_TRUE;

	if (flags & DCMD_ADDRSPEC) {
		status = action_format(addr, NULL, afp);
		rc = (status == WALK_NEXT) ? DCMD_OK : DCMD_ERR;
		goto cleanup;
	}

	if (mdb_pwalk("ipp_byid", action_format, afp,
	    ipp_action_byid) == -1) {
		mdb_warn("failed to execute ipp_byid walk");
		rc = DCMD_ERR;
	}

cleanup:
	mdb_free(afp, sizeof (afdata_t));

	return (rc);
}

/*ARGSUSED*/
static int
action_format(
	uintptr_t	addr,
	const void	*data,
	void		*arg)
{
	afdata_t	*afp = (afdata_t *)arg;
	ipp_action_t	*ap;
	int		rc;

	ap = mdb_alloc(sizeof (ipp_action_t), UM_SLEEP);
	if (mdb_vread(ap, sizeof (ipp_action_t), addr) == -1) {
		mdb_warn("failed to read ipp_action_t at %p", addr);
		rc = WALK_ERR;
		goto done;
	}

	if (afp->af_flags & AF_VERBOSE)
		rc = action_dump(addr, ap, afp->af_banner);
	else
		rc = action_summary(addr, ap, afp->af_banner);

	afp->af_banner = B_FALSE;
done:
	mdb_free(ap, sizeof (ipp_action_t));
	return (rc);
}

/*ARGSUSED*/
static int
action_dump(
	uintptr_t	addr,
	ipp_action_t	*ap,
	boolean_t	banner)
{
	mdb_printf("%?p: %20s = %d\n", addr, "id", ap->ippa_id);
	if (!ap->ippa_nameless) {
		mdb_printf("%?s  %20s = %s\n", "", "name", ap->ippa_name);
	}
	mdb_printf("%?s  %20s = 0x%p\n", "", "mod", ap->ippa_mod);
	mdb_printf("%?s  %20s = 0x%p\n", "", "ref", ap->ippa_ref);
	mdb_printf("%?s  %20s = 0x%p\n", "", "refby", ap->ippa_refby);
	mdb_printf("%?s  %20s = 0x%p\n", "", "ptr", ap->ippa_ptr);

	mdb_printf("%?s  %20s = ", "", "state");
	switch (ap->ippa_state) {
	case IPP_ASTATE_PROTO:
		mdb_printf("%s\n", "PROTO");
		break;
	case IPP_ASTATE_CONFIG_PENDING:
		mdb_printf("%s\n", "CONFIG_PENDING");
		break;
	case IPP_ASTATE_AVAILABLE:
		mdb_printf("%s\n", "AVAILABLE");
		break;
	default:
		mdb_printf("%s\n", "<unknown>");
		break;
	}

	mdb_printf("%?s  %20s = %d\n", "", "packets", ap->ippa_packets);
	mdb_printf("%?s  %20s = %d\n", "", "hold_count", ap->ippa_hold_count);
	mdb_printf("%?s  %20s = %s\n", "", "destruct_pending",
	    (ap->ippa_destruct_pending) ? "TRUE" : "FALSE");
	mdb_printf("%?s  %20s = 0x%p\n", "", "lock",
	    addr + ((uintptr_t)ap->ippa_lock - (uintptr_t)ap));
	mdb_printf("%?s  %20s = 0x%p\n", "", "config_lock",
	    addr + ((uintptr_t)ap->ippa_config_lock - (uintptr_t)ap));
	mdb_printf("\n");

	return (WALK_NEXT);
}

static int
action_summary(
	uintptr_t	addr,
	ipp_action_t	*ap,
	boolean_t	banner)
{
	ipp_mod_t	*imp;
	uintptr_t	ptr;

	if (banner)
		mdb_printf("%?s %<u>%20s %5s %20s%</u>\n",
		    "", "NAME", "ID", "MODNAME");

	imp = mdb_alloc(sizeof (ipp_mod_t), UM_SLEEP);
	ptr = (uintptr_t)ap->ippa_mod;
	if (mdb_vread(imp, sizeof (ipp_mod_t), ptr) == -1) {
		mdb_warn("failed to read ipp_mod_t at %p", ptr);
		mdb_free(imp, sizeof (ipp_mod_t));
		return (WALK_ERR);
	}

	mdb_printf("%?p:%20s %5d %20s\n", addr, ap->ippa_name, ap->ippa_id,
	    imp->ippm_name);

	mdb_free(imp, sizeof (ipp_mod_t));
	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
cfglock(
	uintptr_t	addr,
	uint_t		flags,
	int		argc,
	const mdb_arg_t	*argv)
{
	cfglock_t	*clp;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_ERR);

	clp = mdb_alloc(sizeof (cfglock_t), UM_SLEEP);
	if (mdb_vread(clp, sizeof (cfglock_t), addr) == -1) {
		mdb_warn("failed to read cfglock_t at %p", addr);
		mdb_free(clp, sizeof (cfglock_t));
		return (WALK_ERR);
	}

	mdb_printf("%?p: %20s = %p\n", addr, "owner", clp->cl_owner);
	mdb_printf("%?s  %20s = %s\n", "", "reader",
	    clp->cl_reader ? "TRUE" : "FALSE");
	mdb_printf("%?s  %20s = %d\n", "", "writers", clp->cl_writers);
	mdb_printf("%?s  %20s = 0x%p\n", "", "mutex",
	    addr + ((uintptr_t)clp->cl_mutex - (uintptr_t)clp));
	mdb_printf("%?s  %20s = 0x%p\n", "", "cv",
	    addr + ((uintptr_t)clp->cl_cv - (uintptr_t)clp));
	mdb_printf("\n");

	mdb_free(clp, sizeof (cfglock_t));

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
mod(
	uintptr_t	addr,
	uint_t		flags,
	int		argc,
	const mdb_arg_t	*argv)
{
	int		status;
	int		rc = DCMD_OK;
	mfdata_t	*mfp;

	mfp = mdb_zalloc(sizeof (mfdata_t), UM_SLEEP);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, MF_VERBOSE, &mfp->mf_flags,
	    NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP))
		mfp->mf_banner = B_TRUE;

	if (flags & DCMD_ADDRSPEC) {
		status = mod_format(addr, NULL, mfp);
		rc = (status == WALK_NEXT) ? DCMD_OK : DCMD_ERR;
		goto cleanup;
	}

	if (mdb_pwalk("ipp_byid", mod_format, mfp,
	    ipp_mod_byid) == -1) {
		mdb_warn("failed to execute ipp_byid walk");
		rc = DCMD_ERR;
	}

cleanup:
	mdb_free(mfp, sizeof (mfdata_t));

	return (rc);
}

/*ARGSUSED*/
static int
mod_format(
	uintptr_t	addr,
	const void	*data,
	void		*arg)
{
	mfdata_t	*mfp = (mfdata_t *)arg;
	ipp_mod_t	*imp;
	int		rc;

	imp = mdb_alloc(sizeof (ipp_mod_t), UM_SLEEP);
	if (mdb_vread(imp, sizeof (ipp_mod_t), addr) == -1) {
		mdb_warn("failed to read ipp_mod_t at %p", addr);
		rc = WALK_ERR;
		goto done;
	}

	if (mfp->mf_flags & MF_VERBOSE)
		rc = mod_dump(addr, imp, mfp->mf_banner);
	else
		rc = mod_summary(addr, imp, mfp->mf_banner);

	mfp->mf_banner = B_FALSE;
done:
	mdb_free(imp, sizeof (ipp_mod_t));
	return (rc);
}

/*ARGSUSED*/
static int
mod_dump(
	uintptr_t	addr,
	ipp_mod_t	*imp,
	boolean_t	banner)
{
	mdb_printf("%?p: %20s = %d\n", addr, "id", imp->ippm_id);
	mdb_printf("%?s  %20s = %s\n", "", "name", imp->ippm_name);
	mdb_printf("%?s  %20s = 0x%p\n", "", "ops", imp->ippm_ops);
	mdb_printf("%?s  %20s = 0x%p\n", "", "action", imp->ippm_action);

	mdb_printf("%?s  %20s = ", "", "state");
	switch (imp->ippm_state) {
	case IPP_MODSTATE_PROTO:
		mdb_printf("%s\n", "PROTO");
		break;
	case IPP_MODSTATE_AVAILABLE:
		mdb_printf("%s\n", "AVAILABLE");
		break;
	default:
		mdb_printf("%s\n", "<unknown>");
		break;
	}

	mdb_printf("%?s  %20s = %d\n", "", "hold_count", imp->ippm_hold_count);
	mdb_printf("%?s  %20s = %s\n", "", "destruct_pending",
	    (imp->ippm_destruct_pending) ? "TRUE" : "FALSE");
	mdb_printf("%?s  %20s = 0x%p\n", "", "lock",
	    addr + ((uintptr_t)imp->ippm_lock - (uintptr_t)imp));
	mdb_printf("\n");

	return (WALK_NEXT);
}

static int
mod_summary(
	uintptr_t	addr,
	ipp_mod_t	*imp,
	boolean_t	banner)
{
	if (banner)
		mdb_printf("%?s %<u>%20s %5s%</u>\n",
		    "", "NAME", "ID");

	mdb_printf("%?p:%20s %5d\n", addr, imp->ippm_name, imp->ippm_id);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
ippops(
	uintptr_t	addr,
	uint_t		flags,
	int		argc,
	const mdb_arg_t	*argv)
{
	ipp_ops_t	*ippo;
	GElf_Sym	sym;
	char		buf[MDB_SYM_NAMLEN];

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_ERR);

	ippo = mdb_alloc(sizeof (ipp_ops_t), UM_SLEEP);
	if (mdb_vread(ippo, sizeof (ipp_ops_t), addr) == -1) {
		mdb_warn("failed to read ipp_ops_t at %p", addr);
		mdb_free(ippo, sizeof (ipp_ops_t));
		return (DCMD_ERR);
	}

	mdb_printf("%?p: %20s = %d\n", addr, "rev", ippo->ippo_rev);

	if (mdb_lookup_by_addr((uintptr_t)ippo->ippo_action_create,
	    MDB_SYM_EXACT, buf, MDB_SYM_NAMLEN, &sym) == 0)
		mdb_printf("%?s  %20s = %s\n", "", "action_create", buf);
	else
		mdb_printf("%?s  %20s = 0x%p\n", "", "action_create",
		    ippo->ippo_action_create);

	if (mdb_lookup_by_addr((uintptr_t)ippo->ippo_action_modify,
	    MDB_SYM_EXACT, buf, MDB_SYM_NAMLEN, &sym) == 0)
		mdb_printf("%?s  %20s = %s\n", "", "action_modify", buf);
	else
		mdb_printf("%?s  %20s = 0x%p\n", "", "action_modify",
		    ippo->ippo_action_modify);

	if (mdb_lookup_by_addr((uintptr_t)ippo->ippo_action_destroy,
	    MDB_SYM_EXACT, buf, MDB_SYM_NAMLEN, &sym) == 0)
		mdb_printf("%?s  %20s = %s\n", "", "action_destroy", buf);
	else
		mdb_printf("%?s  %20s = 0x%p\n", "", "action_destroy",
		    ippo->ippo_action_destroy);

	if (mdb_lookup_by_addr((uintptr_t)ippo->ippo_action_info,
	    MDB_SYM_EXACT, buf, MDB_SYM_NAMLEN, &sym) == 0)
		mdb_printf("%?s  %20s = %s\n", "", "action_info", buf);
	else
		mdb_printf("%?s  %20s = 0x%p\n", "", "action_info",
		    ippo->ippo_action_info);

	if (mdb_lookup_by_addr((uintptr_t)ippo->ippo_action_invoke,
	    MDB_SYM_EXACT, buf, MDB_SYM_NAMLEN, &sym) == 0)
		mdb_printf("%?s  %20s = %s\n", "", "action_invoke", buf);
	else
		mdb_printf("%?s  %20s = 0x%p\n", "", "action_invoke",
		    ippo->ippo_action_invoke);

	mdb_printf("\n");

	mdb_free(ippo, sizeof (ipp_ops_t));
	return (DCMD_OK);
}

static int
ref_walk_init(
	mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	return (WALK_NEXT);
}

static int
ref_walk_step(
	mdb_walk_state_t *wsp)
{
	ipp_ref_t	*rp;
	int		status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	rp = mdb_alloc(sizeof (ipp_ref_t), UM_SLEEP);

	if (mdb_vread(rp, sizeof (ipp_ref_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read ipp_ref_t at %p", wsp->walk_addr);
		mdb_free(rp, sizeof (ipp_ref_t));
		return (WALK_ERR);
	}

	status = wsp->walk_callback((uintptr_t)rp->ippr_ptr, NULL,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(rp->ippr_nextp);

	mdb_free(rp, sizeof (ipp_ref_t));
	return (status);
}

/*ARGSUSED*/
static void
ref_walk_fini(
	mdb_walk_state_t *wsp)
{
}

/*ARGSUSED*/
static int
packet(
	uintptr_t	addr,
	uint_t		flags,
	int		argc,
	const mdb_arg_t	*argv)
{
	ipp_packet_t	*pp;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_ERR);

	pp = mdb_alloc(sizeof (ipp_packet_t), UM_SLEEP);
	if (mdb_vread(pp, sizeof (ipp_packet_t), addr) == -1) {
		mdb_warn("failed to read ipp_packet_t at %p", addr);
		mdb_free(pp, sizeof (ipp_packet_t));
		return (DCMD_ERR);
	}

	mdb_printf("%?p: %20s = 0x%p\n", addr, "data", pp->ippp_data);
	mdb_printf("%?s  %20s = 0x%p\n", "", "private", pp->ippp_private);
	dump_classes((uintptr_t)pp->ippp_class_array, pp->ippp_class_windex);
	dump_log((uintptr_t)pp->ippp_log, pp->ippp_log_windex);

	mdb_free(pp, sizeof (ipp_packet_t));
	return (DCMD_OK);
}

static void
dump_classes(
	uintptr_t	ptr,
	uint_t		nelt)
{
	ipp_class_t	*array;
	ipp_class_t	*cp;
	uint_t		i;
	boolean_t	first_time = B_TRUE;
	char		buf[MAXNAMELEN];

	array = mdb_alloc(sizeof (ipp_class_t) * nelt, UM_SLEEP);
	if (mdb_vread(array, sizeof (ipp_class_t) * nelt, ptr) == -1) {
		mdb_warn("failed to read ipp_class_t array at %p", ptr);
		return;
	}

	for (i = 0; i < nelt; i++) {
		if (first_time) {
			mdb_printf("%20s  %?s   %<u>%15s %15s%</u>\n", "",
			    "classes", "NAME", "ACTION");
			first_time = B_FALSE;
		}

		cp = &(array[i]);
		aid2aname(cp->ippc_aid, buf);
		mdb_printf("%20s  %?p:  %15s %15s%\n", "",
		    ptr + (i * sizeof (ipp_class_t)), cp->ippc_name, buf);
	}

	mdb_free(cp, sizeof (ipp_class_t) * nelt);
}

static void
dump_log(
	uintptr_t	ptr,
	uint_t		nelt)
{
	ipp_log_t	*array;
	ipp_log_t	*lp;
	uint_t		i;
	boolean_t	first_time = B_TRUE;
	char		buf[MAXNAMELEN];

	array = mdb_alloc(sizeof (ipp_log_t) * nelt, UM_SLEEP);
	if (mdb_vread(array, sizeof (ipp_log_t) * nelt, ptr) == -1) {
		mdb_warn("failed to read ipp_log_t array at %p", ptr);
		return;
	}

	for (i = 0; i < nelt; i++) {
		if (first_time) {
			mdb_printf("%20s  %?s   %<u>%15s %15s%</u>\n", "",
			    "log", "CLASS NAME", "ACTION");
			first_time = B_FALSE;
		}

		lp = &(array[i]);
		aid2aname(lp->ippl_aid, buf);
		mdb_printf("%20s  %?p:  %15s %15s\n", "",
		    ptr + (i * sizeof (ipp_class_t)), lp->ippl_name, buf);
	}

	mdb_free(lp, sizeof (ipp_log_t) * nelt);
}

static void
aid2aname(
	ipp_action_id_t	aid,
	char		*buf)
{
	uintptr_t	addr;
	uintptr_t	ptr;
	ipp_action_t	*ap;

	switch (aid) {
	case IPP_ACTION_INVAL:
		strcpy(buf, "invalid");
		break;
	case IPP_ACTION_CONT:
		strcpy(buf, "continue");
		break;
	case IPP_ACTION_DEFER:
		strcpy(buf, "defer");
		break;
	case IPP_ACTION_DROP:
		strcpy(buf, "drop");
		break;
	default:
		if (mdb_vread(&addr, sizeof (uintptr_t),
		    ipp_action_byid) == -1) {
			mdb_warn("failed to read from address %p",
			    ipp_action_byid);
			strcpy(buf, "???");
			break;
		}

		addr += ((int32_t)aid * sizeof (void *));
		if (mdb_vread(&ptr, sizeof (uintptr_t), addr) == -1) {
			mdb_warn("failed to read from address %p", addr);
			strcpy(buf, "???");
			break;
		}

		ap = mdb_alloc(sizeof (ipp_action_t), UM_SLEEP);
		if (mdb_vread(ap, sizeof (ipp_action_t), ptr) == -1) {
			mdb_warn("failed to read ipp_action_t at %p", ptr);
			mdb_free(ap, sizeof (ipp_action_t));
			strcpy(buf, "???");
			break;
		}

		if (ap->ippa_id != aid) {
			mdb_warn("corrupt action at %p", ptr);
			mdb_free(ap, sizeof (ipp_action_t));
			strcpy(buf, "???");
			break;
		}

		strcpy(buf, ap->ippa_name);
	}
}

static const mdb_dcmd_t dcmds[] = {
	{ "ipp_action", "?[-v]",
	    "display ipp_action structure", action },
	{ "ipp_mod", "?[-v]",
	    "display ipp_mod structure", mod },
	{ "cfglock", ":",
	    "display cfglock structure", cfglock },
	{ "ippops", ":",
	    "display ipp_ops structure", ippops },
	{ "ipp_packet", ":",
	    "display ipp_packet structure", packet },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "ipp_byid", "walk byid array", byid_walk_init, byid_walk_step,
	    byid_walk_fini },
	{ "ipp_ref", "walk reference list", ref_walk_init, ref_walk_step,
	    ref_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t ipp_modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	GElf_Sym sym;

	if (mdb_lookup_by_name("ipp_action_byid", &sym) == -1) {
		mdb_warn("failed to lookup 'ipp_action_byid'");
		return (NULL);
	}

	ipp_action_byid = (uintptr_t)sym.st_value;

	if (mdb_lookup_by_name("ipp_mod_byid", &sym) == -1) {
		mdb_warn("failed to lookup 'ipp_mod_byid'");
		return (NULL);
	}

	ipp_mod_byid = (uintptr_t)sym.st_value;

	return (&ipp_modinfo);
}
