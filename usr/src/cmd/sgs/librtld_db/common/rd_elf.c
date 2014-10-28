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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#include	<stdlib.h>
#include	<stdio.h>
#include	<proc_service.h>
#include	<link.h>
#include	<rtld_db.h>
#include	<rtld.h>
#include	<alist.h>
#include	<list.h>
#include	<_rtld_db.h>
#include	<msg.h>
#include	<limits.h>
#include	<string.h>
#include	<sys/param.h>

/*
 * We want to include zone.h to pull in the prototype for zone_get_nroot(),
 * but we need to avoid pulling in <sys/stream.h>, which has a definition
 * of M_DATA that conflicts with the ELF-related definition in machdep_*.h.
 */
#define		_SYS_STREAM_H
#include	<zone.h>

/*
 * 64-bit builds are going to compile this module twice, the
 * second time with _ELF64 defined.  These defines should make
 * all the necessary adjustments to the code.
 */
#ifdef _LP64
#ifdef _ELF64
#define	_rd_event_enable32	_rd_event_enable64
#define	_rd_event_getmsg32	_rd_event_getmsg64
#define	_rd_get_dyns32		_rd_get_dyns64
#define	_rd_get_ehdr32		_rd_get_ehdr64
#define	_rd_objpad_enable32	_rd_objpad_enable64
#define	_rd_loadobj_iter32	_rd_loadobj_iter64
#define	_rd_reset32		_rd_reset64
#define	find_dynamic_ent32	find_dynamic_ent64
#define	validate_rdebug32	validate_rdebug64
#define	TAPlist			APlist
#define	TLm_list		Lm_list
#define	TList			List
#define	TListnode		Listnode
#define	MSG_SYM_BRANDOPS	MSG_SYM_BRANDOPS_64
#else	/* ELF32 */
#define	Rt_map			Rt_map32
#define	Rtld_db_priv		Rtld_db_priv32
#define	TAPlist			APlist32
#define	TLm_list		Lm_list32
#define	TList			List32
#define	TListnode		Listnode32
#define	Lm_list			Lm_list32
#define	MSG_SYM_BRANDOPS	MSG_SYM_BRANDOPS_32
#endif	/* _ELF64 */
#else	/* _LP64 */
#define	TAPlist			APlist
#define	TLm_list		Lm_list
#define	TList			List
#define	TListnode		Listnode
#define	MSG_SYM_BRANDOPS	MSG_SYM_BRANDOPS_32
#endif	/* _LP64 */

/*
 * BrandZ added ps_pbrandname().  Many debuggers that link directly
 * against librtld_db.so may not implement this interface.  Hence
 * we won't call the function directly, instead we'll try to look it
 * up using the linker first and only invoke it if we find it.
 */
typedef ps_err_e (*ps_pbrandname_fp_t)(struct ps_prochandle *,
    char *, size_t);

rd_err_e
validate_rdebug32(struct rd_agent *rap)
{
	struct ps_prochandle	*php = rap->rd_psp;
	psaddr_t		db_privp;
	Rtld_db_priv		db_priv;

	if (rap->rd_rdebug == 0)
		return (RD_ERR);

	/*
	 * The rtld_db_priv structure contains both the traditional (exposed)
	 * r_debug structure as well as private data only available to
	 * this library.
	 */
	db_privp = rap->rd_rdebug;

	/*
	 * Verify that librtld_db & rtld are at the proper revision
	 * levels.
	 */
	if (ps_pread(php, db_privp, (char *)&db_priv,
	    sizeof (Rtld_db_priv)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READPRIVFAIL_1),
		    EC_ADDR(db_privp)));
		return (RD_DBERR);
	}

	if ((db_priv.rtd_version < R_RTLDDB_VERSION1) ||
	    (db_priv.rtd_version > R_RTLDDB_VERSION)) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_BADPVERS),
		    db_priv.rtd_version, R_RTLDDB_VERSION));
		return (RD_NOCAPAB);
	}

	/*
	 * Is the image being examined from a core file or not.
	 * If it is a core file then the following write will fail.
	 */
	if (ps_pwrite(php, db_privp, (char *)&db_priv,
	    sizeof (Rtld_db_priv)) != PS_OK)
		rap->rd_flags |= RDF_FL_COREFILE;

	rap->rd_rdebugvers = db_priv.rtd_version;
	rap->rd_rtlddbpriv = db_privp;

	LOG(ps_plog(MSG_ORIG(MSG_DB_VALIDRDEBUG), EC_ADDR(rap->rd_rdebug),
	    R_RTLDDB_VERSION, rap->rd_rdebugvers,
	    rap->rd_flags & RDF_FL_COREFILE));
	return (RD_OK);
}


rd_err_e
find_dynamic_ent32(struct rd_agent *rap, psaddr_t dynaddr,
	Xword dyntag, Dyn *dyn)
{
	struct ps_prochandle	*php = rap->rd_psp;
	Dyn			d;

	d.d_tag = DT_NULL;
	do {
		if (ps_pread(php, dynaddr, (void *)(&d), sizeof (d)) !=
		    PS_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_4),
			    EC_ADDR(dynaddr)));
			return (RD_DBERR);
		}
		dynaddr += sizeof (d);
		if (d.d_tag == dyntag)
			break;
	} while (d.d_tag != DT_NULL);
	if (d.d_tag == dyntag) {
		*dyn = d;
		LOG(ps_plog(MSG_ORIG(MSG_DB_FINDDYNAMIC), EC_ADDR(dyntag),
		    EC_ADDR(d.d_un.d_val)));
		return (RD_OK);
	}
	LOG(ps_plog(MSG_ORIG(MSG_DB_NODYNDEBUG), EC_ADDR(dyntag)));
	return (RD_DBERR);
}

extern char rtld_db_helper_path[MAXPATHLEN];

rd_err_e
_rd_reset32(struct rd_agent *rap)
{
	psaddr_t		symaddr;
	struct ps_prochandle	*php = rap->rd_psp;
	const auxv_t		*auxvp = NULL;
	rd_err_e		rc = RD_OK;
	char			brandname[MAXPATHLEN];
	char			brandlib[MAXPATHLEN];
	ps_pbrandname_fp_t	ps_pbrandname;

	/*
	 * librtld_db attempts three different methods to find
	 * the r_debug structure which is required to
	 * initialize itself.  The methods are:
	 *	method1:
	 *		entirely independent of any text segment
	 *		and relies on the AT_SUN_LDDATA auxvector
	 *		to find the ld.so.1::rdebug structure.
	 *	method2:
	 *		lookup symbols in ld.so.1's symbol table
	 *		to find the r_debug symbol.
	 *	method3:
	 *		(old dbx method) dependent upon the
	 *		text segment/symbol table of the
	 *		executable and not ld.so.1.  We lookup the
	 *		_DYNAMIC symbol in the executable and look for
	 *		the DT_DEBUG entry in the .dynamic table.  This
	 *		points to rdebug.
	 *
	 * If none of that works - we fail.
	 */
	LOG(ps_plog(MSG_ORIG(MSG_DB_RDRESET), rap->rd_dmodel));
	/*
	 * Method1
	 *
	 * Scan the aux vector looking for AT_BASE & AT_SUN_LDDATA
	 */

	if (ps_pauxv(php, &auxvp) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_NOAUXV)));
		rc = RD_ERR;
	}

	rap->rd_rdebug = 0;

	if (auxvp != NULL) {
		rc = RD_ERR;
		while (auxvp->a_type != AT_NULL) {
			if (auxvp->a_type == AT_SUN_LDDATA) {
				/* LINTED */
				rap->rd_rdebug = (uintptr_t)auxvp->a_un.a_ptr;
				LOG(ps_plog(MSG_ORIG(MSG_DB_FLDDATA),
				    rap->rd_rdebug));
				rc = validate_rdebug32(rap);
				break;
			}
			auxvp++;
		}
	}

	/*
	 * method2 - look for r_rdebug symbol in ld.so.1
	 */
	if (rc != RD_OK) {
		/*
		 * If the AT_SUN_LDDATA auxv vector is not present
		 * fall back on doing a symlookup of
		 * the r_debug symbol.  This is for backward
		 * compatiblity with older OS's
		 */
		LOG(ps_plog(MSG_ORIG(MSG_DB_NOLDDATA)));
		if (ps_pglobal_lookup(php, PS_OBJ_LDSO, MSG_ORIG(MSG_SYM_DEBUG),
		    &symaddr) != PS_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_LOOKFAIL),
			    MSG_ORIG(MSG_SYM_DEBUG)));
			rc = RD_DBERR;
		} else {
			rap->rd_rdebug = symaddr;
			LOG(ps_plog(MSG_ORIG(MSG_DB_SYMRDEBUG),
			    EC_ADDR(symaddr)));
			rc = validate_rdebug32(rap);
		}
	}


	/*
	 * method3 - find DT_DEBUG in the executables .dynamic section.
	 */
	if (rc != RD_OK) {
		Dyn	dyn;
		if (ps_pglobal_lookup(php, PS_OBJ_EXEC,
		    MSG_ORIG(MSG_SYM_DYNAMIC), &symaddr) != PS_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_NODYNAMIC)));
			LOG(ps_plog(MSG_ORIG(MSG_DB_INITFAILED)));
			return (rc);
		}
		rc = find_dynamic_ent32(rap, symaddr, DT_DEBUG, &dyn);
		if (rc != RD_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_INITFAILED)));
			return (rc);
		}
		rap->rd_rdebug = dyn.d_un.d_ptr;
		rc = validate_rdebug32(rap);
		if (rc != RD_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_INITFAILED)));
			return (rc);
		}
	}

	/*
	 * If we are debugging a branded executable, load the appropriate
	 * helper library, and call its initialization routine.  Being unable
	 * to load the helper library is not a critical error.  (Hopefully
	 * we'll still be able to access some objects in the target.)  Note
	 * that we pull in the native root here to allow for helper libraries
	 * to be properly found from within the branded zone.
	 */
	ps_pbrandname = (ps_pbrandname_fp_t)dlsym(RTLD_PROBE, "ps_pbrandname");
	while ((ps_pbrandname != NULL) &&
	    (ps_pbrandname(php, brandname, MAXPATHLEN) == PS_OK)) {
		const char *isa = "";

#ifdef _LP64
		isa = MSG_ORIG(MSG_DB_64BIT_PREFIX);
#endif /* _LP64 */

		if (rtld_db_helper_path[0] != '\0') {
			(void) snprintf(brandlib, MAXPATHLEN,
			    MSG_ORIG(MSG_DB_BRAND_HELPERPATH_PREFIX),
			    rtld_db_helper_path,
			    MSG_ORIG(MSG_DB_HELPER_PREFIX), brandname, isa,
			    brandname);
		} else {
			const char *nroot = zone_get_nroot();

			if (nroot == NULL)
				nroot = "";

			(void) snprintf(brandlib, MAXPATHLEN,
			    MSG_ORIG(MSG_DB_BRAND_HELPERPATH), nroot,
			    MSG_ORIG(MSG_DB_HELPER_PREFIX), brandname, isa,
			    brandname);
		}

		rap->rd_helper.rh_dlhandle = dlopen(brandlib,
		    RTLD_LAZY | RTLD_LOCAL);
		if (rap->rd_helper.rh_dlhandle == NULL) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_HELPERLOADFAILED),
			    brandlib));
			break;
		}

		rap->rd_helper.rh_ops = dlsym(rap->rd_helper.rh_dlhandle,
		    MSG_ORIG(MSG_SYM_BRANDOPS));
		if (rap->rd_helper.rh_ops == NULL) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_HELPERNOOPS),
			    brandlib));
			(void) dlclose(rap->rd_helper.rh_dlhandle);
			rap->rd_helper.rh_dlhandle = NULL;
			break;
		}

		rap->rd_helper.rh_data = rap->rd_helper.rh_ops->rho_init(rap,
		    php);
		if (rap->rd_helper.rh_data == NULL) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_HELPERINITFAILED)));
			(void) dlclose(rap->rd_helper.rh_dlhandle);
			rap->rd_helper.rh_dlhandle = NULL;
			rap->rd_helper.rh_ops = NULL;
			break;
		}

		LOG(ps_plog(MSG_ORIG(MSG_DB_HELPERLOADED), brandname));
		break;

		/* NOTREACHED */
	}

	if ((rap->rd_flags & RDF_FL_COREFILE) == 0) {
		if (ps_pglobal_lookup(php, PS_OBJ_LDSO,
		    MSG_ORIG(MSG_SYM_PREINIT), &symaddr) != PS_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_LOOKFAIL),
			    MSG_ORIG(MSG_SYM_PREINIT)));
			return (RD_DBERR);
		}
		rap->rd_preinit = symaddr;

		if (ps_pglobal_lookup(php, PS_OBJ_LDSO,
		    MSG_ORIG(MSG_SYM_POSTINIT), &symaddr) != PS_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_LOOKFAIL),
			    MSG_ORIG(MSG_SYM_POSTINIT)));
			return (RD_DBERR);
		}
		rap->rd_postinit = symaddr;

		if (ps_pglobal_lookup(php, PS_OBJ_LDSO,
		    MSG_ORIG(MSG_SYM_DLACT), &symaddr) != PS_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_LOOKFAIL),
			    MSG_ORIG(MSG_SYM_DLACT)));
			return (RD_DBERR);
		}
		rap->rd_dlact = symaddr;
		rap->rd_tbinder = 0;
	}

	return (RD_OK);
}

rd_err_e
_rd_get_ehdr32(struct rd_agent *rap,
    psaddr_t addr, Ehdr *ehdr, uint_t *phnum)
{
	struct ps_prochandle	*php = rap->rd_psp;
	Shdr			shdr;

	if (ps_pread(php, addr, ehdr, sizeof (*ehdr)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_5), EC_ADDR(addr)));
		return (RD_ERR);
	}
	if (phnum == NULL)
		return (RD_OK);

	if (ehdr->e_phnum != PN_XNUM) {
		*phnum = ehdr->e_phnum;
		return (RD_OK);
	}

	/* deal with elf extended program headers */
	if ((ehdr->e_shoff == 0) || (ehdr->e_shentsize < sizeof (shdr)))
		return (RD_ERR);

	addr += ehdr->e_shoff;
	if (ps_pread(php, addr, &shdr, sizeof (shdr)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_5), EC_ADDR(addr)));
		return (RD_ERR);
	}

	if (shdr.sh_info == 0)
		return (RD_ERR);

	*phnum = shdr.sh_info;
	return (RD_OK);
}

rd_err_e
_rd_get_dyns32(rd_agent_t *rap, psaddr_t addr, Dyn **dynpp, size_t *dynpp_sz)
{
	struct ps_prochandle	*php = rap->rd_psp;
	rd_err_e		err;
	uint_t			phnum;
	Ehdr			ehdr;
	Phdr			phdr;
	Dyn			*dynp;
	int			i;

	/* We only need to muck with dyn elements for ET_DYN objects */
	if ((err = _rd_get_ehdr32(rap, addr, &ehdr, &phnum)) != RD_OK)
		return (err);

	for (i = 0; i < phnum; i++) {
		psaddr_t a = addr + ehdr.e_phoff + (i * ehdr.e_phentsize);
		if (ps_pread(php, a, &phdr, sizeof (phdr)) != PS_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_6), EC_ADDR(a)));
			return (RD_ERR);
		}
		if (phdr.p_type == PT_DYNAMIC)
			break;
	}
	if (i == phnum)
		return (RD_ERR);

	if ((dynp = malloc(phdr.p_filesz)) == NULL)
		return (RD_ERR);
	if (ehdr.e_type == ET_DYN)
		phdr.p_vaddr += addr;
	if (ps_pread(php, phdr.p_vaddr, dynp, phdr.p_filesz) != PS_OK) {
		free(dynp);
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_6),
		    EC_ADDR(phdr.p_vaddr)));
		return (RD_ERR);
	}

	*dynpp = dynp;
	if (dynpp_sz != NULL)
		*dynpp_sz = phdr.p_filesz;
	return (RD_OK);
}

rd_err_e
_rd_event_enable32(rd_agent_t *rap, int onoff)
{
	struct ps_prochandle	*php = rap->rd_psp;
	Rtld_db_priv		rdb;

	LOG(ps_plog(MSG_ORIG(MSG_DB_RDEVENTENABLE), rap->rd_dmodel, onoff));
	/*
	 * Tell the debugged process that debugging is occuring
	 * This will enable the storing of event messages so that
	 * the can be gathered by the debugger.
	 */
	if (ps_pread(php, rap->rd_rdebug, (char *)&rdb,
	    sizeof (Rtld_db_priv)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_1),
		    EC_ADDR((uintptr_t)&rdb)));
		return (RD_DBERR);
	}

	if (onoff)
		rdb.rtd_rdebug.r_flags |= RD_FL_DBG;
	else
		rdb.rtd_rdebug.r_flags &= ~RD_FL_DBG;

	if (ps_pwrite(php, rap->rd_rdebug, (char *)&rdb,
	    sizeof (Rtld_db_priv)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_WRITEFAIL_1),
		    EC_ADDR((uintptr_t)&rdb)));
		return (RD_DBERR);
	}

	return (RD_OK);
}


rd_err_e
_rd_event_getmsg32(rd_agent_t *rap, rd_event_msg_t *emsg)
{
	Rtld_db_priv	rdb;

	if (ps_pread(rap->rd_psp, rap->rd_rdebug, (char *)&rdb,
	    sizeof (Rtld_db_priv)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READDBGFAIL_2),
		    EC_ADDR(rap->rd_rdebug)));
		return (RD_DBERR);
	}
	emsg->type = rdb.rtd_rdebug.r_rdevent;
	if (emsg->type == RD_DLACTIVITY) {
		switch (rdb.rtd_rdebug.r_state) {
			case RT_CONSISTENT:
				emsg->u.state = RD_CONSISTENT;
				break;
			case RT_ADD:
				emsg->u.state = RD_ADD;
				break;
			case RT_DELETE:
				emsg->u.state = RD_DELETE;
				break;
		}
	} else
		emsg->u.state = RD_NOSTATE;

	LOG(ps_plog(MSG_ORIG(MSG_DB_RDEVENTGETMSG), rap->rd_dmodel,
	    emsg->type, emsg->u.state));

	return (RD_OK);
}


rd_err_e
_rd_objpad_enable32(struct rd_agent *rap, size_t padsize)
{
	Rtld_db_priv		db_priv;
	struct ps_prochandle	*php = rap->rd_psp;

	LOG(ps_plog(MSG_ORIG(MSG_DB_RDOBJPADE), EC_ADDR(padsize)));

	if (ps_pread(php, rap->rd_rtlddbpriv, (char *)&db_priv,
	    sizeof (Rtld_db_priv)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_3),
		    EC_ADDR(rap->rd_rtlddbpriv)));
		return (RD_DBERR);
	}
#if	defined(_LP64) && !defined(_ELF64)
	/*LINTED*/
	db_priv.rtd_objpad = (uint32_t)padsize;
#else
	db_priv.rtd_objpad = padsize;
#endif
	if (ps_pwrite(php, rap->rd_rtlddbpriv, (char *)&db_priv,
	    sizeof (Rtld_db_priv)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_WRITEFAIL_2),
		    EC_ADDR(rap->rd_rtlddbpriv)));
		return (RD_DBERR);
	}
	return (RD_OK);
}

static rd_err_e
iter_map(rd_agent_t *rap, unsigned long ident, psaddr_t lmaddr,
	rl_iter_f *cb, void *client_data, uint_t *abort_iterp)
{
	while (lmaddr) {
		Rt_map		rmap;
		rd_loadobj_t	lobj;
		int		i;
		ulong_t		off;
		Ehdr		ehdr;
		Phdr		phdr;

		if (ps_pread(rap->rd_psp, lmaddr, (char *)&rmap,
		    sizeof (Rt_map)) != PS_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_LKMAPFAIL)));
			return (RD_DBERR);
		}

		/*
		 * As of 'VERSION5' we only report objects
		 * which have been fully relocated.  While the maps
		 * might be in a consistent state - if a object hasn't
		 * been relocated - it's not really ready for the debuggers
		 * to examine.  This is mostly due to the fact that we
		 * might still be mucking with the text-segment, if
		 * we are - we could conflict with any break-points
		 * the debuggers might have set.
		 */
		if (rap->rd_rdebugvers >= R_RTLDDB_VERSION5) {
			if ((FLAGS(&rmap) & FLG_RT_RELOCED) == 0) {
				lmaddr = (psaddr_t)NEXT(&rmap);
				continue;
			}
		}

		lobj.rl_base = (psaddr_t)ADDR(&rmap);
		lobj.rl_flags = 0;
		lobj.rl_refnameaddr = (psaddr_t)REFNAME(&rmap);
		if ((rap->rd_helper.rh_ops != NULL) &&
		    (rap->rd_helper.rh_ops->rho_lmid != LM_ID_NONE))
			lobj.rl_lmident =
			    rap->rd_helper.rh_ops->rho_lmid;
		else
			lobj.rl_lmident = ident;

		/*
		 * refnameaddr is only valid from a core file
		 * which is VERSION3 or greater.
		 */
		if (rap->rd_rdebugvers < R_RTLDDB_VERSION3) {
			lobj.rl_nameaddr = (psaddr_t)NAME(&rmap);
			lobj.rl_bend = 0;
			lobj.rl_padstart = 0;
			lobj.rl_padend = 0;
		} else {
			lobj.rl_nameaddr = (psaddr_t)PATHNAME(&rmap);
			lobj.rl_bend = ADDR(&rmap) + MSIZE(&rmap);
			lobj.rl_padstart = PADSTART(&rmap);
			lobj.rl_padend = PADSTART(&rmap) + PADIMLEN(&rmap);

		}

		if (rtld_db_version >= RD_VERSION2)
			if (FLAGS(&rmap) & FLG_RT_IMGALLOC)
				lobj.rl_flags |= RD_FLG_MEM_OBJECT;
		if (rtld_db_version >= RD_VERSION2) {
			lobj.rl_dynamic = (psaddr_t)DYN(&rmap);
		}

		if (rtld_db_version >= RD_VERSION4)
			lobj.rl_tlsmodid = TLSMODID(&rmap);

		/*
		 * Look for beginning of data segment.
		 *
		 * NOTE: the data segment can only be found for full
		 *	processes and not from core images.
		 */
		lobj.rl_data_base = 0;
		if (rap->rd_flags & RDF_FL_COREFILE)
			lobj.rl_data_base = 0;
		else {
			off = ADDR(&rmap);
			if (ps_pread(rap->rd_psp, off, (char *)&ehdr,
			    sizeof (Ehdr)) != PS_OK) {
				LOG(ps_plog(MSG_ORIG(MSG_DB_LKMAPFAIL)));
				return (RD_DBERR);
			}
			off += sizeof (Ehdr);
			for (i = 0; i < ehdr.e_phnum; i++) {
				if (ps_pread(rap->rd_psp, off, (char *)&phdr,
				    sizeof (Phdr)) != PS_OK) {
					LOG(ps_plog(MSG_ORIG(
					    MSG_DB_LKMAPFAIL)));
					return (RD_DBERR);
				}
				if ((phdr.p_type == PT_LOAD) &&
				    (phdr.p_flags & PF_W)) {
					lobj.rl_data_base = phdr.p_vaddr;
					if (ehdr.e_type == ET_DYN)
						lobj.rl_data_base +=
						    ADDR(&rmap);
					break;
				}
				off += ehdr.e_phentsize;
			}
		}

		/*
		 * When we transfer control to the client we free the
		 * lock and re-atain it after we've returned from the
		 * client.  This is to avoid any deadlock situations.
		 */
		LOG(ps_plog(MSG_ORIG(MSG_DB_ITERMAP), cb, client_data,
		    EC_ADDR(lobj.rl_base), EC_ADDR(lobj.rl_lmident)));
		RDAGUNLOCK(rap);
		if ((*cb)(&lobj, client_data) == 0) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_CALLBACKR0)));
			RDAGLOCK(rap);
			*abort_iterp = 1;
			break;
		}
		RDAGLOCK(rap);
		lmaddr = (psaddr_t)NEXT(&rmap);
	}
	return (RD_OK);
}


static rd_err_e
_rd_loadobj_iter32_native(rd_agent_t *rap, rl_iter_f *cb, void *client_data,
    uint_t *abort_iterp)
{
	Rtld_db_priv	db_priv;
	TAPlist		apl;
	uintptr_t	datap, nitems;
	Addr		addr;
	rd_err_e	rc;

	LOG(ps_plog(MSG_ORIG(MSG_DB_LOADOBJITER), rap->rd_dmodel, cb,
	    client_data));

	/*
	 * First, determine whether the link-map information has been
	 * established.  Some debuggers have made an initial call to this
	 * function with a null call back function (cb), but expect a
	 * RD_NOMAPS error return rather than a RD_ERR return when the
	 * link-maps aren't available.
	 */
	if (ps_pread(rap->rd_psp, rap->rd_rtlddbpriv, (char *)&db_priv,
	    sizeof (Rtld_db_priv)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READDBGFAIL_1),
		    EC_ADDR(rap->rd_rtlddbpriv)));
		return (RD_DBERR);
	}

	if (db_priv.rtd_dynlmlst == NULL) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_LKMAPNOINIT),
		    EC_ADDR((uintptr_t)db_priv.rtd_dynlmlst)));
		return (RD_NOMAPS);
	}

	if (ps_pread(rap->rd_psp, (psaddr_t)db_priv.rtd_dynlmlst, (char *)&addr,
	    sizeof (Addr)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READDBGFAIL_3),
		    EC_ADDR((uintptr_t)db_priv.rtd_dynlmlst)));
		return (RD_DBERR);
	}

	if (addr == NULL) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_LKMAPNOINIT_1),
		    EC_ADDR((uintptr_t)db_priv.rtd_dynlmlst)));
		return (RD_NOMAPS);
	}

	/*
	 * Having determined we have link-maps, ensure we have an iterator
	 * call back function.
	 */
	if (cb == NULL) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_NULLITER)));
		return (RD_ERR);
	}

	/*
	 * As of VERSION6, rtd_dynlmlst points to an APlist.  Prior to VERSION6
	 * rtd_dynlmlst pointed to a List.  But, there was a window where the
	 * version was not incremented, and this must be worked around by
	 * interpreting the APlist data.  Read the initial APlist information.
	 */
	if (ps_pread(rap->rd_psp, (psaddr_t)addr, (char *)&apl,
	    sizeof (TAPlist)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READDBGFAIL_4),
		    EC_ADDR((uintptr_t)addr)));
		return (RD_DBERR);
	}

	/*
	 * The rtd_dynlmlst change from a List to an APlist occurred under
	 * 6801536 in snv_112.  However, this change neglected to preserve
	 * backward compatibility by maintaining List processing and using a
	 * version increment to detect the change.  6862967, intergrated in
	 * snv_121 corrects the version detection.  However, to catch objects
	 * built between these releases, we look at the first element of the
	 * APlist.  apl_arritems indicates the number of APlist items that are
	 * available.  This was originally initialized with a AL_CNT_DYNLIST
	 * value of 2 (one entry for LM_ID_BASE and one entry for LM_ID_LDSO).
	 * It is possible that the use of an auditor results in an additional
	 * link-map list, in which case the original apl_arritems would have
	 * been doubled.
	 *
	 * Therefore, if the debugging verion is VERSION6, or the apl_arritems
	 * entry has a value less than or equal to 4 and the debugging version
	 * is VERSION5, then we process APlists.  Otherwise, fall back to List
	 * processing.
	 */
	if ((rap->rd_rdebugvers >= R_RTLDDB_VERSION6) ||
	    ((rap->rd_rdebugvers == R_RTLDDB_VERSION5) &&
	    (apl.apl_arritems <= 4))) {
		/*
		 * Iterate through each apl.ap_data[] entry.
		 */
		for (datap = (uintptr_t)((char *)(uintptr_t)addr +
		    ((size_t)(((TAPlist *)0)->apl_data))), nitems = 0;
		    nitems < apl.apl_nitems; nitems++, datap += sizeof (Addr)) {
			TLm_list	lm;
			ulong_t		ident;

			/*
			 * Obtain the Lm_list address for this apl.ap_data[]
			 * entry.
			 */
			if (ps_pread(rap->rd_psp, (psaddr_t)datap,
			    (char *)&addr, sizeof (Addr)) != PS_OK) {
				LOG(ps_plog(MSG_ORIG(MSG_DB_READDBGFAIL_5),
				    EC_ADDR(datap)));
				return (RD_DBERR);
			}

			/*
			 * Obtain the Lm_list data for this Lm_list address.
			 */
			if (ps_pread(rap->rd_psp, (psaddr_t)addr, (char *)&lm,
			    sizeof (TLm_list)) != PS_OK) {
				LOG(ps_plog(MSG_ORIG(MSG_DB_READDBGFAIL_6),
				    EC_ADDR((uintptr_t)addr)));
				return (RD_DBERR);
			}

			/*
			 * Determine IDENT of current LM_LIST
			 */
			if (lm.lm_flags & LML_FLG_BASELM)
				ident = LM_ID_BASE;
			else if (lm.lm_flags & LML_FLG_RTLDLM)
				ident = LM_ID_LDSO;
			else
				ident = (ulong_t)addr;

			if ((rc = iter_map(rap, ident, (psaddr_t)lm.lm_head,
			    cb, client_data, abort_iterp)) != RD_OK)
				return (rc);

			if (*abort_iterp != 0)
				break;
		}
	} else {
		TList		list;
		TListnode	lnode;
		Addr		lnp;

		/*
		 * Re-read the dynlmlst address to obtain a List structure.
		 */
		if (ps_pread(rap->rd_psp, (psaddr_t)db_priv.rtd_dynlmlst,
		    (char *)&list, sizeof (TList)) != PS_OK) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_READDBGFAIL_3),
			    EC_ADDR((uintptr_t)db_priv.rtd_dynlmlst)));
			return (RD_DBERR);
		}

		/*
		 * Iterate through the link-map list.
		 */
		for (lnp = (Addr)list.head; lnp; lnp = (Addr)lnode.next) {
			Lm_list	lml;
			ulong_t	ident;

			/*
			 * Iterate through the List of Lm_list's.
			 */
			if (ps_pread(rap->rd_psp, (psaddr_t)lnp, (char *)&lnode,
			    sizeof (TListnode)) != PS_OK) {
				LOG(ps_plog(MSG_ORIG(MSG_DB_READDBGFAIL_4),
				    EC_ADDR(lnp)));
					return (RD_DBERR);
			}

			if (ps_pread(rap->rd_psp, (psaddr_t)lnode.data,
			    (char *)&lml, sizeof (Lm_list)) != PS_OK) {
				LOG(ps_plog(MSG_ORIG(MSG_DB_READDBGFAIL_5),
				    EC_ADDR((uintptr_t)lnode.data)));
					return (RD_DBERR);
			}

			/*
			 * Determine IDENT of current LM_LIST
			 */
			if (lml.lm_flags & LML_FLG_BASELM)
				ident = LM_ID_BASE;
			else if (lml.lm_flags & LML_FLG_RTLDLM)
				ident = LM_ID_LDSO;
			else
				ident = (unsigned long)lnode.data;

			if ((rc = iter_map(rap, ident, (psaddr_t)lml.lm_head,
			    cb, client_data, abort_iterp)) != RD_OK)
				return (rc);

			if (*abort_iterp != 0)
				break;
		}
	}

	return (rc);
}

rd_err_e
_rd_loadobj_iter32(rd_agent_t *rap, rl_iter_f *cb, void *client_data)
{
	rd_err_e	rc, rc_brand = RD_OK;
	uint_t		abort_iter = 0;

	/* First iterate over the native target objects */
	rc = _rd_loadobj_iter32_native(rap, cb, client_data, &abort_iter);
	if (abort_iter != 0)
		return (rc);

	/* Then iterate over any branded objects. */
	if ((rap->rd_helper.rh_ops != NULL) &&
	    (rap->rd_helper.rh_ops->rho_loadobj_iter != NULL))
		rc_brand = rap->rd_helper.rh_ops->rho_loadobj_iter(
		    rap->rd_helper.rh_data, cb, client_data);

	rc = (rc != RD_OK) ? rc : rc_brand;
	return (rc);
}
