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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <alloca.h>
#include <libgen.h>
#include <stddef.h>

#include <dt_impl.h>
#include <dt_program.h>
#include <dt_pid.h>
#include <dt_string.h>

typedef struct dt_pid_probe {
	dtrace_hdl_t		*dpp_dtp;
	struct ps_prochandle	*dpp_pr;
	const char		*dpp_mod;
	char			*dpp_func;
	const char		*dpp_name;
	const char		*dpp_obj;
	uintptr_t		dpp_pc;
	size_t			dpp_size;
	Lmid_t			dpp_lmid;
	uint_t			dpp_nmatches;
	uint64_t		dpp_stret[4];
	GElf_Sym		dpp_last;
	uint_t			dpp_last_taken;
} dt_pid_probe_t;

/*
 * Compose the lmid and object name into the canonical representation. We
 * omit the lmid for the default link map for convenience.
 */
static void
dt_pid_objname(char *buf, size_t len, Lmid_t lmid, const char *obj)
{
	if (lmid == LM_ID_BASE)
		(void) strncpy(buf, obj, len);
	else
		(void) snprintf(buf, len, "LM%lx`%s", lmid, obj);
}

static void
dt_pid_error(dtrace_hdl_t *dtp, dt_errtag_t tag, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	dt_set_errmsg(dtp, dt_errtag(tag), NULL, NULL, 0, fmt, ap);
	va_end(ap);
}

static void
dt_pid_per_sym(dt_pid_probe_t *pp, const GElf_Sym *symp, const char *func)
{
	fasttrap_probe_spec_t *ftp;
	uint64_t off;
	char *end;
	uint_t nmatches = 0;
	ulong_t sz;
	int glob, err;
	int isdash = strcmp("-", func) == 0;
	pid_t pid;

	pid = Pstatus(pp->dpp_pr)->pr_pid;

	dt_dprintf("creating probe pid%d:%s:%s:%s\n", (int)pid, pp->dpp_obj,
	    func, pp->dpp_name);

	sz = sizeof (fasttrap_probe_spec_t) + (isdash ? 4 :
	    (symp->st_size - 1) * sizeof (ftp->ftps_offs[0]));

	if (sz < 4000) {
		ftp = alloca(sz);
		sz = 0;
	} else if ((ftp = malloc(sz)) == NULL) {
		dt_dprintf("proc_per_sym: malloc(%lu) failed\n", sz);
		return;
	}

	ftp->ftps_pid = pid;
	(void) strncpy(ftp->ftps_func, func, sizeof (ftp->ftps_func));

	dt_pid_objname(ftp->ftps_mod, sizeof (ftp->ftps_mod), pp->dpp_lmid,
	    pp->dpp_obj);

	if (!isdash && gmatch("return", pp->dpp_name)) {
		if (dt_pid_create_return_probe(pp->dpp_pr, pp->dpp_dtp,
		    ftp, symp, pp->dpp_stret) < 0)
			goto create_err;

		nmatches++;
	}

	if (!isdash && gmatch("entry", pp->dpp_name)) {
		if (dt_pid_create_entry_probe(pp->dpp_pr, pp->dpp_dtp,
		    ftp, symp) < 0)
			goto create_err;

		nmatches++;
	}

	glob = strisglob(pp->dpp_name);
	if (!glob && nmatches == 0) {
		off = strtoull(pp->dpp_name, &end, 16);
		if (*end != '\0') {
			if (sz != 0)
				free(ftp);
			dt_proc_release(pp->dpp_dtp, pp->dpp_pr);
			xyerror(D_PROC_NAME, "'%s' is an invalid probe name\n",
			    pp->dpp_name);
		}

		if (off >= symp->st_size) {
			dt_pid_error(pp->dpp_dtp, D_PROC_OFF, "offset "
			    "0x%llx outside of function '%s'\n",
			    (u_longlong_t)off, func);
			goto out;
		}

		err = dt_pid_create_offset_probe(pp->dpp_pr, pp->dpp_dtp, ftp,
		    symp, off);

		if (err == DT_PROC_ERR)
			goto create_err;
		if (err == DT_PROC_ALIGN) {
#ifdef __sparc
			if (sz != 0)
				free(ftp);
			dt_proc_release(pp->dpp_dtp, pp->dpp_pr);
			xyerror(D_PROC_ALIGN, "offset 0x%llx is not properly "
			    "aligned\n", (u_longlong_t)off);
#else
			dt_pid_error(pp->dpp_dtp, D_PROC_ALIGN, "offset "
			    "0x%llx is not aligned on an instruction\n",
			    (u_longlong_t)off);
			goto out;
#endif
		}

		nmatches++;

	} else if (glob && !isdash) {
		if (dt_pid_create_glob_offset_probes(pp->dpp_pr,
		    pp->dpp_dtp, ftp, symp, pp->dpp_name) < 0)
			goto create_err;

		nmatches++;
	}

	pp->dpp_nmatches += nmatches;

out:
	if (sz != 0)
		free(ftp);
	return;

create_err:
	if (sz != 0)
		free(ftp);

	dt_proc_release(pp->dpp_dtp, pp->dpp_pr);
	dt_pid_error(pp->dpp_dtp, D_PROC_CREATEFAIL, "failed to create "
	    "probe in process %d: %s", (int)pid,
	    dtrace_errmsg(pp->dpp_dtp, dtrace_errno(pp->dpp_dtp)));
}

static int
dt_pid_sym_filt(void *arg, const GElf_Sym *symp, const char *func)
{
	dt_pid_probe_t *pp = arg;

	if (symp->st_shndx == SHN_UNDEF)
		return (0);

	if (symp->st_size == 0) {
		dt_dprintf("st_size of %s is zero\n", func);
		return (0);
	}

	if (symp->st_value != pp->dpp_last.st_value ||
	    symp->st_size != pp->dpp_last.st_size) {
		/*
		 * Due to 4524008, _init and _fini may have a bloated st_size.
		 * While this bug has been fixed for a while, old binaries
		 * may exist that still exhibit this problem. As a result, we
		 * don't match _init and _fini though we allow users to
		 * specify them explicitly.
		 */
		if (strcmp(func, "_init") == 0 || strcmp(func, "_fini") == 0)
			return (0);

		if (gmatch(func, pp->dpp_func)) {
			dt_pid_per_sym(pp, symp, func);
			pp->dpp_last_taken = 1;
		}

		pp->dpp_last = *symp;
	}

	return (0);
}

static void
dt_pid_per_mod(void *arg, const prmap_t *pmp, const char *obj)
{
	dt_pid_probe_t *pp = arg;
	GElf_Sym sym;

	if (obj == NULL)
		return;

	(void) Plmid(pp->dpp_pr, pmp->pr_vaddr, &pp->dpp_lmid);

	if ((pp->dpp_obj = strrchr(obj, '/')) == NULL)
		pp->dpp_obj = obj;
	else
		pp->dpp_obj++;

	if (Pxlookup_by_name(pp->dpp_pr, pp->dpp_lmid, obj, ".stret1", &sym,
	    NULL) == 0)
		pp->dpp_stret[0] = sym.st_value;
	else
		pp->dpp_stret[0] = 0;

	if (Pxlookup_by_name(pp->dpp_pr, pp->dpp_lmid, obj, ".stret2", &sym,
	    NULL) == 0)
		pp->dpp_stret[1] = sym.st_value;
	else
		pp->dpp_stret[1] = 0;

	if (Pxlookup_by_name(pp->dpp_pr, pp->dpp_lmid, obj, ".stret4", &sym,
	    NULL) == 0)
		pp->dpp_stret[2] = sym.st_value;
	else
		pp->dpp_stret[2] = 0;

	if (Pxlookup_by_name(pp->dpp_pr, pp->dpp_lmid, obj, ".stret8", &sym,
	    NULL) == 0)
		pp->dpp_stret[3] = sym.st_value;
	else
		pp->dpp_stret[3] = 0;

	dt_dprintf("%s stret %llx %llx %llx %llx\n", obj,
	    (u_longlong_t)pp->dpp_stret[0], (u_longlong_t)pp->dpp_stret[1],
	    (u_longlong_t)pp->dpp_stret[2], (u_longlong_t)pp->dpp_stret[3]);

	/*
	 * If pp->dpp_func contains any globbing meta-characters, we need
	 * to iterate over the symbol table and compare each function name
	 * against the pattern.
	 */
	if (!strisglob(pp->dpp_func)) {
		/*
		 * If we fail to lookup the symbol, try interpreting the
		 * function as the special "-" function that indicates that the
		 * probe name should be interpreted as a absolute virtual
		 * address. If that fails and we were matching a specific
		 * function in a specific module, report the error, otherwise
		 * just fail silently in the hopes that some other object will
		 * contain the desired symbol.
		 */
		if (Pxlookup_by_name(pp->dpp_pr, pp->dpp_lmid, obj,
		    pp->dpp_func, &sym, NULL) != 0) {
			if (strcmp("-", pp->dpp_func) == 0) {
				sym.st_name = 0;
				sym.st_info =
				    GELF_ST_INFO(STB_LOCAL, STT_FUNC);
				sym.st_other = 0;
				sym.st_value = 0;
				sym.st_size = Pstatus(pp->dpp_pr)->pr_dmodel ==
				    PR_MODEL_ILP32 ? -1U : -1ULL;

			} else if (!strisglob(pp->dpp_mod)) {
				dt_proc_release(pp->dpp_dtp, pp->dpp_pr);
				xyerror(D_PROC_FUNC, "failed to lookup '%s' "
				    "in module '%s'\n", pp->dpp_func,
				    pp->dpp_mod);
			} else {
				return;
			}
		}

		/*
		 * Only match defined functions of non-zero size.
		 */
		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC ||
		    sym.st_shndx == SHN_UNDEF || sym.st_size == 0)
			return;

		/*
		 * We don't instrument PLTs -- they're dynamically rewritten,
		 * and, so, inherently dicey to instrument.
		 */
		if (Ppltdest(pp->dpp_pr, sym.st_value) != NULL)
			return;

		(void) Plookup_by_addr(pp->dpp_pr, sym.st_value, pp->dpp_func,
		    DTRACE_FUNCNAMELEN, &sym);

		dt_pid_per_sym(pp, &sym, pp->dpp_func);
	} else {
		uint_t nmatches = pp->dpp_nmatches;

		(void) Psymbol_iter_by_addr(pp->dpp_pr, obj, PR_SYMTAB,
		    BIND_ANY | TYPE_FUNC, dt_pid_sym_filt, pp);

		if (nmatches == pp->dpp_nmatches) {
			/*
			 * If we didn't match anything in the PR_SYMTAB, try
			 * the PR_DYNSYM.
			 */
			(void) Psymbol_iter_by_addr(pp->dpp_pr, obj, PR_DYNSYM,
			    BIND_ANY | TYPE_FUNC, dt_pid_sym_filt, pp);
		}
	}
}

static int
dt_pid_mod_filt(void *arg, const prmap_t *pmp, const char *obj)
{
	dt_pid_probe_t *pp = arg;

	if (gmatch(obj, pp->dpp_mod)) {
		dt_pid_per_mod(pp, pmp, obj);
	} else {
		char name[DTRACE_MODNAMELEN];

		(void) Plmid(pp->dpp_pr, pmp->pr_vaddr, &pp->dpp_lmid);

		if ((pp->dpp_obj = strrchr(obj, '/')) == NULL)
			pp->dpp_obj = obj;
		else
			pp->dpp_obj++;

		dt_pid_objname(name, sizeof (name), pp->dpp_lmid, obj);

		if (gmatch(name, pp->dpp_mod))
			dt_pid_per_mod(pp, pmp, obj);
	}

	return (0);
}

static const prmap_t *
dt_pid_fix_mod(dtrace_probedesc_t *pdp, struct ps_prochandle *P)
{
	char m[MAXPATHLEN];
	Lmid_t lmid = PR_LMID_EVERY;
	const char *obj;
	const prmap_t *pmp;

	/*
	 * Pick apart the link map from the library name.
	 */
	if (strchr(pdp->dtpd_mod, '`') != NULL) {
		char *end;

		if (strncmp(pdp->dtpd_mod, "LM", 2) != 0 ||
		    !isdigit(pdp->dtpd_mod[2]))
			return (NULL);

		lmid = strtoul(&pdp->dtpd_mod[2], &end, 16);

		obj = end + 1;

		if (*end != '`' || strchr(obj, '`') != NULL)
			return (NULL);

	} else {
		obj = pdp->dtpd_mod;
	}

	if ((pmp = Plmid_to_map(P, lmid, obj)) == NULL)
		return (NULL);

	(void) Pobjname(P, pmp->pr_vaddr, m, sizeof (m));
	if ((obj = strrchr(m, '/')) == NULL)
		obj = &m[0];
	else
		obj++;

	(void) Plmid(P, pmp->pr_vaddr, &lmid);
	dt_pid_objname(pdp->dtpd_mod, sizeof (pdp->dtpd_mod), lmid, obj);

	return (pmp);
}


static void
dt_pid_create_pid_probes(dtrace_probedesc_t *pdp, dtrace_hdl_t *dtp, pid_t pid)
{
	dt_pid_probe_t pp;

	pp.dpp_pr = dt_proc_grab(dtp, pid, PGRAB_RDONLY | PGRAB_FORCE, 0);
	if (pp.dpp_pr == NULL)
		longjmp(dtp->dt_pcb->pcb_jmpbuf, EDT_COMPILER);

	/*
	 * We can only trace dynamically-linked executables (since we've
	 * hidden some magic in ld.so.1 as well as libc.so.1).
	 */
	if (Pname_to_map(pp.dpp_pr, PR_OBJ_LDSO) == NULL) {
		dt_proc_release(dtp, pp.dpp_pr);
		xyerror(D_PROC_DYN, "process %s is not a dynamically-linked "
		    "executable\n", &pdp->dtpd_provider[3]);
	}

	pp.dpp_dtp = dtp;
	pp.dpp_mod = pdp->dtpd_mod[0] != '\0' ? pdp->dtpd_mod : "*";
	pp.dpp_func = pdp->dtpd_func[0] != '\0' ? pdp->dtpd_func : "*";
	pp.dpp_name = pdp->dtpd_name[0] != '\0' ? pdp->dtpd_name : "*";

	if (strcmp(pp.dpp_func, "-") == 0) {
		const prmap_t *aout, *pmp;

		if (pdp->dtpd_mod[0] == '\0') {
			pp.dpp_mod = pdp->dtpd_mod;
			(void) strcpy(pdp->dtpd_mod, "a.out");
		} else if (strisglob(pp.dpp_mod) ||
		    (aout = Pname_to_map(pp.dpp_pr, "a.out")) == NULL ||
		    (pmp = Pname_to_map(pp.dpp_pr, pp.dpp_mod)) == NULL ||
		    aout->pr_vaddr != pmp->pr_vaddr) {
			dt_proc_release(dtp, pp.dpp_pr);
			xyerror(D_PROC_LIB, "only the a.out module is valid "
			    "with the '-' function\n");
		}

		if (strisglob(pp.dpp_name)) {
			dt_proc_release(dtp, pp.dpp_pr);
			xyerror(D_PROC_NAME, "only individual addresses may "
			    "be specified with the '-' function\n");
		}
	}

	/*
	 * If pp.dpp_mod contains any globbing meta-characters, we need
	 * to iterate over each module and compare its name against the
	 * pattern. An empty module name is treated as '*'.
	 */
	if (strisglob(pp.dpp_mod)) {
		(void) Pobject_iter(pp.dpp_pr, dt_pid_mod_filt, &pp);
	} else {
		const prmap_t *pmp;
		char *obj;

		/*
		 * If can't find a matching module, don't sweat it -- either
		 * we'll fail the enabling because the probes don't exist or
		 * we'll wait for that module to come along.
		 */
		if ((pmp = dt_pid_fix_mod(pdp, pp.dpp_pr)) != NULL) {
			if ((obj = strchr(pdp->dtpd_mod, '`')) == NULL)
				obj = pdp->dtpd_mod;
			else
				obj++;

			dt_pid_per_mod(&pp, pmp, obj);
		}
	}

	dt_proc_release(dtp, pp.dpp_pr);
}

static int
dt_pid_usdt_mapping(void *data, const prmap_t *pmp, const char *oname)
{
	struct ps_prochandle *P = data;
	GElf_Sym sym;
	prsyminfo_t sip;
	int fd;
	dof_helper_t dh;
	GElf_Half e_type;
	const char *mname;
	const char *syms[] = { "___SUNW_dof", "__SUNW_dof" };
	int i;

	/*
	 * The symbol ___SUNW_dof is for lazy-loaded DOF sections, and
	 * __SUNW_dof is for actively-loaded DOF sections. We try to force
	 * in both types of DOF section since the process may not yet have
	 * run the code to instantiate these providers.
	 */
	for (i = 0; i < 2; i++) {
		if (Pxlookup_by_name(P, PR_LMID_EVERY, oname, syms[i], &sym,
		    &sip) != 0) {
			continue;
		}

		if ((mname = strrchr(oname, '/')) == NULL)
			mname = oname;
		else
			mname++;

		dt_dprintf("lookup of %s succeeded for %s\n", syms[i], mname);

		if (Pread(P, &e_type, sizeof (e_type), pmp->pr_vaddr +
		    offsetof(Elf64_Ehdr, e_type)) != sizeof (e_type)) {
			dt_dprintf("read of ELF header failed");
			continue;
		}

		dh.dofhp_dof = sym.st_value;
		dh.dofhp_addr = (e_type == ET_EXEC) ? 0 : pmp->pr_vaddr;

		dt_pid_objname(dh.dofhp_mod, sizeof (dh.dofhp_mod),
		    sip.prs_lmid, mname);

		if ((fd = pr_open(P, "/dev/dtrace/helper", O_RDWR, 0)) < 0) {
			dt_dprintf("pr_open of helper device failed: %s\n",
			    strerror(errno));
			return (errno);
		}

		(void) pr_ioctl(P, fd, DTRACEHIOC_ADDDOF, &dh, sizeof (dh));

		if (pr_close(P, fd) != 0)
			return (errno);
	}

	return (0);
}

static int
dt_pid_create_usdt_probes(dtrace_probedesc_t *pdp, dt_proc_t *dpr)
{
	struct ps_prochandle *P = dpr->dpr_proc;
	int err;

	assert(DT_MUTEX_HELD(&dpr->dpr_lock));

	(void) Pupdate_maps(P);
	err = Pobject_iter(P, dt_pid_usdt_mapping, P);

	/*
	 * Put the module name in its canonical form.
	 */
	(void) dt_pid_fix_mod(pdp, P);

	return (err);
}

static pid_t
dt_pid_get_pid(dtrace_probedesc_t *pdp, int *errp)
{
	pid_t pid;
	char *c, *last = NULL, *end;

	for (c = &pdp->dtpd_provider[0]; *c != '\0'; c++) {
		if (!isdigit(*c))
			last = c;
	}

	if (last == NULL || (*(++last) == '\0')) {
		if (errp != NULL) {
			*errp = D_PROC_BADPROV;
			return (-1);
		}
		xyerror(D_PROC_BADPROV, "%s is not a valid provider\n",
		    pdp->dtpd_provider);
	}

	errno = 0;
	pid = strtol(last, &end, 10);

	if (errno != 0 || end == last || end[0] != '\0' || pid <= 0) {
		if (errp != NULL) {
			*errp = D_PROC_BADPID;
			return (-1);
		}
		xyerror(D_PROC_BADPID, "%s does not contain a valid pid\n",
		    pdp->dtpd_provider);
	}

	if (errp != NULL)
		*errp = 0;

	return (pid);
}

void
dt_pid_create_probes(dtrace_probedesc_t *pdp, dtrace_hdl_t *dtp)
{
	pid_t pid = dt_pid_get_pid(pdp, NULL);
	char provname[DTRACE_PROVNAMELEN];
	struct ps_prochandle *P;
	dt_proc_t *dpr;
	int err = 0;

	if (dtp->dt_ftfd == -1) {
		if (dtp->dt_fterr == ENOENT) {
			xyerror(D_PROC_NODEV, "pid provider is not "
			    "installed on this system\n");
		} else {
			xyerror(D_PROC_NODEV, "pid provider is not "
			    "available: %s\n", strerror(dtp->dt_fterr));
		}
	}

	(void) snprintf(provname, sizeof (provname), "pid%d", (int)pid);

	if (strcmp(provname, pdp->dtpd_provider) == 0) {
		dt_pid_create_pid_probes(pdp, dtp, pid);
	} else {
		if ((P = dt_proc_grab(dtp, pid, 0, 1)) == NULL)
			longjmp(dtp->dt_pcb->pcb_jmpbuf, EDT_COMPILER);

		dpr = dt_proc_lookup(dtp, P, 0);
		assert(dpr != NULL);

		(void) pthread_mutex_lock(&dpr->dpr_lock);

		if (!dpr->dpr_usdt) {
			err = dt_pid_create_usdt_probes(pdp, dpr);
			dpr->dpr_usdt = B_TRUE;
		}

		(void) pthread_mutex_unlock(&dpr->dpr_lock);

		dt_proc_release(dtp, P);

		if (err != 0)
			dt_pid_error(dtp, D_PROC_USDT, "failed to instantiate "
			    "probes for PID %d: %s", (int)pid, strerror(err));
	}
}

void
dt_pid_create_probes_module(dtrace_hdl_t *dtp, dt_proc_t *dpr)
{
	dtrace_prog_t *pgp;
	dt_stmt_t *stp;
	char provname[DTRACE_PROVNAMELEN];
	dtrace_probedesc_t *pdp, pd;
	pid_t pid;
	int err;
	int found = B_FALSE;

	for (pgp = dt_list_next(&dtp->dt_programs); pgp != NULL;
	    pgp = dt_list_next(pgp)) {

		for (stp = dt_list_next(&pgp->dp_stmts); stp != NULL;
		    stp = dt_list_next(stp)) {

			pdp = &stp->ds_desc->dtsd_ecbdesc->dted_probe;
			pid = dt_pid_get_pid(pdp, &err);
			if (err != 0 || pid != dpr->dpr_pid)
				continue;

			found = B_TRUE;

			pd = *pdp;

			(void) snprintf(provname, sizeof (provname), "pid%d",
			    (int)pid);

			if (strcmp(provname, pdp->dtpd_provider) == 0)
				dt_pid_create_pid_probes(&pd, dtp, pid);
			else
				(void) dt_pid_create_usdt_probes(&pd, dpr);
		}
	}

	if (found) {
		/*
		 * Give DTrace a shot to the ribs to get it to check
		 * out the newly created probes.
		 */
		(void) dt_ioctl(dtp, DTRACEIOC_ENABLE, NULL);
	}
}
