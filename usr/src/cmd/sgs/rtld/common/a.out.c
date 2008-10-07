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
 */

/*
 * Object file dependent support for a.out format objects.
 */

#include	<a.out.h>		/* Explicitly override M_SEGSIZE */
#include	<machdep.h>		/*	used in M_SROUND */

#include	<sys/mman.h>
#include	<unistd.h>
#include	<string.h>
#include	<limits.h>
#include	<stdio.h>
#include	<dlfcn.h>
#include	<errno.h>
#include	<debug.h>
#include	"_a.out.h"
#include	"cache_a.out.h"
#include	"msg.h"
#include	"_rtld.h"

/*
 * Default and secure dependency search paths.
 */
static Pnode		aout_dflt_dirs[] = {
	{ MSG_ORIG(MSG_PTH_USR4LIB),	0,	MSG_PTH_USR4LIB_SIZE,
		LA_SER_DEFAULT,		0,	&aout_dflt_dirs[1] },
	{ MSG_ORIG(MSG_PTH_USRLIB),	0,	MSG_PTH_USRLIB_SIZE,
		LA_SER_DEFAULT,		0,	&aout_dflt_dirs[2] },
	{ MSG_ORIG(MSG_PTH_USRLCLIB),	0,	MSG_PTH_USRLCLIB_SIZE,
		LA_SER_DEFAULT,		0, 0 }
};

static Pnode		aout_secure_dirs[] = {
#ifndef	SGS_PRE_UNIFIED_PROCESS
	{ MSG_ORIG(MSG_PTH_LIBSE),	0,	MSG_PTH_LIBSE_SIZE,
		LA_SER_SECURE,		0,	&aout_secure_dirs[1] },
#endif
	{ MSG_ORIG(MSG_PTH_USRLIBSE),	0,	MSG_PTH_USRLIBSE_SIZE,
		LA_SER_SECURE,		0, 0 }
};

/*
 * Defines for local functions.
 */
static int		aout_are_u();
static ulong_t		aout_entry_pt();
static Rt_map		*aout_map_so();
static void		aout_unmap_so();
static int		aout_needed();
extern Sym		*aout_lookup_sym();
static Sym		*aout_find_sym();
static char		*aout_get_so();
static Pnode		*aout_fix_name();
static void		aout_dladdr();
static Sym		*aout_dlsym_handle();
static int		aout_verify_vers();

/*
 * Functions and data accessed through indirect pointers.
 */
Fct aout_fct = {
	aout_are_u,
	aout_entry_pt,
	aout_map_so,
	aout_unmap_so,
	aout_needed,
	aout_lookup_sym,
	aout_reloc,
	aout_dflt_dirs,
	aout_secure_dirs,
	aout_fix_name,
	aout_get_so,
	aout_dladdr,
	aout_dlsym_handle,
	aout_verify_vers,
	aout_set_prot
};


/*
 * In 4.x, a needed file or a dlopened file that was a simple file name implied
 * that the file be found in the present working directory.  To simulate this
 * lookup within the elf rules it is necessary to add a proceeding `./' to the
 * filename.
 */
static Pnode *
aout_fix_name(const char *name, Rt_map *clmp)
{
	size_t	len;
	Pnode	*pnp;

	if ((pnp = calloc(1, sizeof (Pnode))) == 0)
		return (0);

	/*
	 * Check for slash in name, if none, prepend "./", otherwise just
	 * return name given.
	 */
	if (strchr(name, '/')) {
		len = strlen(name) + 1;
		if ((pnp->p_name = malloc(len)) != 0)
			(void) strcpy((char *)pnp->p_name, name);
	} else {
		len = strlen(name) + 3;
		if ((pnp->p_name = malloc(len)) != 0)
			(void) snprintf((char *)pnp->p_name, len,
			    MSG_ORIG(MSG_FMT_4XPATH), name);
	}

	if (pnp->p_name) {
		pnp->p_len = len;
		DBG_CALL(Dbg_file_fixname(LIST(clmp), pnp->p_name, name));
		return (pnp);
	}
	free(pnp);
	return (0);
}

/*
 * Determine if we have been given an A_OUT file.  Returns 1 if true.
 */
static int
aout_are_u()
{
	struct exec *exec;

	/* LINTED */
	exec = (struct exec *)fmap->fm_maddr;
	if (fmap->fm_fsize < sizeof (exec) || (exec->a_machtype != M_SPARC) ||
	    (N_BADMAG(*exec))) {
		return (0);
	}
	return (1);
}

/*
 * Return the entry point the A_OUT executable. This is always zero.
 */
static ulong_t
aout_entry_pt()
{
	return (0);
}

/*
 * Unmap a given A_OUT shared object from the address space.
 */
static void
aout_unmap_so(Rt_map *lmp)
{
	Mmap	*immap = MMAPS(lmp);

	(void) munmap(immap->m_vaddr, immap->m_msize);
}

/*
 * Dummy versioning interface - real functionality is only applicable to elf.
 */
static int
aout_verify_vers()
{
	return (1);
}

/*
 * Search through the dynamic section for DT_NEEDED entries and perform one
 * of two functions.  If only the first argument is specified then load the
 * defined shared object, otherwise add the link map representing the
 * defined link map the the dlopen list.
 */
static int
aout_needed(Lm_list *lml, Aliste lmco, Rt_map *clmp, int *in_nfavl)
{
	void	*need;

	for (need = &TEXTBASE(clmp)[AOUTDYN(clmp)->v2->ld_need];
	    need != &TEXTBASE(clmp)[0];
	    need = &TEXTBASE(clmp)[((Lnk_obj *)(need))->lo_next]) {
		Rt_map	*nlmp;
		char	*name;
		Pnode	*pnp;

		name = &TEXTBASE(clmp)[((Lnk_obj *)(need))->lo_name];

		if (((Lnk_obj *)(need))->lo_library) {
			/*
			 * If lo_library field is not NULL then this needed
			 * library was linked in using the "-l" option.
			 * Thus we need to rebuild the library name before
			 * trying to load it.
			 */
			Pnode	*dir, *dirlist = (Pnode *)0;
			char	*file;
			size_t	len;

			/*
			 * Allocate name length plus 20 for full library name.
			 * lib.so.. = 7 + (2 * short) + NULL = 7 + 12 + 1 = 20
			 */
			len = strlen(name) + 20;
			if ((file = malloc(len)) == 0)
				return (0);
			(void) snprintf(file, len, MSG_ORIG(MSG_FMT_4XLIB),
			    name, ((Lnk_obj *)(need))->lo_major,
			    ((Lnk_obj *)(need))->lo_minor);

			DBG_CALL(Dbg_libs_find(lml, file));

			/*
			 * We need to determine what filename will match the
			 * the filename specified (ie, a libc.so.1.2 may match
			 * to a libc.so.1.3).  It's the real pathname that is
			 * recorded in the link maps.  If we are presently
			 * being traced, skip this pathname generation so
			 * that we fall through into load_so() to print the
			 * appropriate diagnostics.  I don't like this at all.
			 */
			if (lml->lm_flags & LML_FLG_TRC_ENABLE)
				name = file;
			else {
				char	*path = (char *)0;

				for (dir = get_next_dir(&dirlist, clmp, 0); dir;
				    dir = get_next_dir(&dirlist, clmp, 0)) {
					if (dir->p_name == 0)
						continue;

					if (path =
					    aout_get_so(dir->p_name, file))
						break;
				}
				if (!path) {
					eprintf(lml, ERR_FATAL,
					    MSG_INTL(MSG_SYS_OPEN), file,
					    strerror(ENOENT));
					return (0);
				}
				name = path;
			}
			if ((pnp = expand_paths(clmp, name, 0, 0)) == 0)
				return (0);
		} else {
			/*
			 * If the library is specified as a pathname, see if
			 * it must be fixed to specify the current working
			 * directory (ie. libc.so.1.2 -> ./libc.so.1.2).
			 */
			if ((pnp = aout_fix_name(name, clmp)) == 0)
				return (0);
		}

		DBG_CALL(Dbg_file_needed(clmp, name));

		nlmp = load_one(lml, lmco, pnp, clmp, MODE(clmp), 0, 0,
		    in_nfavl);
		remove_pnode(pnp);
		if (((nlmp == 0) || (bind_one(clmp, nlmp, BND_NEEDED) == 0)) &&
		    ((lml->lm_flags & LML_FLG_TRC_ENABLE) == 0))
			return (0);
	}

	return (1);
}

static Sym *
aout_symconvert(struct nlist *sp)
{
	static Sym	sym;

	sym.st_value = sp->n_value;
	sym.st_size = 0;
	sym.st_info = 0;
	sym.st_other = 0;
	switch (sp->n_type) {
		case N_EXT + N_ABS:
			sym.st_shndx = SHN_ABS;
			break;
		case N_COMM:
			sym.st_shndx = SHN_COMMON;
			break;
		case N_EXT + N_UNDF:
			sym.st_shndx = SHN_UNDEF;
			break;
		default:
			sym.st_shndx = 0;
			break;
	}
	return (&sym);
}

/*
 * Process a.out format commons.
 */
static struct nlist *
aout_find_com(struct nlist *sp, const char *name)
{
	static struct rtc_symb	*rtcp = 0;
	struct rtc_symb		*rs, * trs;
	const char		*sl;
	char			*cp;

	/*
	 * See if common is already allocated.
	 */
	trs = rtcp;
	while (trs) {
		sl = name;
		cp = trs->rtc_sp->n_un.n_name;
		while (*sl == *cp++)
			if (*sl++ == '\0')
				return (trs->rtc_sp);
		trs = trs->rtc_next;
	}

	/*
	 * If we got here, common is not already allocated so allocate it.
	 */
	if ((rs = malloc(sizeof (struct rtc_symb))) == 0)
		return (0);
	if ((rs->rtc_sp = malloc(sizeof (struct nlist))) == 0)
		return (0);
	trs = rtcp;
	rtcp = rs;
	rs->rtc_next = trs;
	*(rs->rtc_sp) = *sp;
	if ((rs->rtc_sp->n_un.n_name = malloc(strlen(name) + 1)) == 0)
		return (0);
	(void) strcpy(rs->rtc_sp->n_un.n_name, name);
	rs->rtc_sp->n_type = N_COMM;
	if ((rs->rtc_sp->n_value = (long)calloc(rs->rtc_sp->n_value, 1)) == 0)
		return (0);
	return (rs->rtc_sp);
}

/*
 * Find a.out format symbol in the specified link map.  Unlike the sister
 * elf routine we re-calculate the symbols hash value for each link map
 * we're looking at.
 */
static struct nlist *
aout_findsb(const char *aname, Rt_map *lmp, int flag)
{
	const char	*name = aname;
	char		*cp;
	struct fshash	*p;
	int		i;
	struct nlist	*sp;
	ulong_t		hval = 0;

#define	HASHMASK	0x7fffffff
#define	RTHS		126

	/*
	 * The name passed to us is in ELF format, thus it is necessary to
	 * map this back to the A_OUT format to compute the hash value (see
	 * mapping rules in aout_lookup_sym()).  Basically the symbols are
	 * mapped according to whether a leading `.' exists.
	 *
	 *	elf symbol		a.out symbol
	 * i.	   .bar		->	   .bar		(LKUP_LDOT)
	 * ii.	   .nuts	->	    nuts
	 * iii.	    foo		->	   _foo
	 */
	if (*name == '.') {
		if (!(flag & LKUP_LDOT))
			name++;
	} else
		hval = '_';

	while (*name)
		hval = (hval << 1) + *name++;
	hval = hval & HASHMASK;

	i = hval % (AOUTDYN(lmp)->v2->ld_buckets == 0 ? RTHS :
	    AOUTDYN(lmp)->v2->ld_buckets);
	p = LM2LP(lmp)->lp_hash + i;

	if (p->fssymbno != -1)
		do {
			sp = &LM2LP(lmp)->lp_symtab[p->fssymbno];
			cp = &LM2LP(lmp)->lp_symstr[sp->n_un.n_strx];
			name = aname;
			if (*name == '.') {
				if (!(flag & LKUP_LDOT))
					name++;
			} else {
				cp++;
			}
			while (*name == *cp++) {
				if (*name++ == '\0')
					return (sp);	/* found */
			}
			if (p->next == 0)
				return (0);		/* not found */
			else
				continue;
		} while ((p = &LM2LP(lmp)->lp_hash[p->next]) != 0);
	return (0);
}

/*
 * The symbol name we have been asked to look up is in A_OUT format, this
 * symbol is mapped to the appropriate ELF format which is the standard by
 * which symbols are passed around ld.so.1.  The symbols are mapped
 * according to whether a leading `_' or `.' exists.
 *
 *	a.out symbol		elf symbol
 * i.	   _foo		->	    foo
 * ii.	   .bar		->	   .bar		(LKUP_LDOT)
 * iii.	    nuts	->	   .nuts
 */
Sym *
aout_lookup_sym(Slookup *slp, Rt_map **dlmp, uint_t *binfo, int *in_nfavl)
{
	char	name[PATH_MAX];
	Slookup	sl = *slp;

	DBG_CALL(Dbg_syms_lookup_aout(LIST(slp->sl_imap), slp->sl_name));

	if (*sl.sl_name == '_')
		++sl.sl_name;
	else if (*sl.sl_name == '.')
		sl.sl_flags |= LKUP_LDOT;
	else {
		name[0] = '.';
		(void) strcpy(&name[1], sl.sl_name);
		sl.sl_name = name;
	}

	/*
	 * Call the generic lookup routine to cycle through the specified
	 * link maps.
	 */
	return (lookup_sym(&sl, dlmp, binfo, in_nfavl));
}

/*
 * Symbol lookup for an a.out format module.
 */
/* ARGSUSED3 */
static Sym *
aout_find_sym(Slookup *slp, Rt_map **dlmp, uint_t *binfo, int *in_nfavl)
{
	const char	*name = slp->sl_name;
	Rt_map		*ilmp = slp->sl_imap;
	struct nlist	*sp;

	DBG_CALL(Dbg_syms_lookup(ilmp, name, MSG_ORIG(MSG_STR_AOUT)));

	if (sp = aout_findsb(name, ilmp, slp->sl_flags)) {
		if (sp->n_value != 0) {
			/*
			 * is it a common?
			 */
			if (sp->n_type == (N_EXT + N_UNDF)) {
				if ((sp = aout_find_com(sp, name)) == 0)
					return ((Sym *)0);
			}
			*dlmp = ilmp;
			*binfo |= DBG_BINFO_FOUND;
			return (aout_symconvert(sp));
		}
	}
	return ((Sym *)0);
}

/*
 * Map in an a.out format object.
 * Takes an open file descriptor for the object to map and
 * its pathname; returns a pointer to a Rt_map structure
 * for this object, or 0 on error.
 */
static Rt_map *
aout_map_so(Lm_list *lml, Aliste lmco, const char *pname, const char *oname,
    int fd)
{
	struct exec	*exec;		/* working area for object headers */
	caddr_t		addr;		/* mmap result temporary */
	struct link_dynamic *ld;	/* dynamic pointer of object mapped */
	size_t		size;		/* size of object */
	Rt_map		*lmp;		/* link map created */
	int		err;
	struct nlist	*nl;

	/*
	 * Map text and allocate enough address space to fit the whole
	 * library.  Note that we map enough to catch the first symbol
	 * in the symbol table and thereby avoid an "lseek" & "read"
	 * pair to pick it up.
	 */
	/* LINTED */
	exec = (struct exec *)fmap->fm_maddr;
	size = max(SIZE(*exec), N_SYMOFF(*exec) + sizeof (struct nlist));
	if ((addr = mmap(0, size, (PROT_READ | PROT_EXEC), MAP_PRIVATE,
	    fd, 0)) == MAP_FAILED) {
		err = errno;
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_MMAP), pname,
		    strerror(err));
		return (0);
	}

	/*
	 * Grab the first symbol entry while we've got it mapped aligned
	 * to file addresses.  We assume that this symbol describes the
	 * object's link_dynamic.
	 */
	/* LINTED */
	nl = (struct nlist *)&addr[N_SYMOFF(*exec)];
	/* LINTED */
	ld = (struct link_dynamic *)&addr[nl->n_value];

	/*
	 * Map the initialized data portion of the file to the correct
	 * point in the range of allocated addresses.  This will leave
	 * some portion of the data segment "doubly mapped" on machines
	 * where the text/data relocation alignment is not on a page
	 * boundaries.  However, leaving the file mapped has the double
	 * advantage of both saving the munmap system call and of leaving
	 * us a contiguous chunk of address space devoted to the object --
	 * in case we need to unmap it all later.
	 */
	if (mmap((caddr_t)(addr + M_SROUND(exec->a_text)),
	    (int)exec->a_data, (PROT_READ | PROT_WRITE | PROT_EXEC),
	    (MAP_FIXED | MAP_PRIVATE), fd, (off_t)exec->a_text) == MAP_FAILED) {
		err = errno;
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_MMAP), pname,
		    strerror(err));
		return (0);
	}

	/*
	 * Allocate pages for the object's bss, if necessary.
	 */
	if (exec->a_bss != 0) {
		if (dz_map(lml, addr + M_SROUND(exec->a_text) + exec->a_data,
		    (int)exec->a_bss, PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_FIXED | MAP_PRIVATE) == MAP_FAILED)
			goto error;
	}

	/*
	 * Create link map structure for newly mapped shared object.
	 */
	ld->v2 = (struct link_dynamic_2 *)((int)ld->v2 + (int)addr);
	if (!(lmp = aout_new_lm(lml, pname, oname, ld, addr, size, lmco)))
		goto error;

	return (lmp);

	/*
	 * Error returns: close off file and free address space.
	 */
error:
	(void) munmap((caddr_t)addr, size);
	return (0);
}

/*
 * Create a new Rt_map structure for an a.out format object and
 * initializes all values.
 */
Rt_map *
aout_new_lm(Lm_list *lml, const char *pname, const char *oname,
    struct link_dynamic *ld, caddr_t addr, size_t size, Aliste lmco)
{
	Rt_map	*lmp;
	caddr_t offset;

	DBG_CALL(Dbg_file_aout(lml, pname, (ulong_t)ld, (ulong_t)addr,
	    (ulong_t)size, lml->lm_lmidstr, lmco));

	/*
	 * Allocate space for the link-map and private a.out information.  Once
	 * these are allocated and initialized, we can use remove_so(0, lmp) to
	 * tear down the link-map should any failures occur.
	 */
	if ((lmp = calloc(sizeof (Rt_map), 1)) == 0)
		return (0);
	if ((AOUTPRV(lmp) = calloc(sizeof (Rt_aoutp), 1)) == 0) {
		free(lmp);
		return (0);
	}
	if ((((Rt_aoutp *)AOUTPRV(lmp))->lm_lpd =
	    calloc(sizeof (struct ld_private), 1)) == 0) {
		free(AOUTPRV(lmp));
		free(lmp);
		return (0);
	}

	/*
	 * All fields not filled in were set to 0 by calloc.
	 */
	ORIGNAME(lmp) = PATHNAME(lmp) = NAME(lmp) = (char *)pname;
	ADDR(lmp) = (ulong_t)addr;
	MSIZE(lmp) = (ulong_t)size;
	SYMINTP(lmp) = aout_find_sym;
	FCT(lmp) = &aout_fct;
	LIST(lmp) = lml;
	THREADID(lmp) = rt_thr_self();
	OBJFLTRNDX(lmp) = FLTR_DISABLED;
	SORTVAL(lmp) = -1;

	/*
	 * Specific settings for a.out format.
	 */
	if (lml->lm_head == 0) {
		offset = (caddr_t)MAIN_BASE;
		FLAGS(lmp) |= FLG_RT_FIXED;
	} else
		offset = addr;

	ETEXT(lmp) = (ulong_t)&offset[ld->v2->ld_text];

	/*
	 * Create a mapping descriptor to describe the whole object as a single
	 * mapping.
	 */
	if ((MMAPS(lmp) = calloc(2, sizeof (Mmap))) == 0)
		return (0);
	MMAPS(lmp)->m_vaddr = offset;
	/* LINTED */
	MMAPS(lmp)->m_msize = max(SIZE(*(struct exec *)offset),
	    N_SYMOFF((*(struct exec *)offset)) + sizeof (struct nlist));
	MMAPS(lmp)->m_fsize = MMAPS(lmp)->m_msize;
	MMAPCNT(lmp) = 1;

	/*
	 * Fill in all AOUT information.
	 */
	AOUTDYN(lmp) = ld;
	if ((RPATH(lmp) = (char *)&offset[ld->v2->ld_rules]) == offset)
		RPATH(lmp) = 0;
	LM2LP(lmp)->lp_symbol_base = addr;
	/* LINTED */
	LM2LP(lmp)->lp_plt = (struct jbind *)(&addr[JMPOFF(ld)]);
	LM2LP(lmp)->lp_rp =
	/* LINTED */
	    (struct relocation_info *)(&offset[RELOCOFF(ld)]);
	/* LINTED */
	LM2LP(lmp)->lp_hash = (struct fshash *)(&offset[HASHOFF(ld)]);
	/* LINTED */
	LM2LP(lmp)->lp_symtab = (struct nlist *)(&offset[SYMOFF(ld)]);
	LM2LP(lmp)->lp_symstr = &offset[STROFF(ld)];
	LM2LP(lmp)->lp_textbase = offset;
	LM2LP(lmp)->lp_refcnt++;
	LM2LP(lmp)->lp_dlp = NULL;

	if (rtld_flags & RT_FL_RELATIVE)
		FLAGS1(lmp) |= FL1_RT_RELATIVE;

	if ((CONDVAR(lmp) = rt_cond_create()) == 0) {
		remove_so(0, lmp);
		return (0);
	}
	if (oname && ((append_alias((lmp), oname, 0)) == 0)) {
		remove_so(0, lmp);
		return (0);
	}

	/*
	 * Add the mapped object to the end of the link map list.
	 */
	lm_append(lml, lmco, lmp);
	return (lmp);
}

/*
 * Function to correct protection settings.
 * Segments are all mapped initially with permissions as given in
 * the segment header, but we need to turn on write permissions
 * on a text segment if there are any relocations against that segment,
 * and them turn write permission back off again before returning control
 * to the program.  This function turns the permission on or off depending
 * on the value of the argument.
 */
int
aout_set_prot(Rt_map *lmp, int permission)
{
	int		prot;		/* protection setting */
	caddr_t		et;		/* cached _etext of object */
	size_t		size;		/* size of text segment */

	DBG_CALL(Dbg_file_prot(lmp, permission));

	et = (caddr_t)ETEXT(lmp);
	size = M_PROUND((ulong_t)(et - TEXTBASE(lmp)));
	prot = PROT_READ | PROT_EXEC | permission;
	if (mprotect((caddr_t)TEXTBASE(lmp), size, prot) == -1) {
		int	err = errno;

		eprintf(LIST(lmp), ERR_FATAL, MSG_INTL(MSG_SYS_MPROT),
		    NAME(lmp), strerror(err));
		return (0);
	}
	return (1);
}

/*
 * Build full pathname of shared object from the given directory name and
 * filename.
 */
static char *
aout_get_so(const char *dir, const char *file)
{
	struct db	*dbp;
	char		*path = NULL;

	if (dbp = lo_cache(dir)) {
		path = ask_db(dbp, file);
	}
	return (path);
}

/*
 * Determine the symbol location of an address within a link-map.  Look for
 * the nearest symbol (whoes value is less than or equal to the required
 * address).  This is the object specific part of dladdr().
 */
static void
aout_dladdr(ulong_t addr, Rt_map *lmp, Dl_info *dlip, void **info,
    int flags)
{
	ulong_t		ndx, cnt, base, _value;
	struct nlist	*sym, *_sym;

	cnt = ((int)LM2LP(lmp)->lp_symstr - (int)LM2LP(lmp)->lp_symtab) /
	    sizeof (struct nlist);
	sym = LM2LP(lmp)->lp_symtab;

	if (FLAGS(lmp) & FLG_RT_FIXED)
		base = 0;
	else
		base = ADDR(lmp);

	for (_sym = 0, _value = 0, ndx = 0; ndx < cnt; ndx++, sym++) {
		ulong_t	value;

		if (sym->n_type == (N_EXT + N_UNDF))
			continue;

		value = sym->n_value + base;
		if (value > addr)
			continue;
		if (value < _value)
			continue;

		_sym = sym;
		_value = value;

		if (value == addr)
			break;
	}

	if (_sym) {
		int	_flags = flags & RTLD_DL_MASK;

		/*
		 * The only way we can create a symbol entry is to use
		 * aout_symconvert(), however this results in us pointing to
		 * static data that could be overridden.  In addition the AOUT
		 * symbol format doesn't give us everything an ELF symbol does.
		 * So, unless we get convinced otherwise, don't bother returning
		 * a symbol entry for AOUT's.
		 */
		if (_flags == RTLD_DL_SYMENT)
			*info = 0;
		else if (_flags == RTLD_DL_LINKMAP)
			*info = (void *)lmp;

		dlip->dli_sname = &LM2LP(lmp)->lp_symstr[_sym->n_un.n_strx];
		dlip->dli_saddr = (void *)_value;
	}
}

/*
 * Continue processing a dlsym request.  Lookup the required symbol in each
 * link-map specified by the handle.  Note, that because this lookup is against
 * individual link-maps we don't need to supply a starting link-map to the
 * lookup routine (see lookup_sym():analyze.c).
 */
Sym *
aout_dlsym_handle(Grp_hdl * ghp, Slookup *slp, Rt_map **_lmp, uint_t *binfo,
    int *in_nfavl)
{
	Sym	*sym;
	char	buffer[PATH_MAX];
	Slookup	sl;

	buffer[0] = '_';
	(void) strcpy(&buffer[1], slp->sl_name);

	if ((sym = dlsym_handle(ghp, slp, _lmp, binfo, in_nfavl)) != 0)
		return (sym);

	/*
	 * Symbol not found as supplied.  However, most of our symbols will
	 * be in the "C" name space, where the implementation prepends a "_"
	 * to the symbol as it emits it.  Therefore, attempt to find the
	 * symbol with the "_" prepend.
	 */
	sl = *slp;
	sl.sl_name = (const char *)buffer;

	return (dlsym_handle(ghp, &sl, _lmp, binfo, in_nfavl));
}
