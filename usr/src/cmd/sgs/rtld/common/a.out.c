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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Object file dependent support for a.out format objects.
 */

#include	<a.out.h>		/* Explicitly override M_SEGSIZE */
#include	<machdep.h>		/*	used in M_SROUND */

#include	<sys/types.h>
#include	<sys/procfs.h>
#include	<sys/mman.h>
#include	<fcntl.h>
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
static Spath_defn _aout_def_dirs[] = {
	{ MSG_ORIG(MSG_PTH_USRLIB),		MSG_PTH_USRLIB_SIZE },
	{ MSG_ORIG(MSG_PTH_USRLCLIB),		MSG_PTH_USRLCLIB_SIZE },
	{ 0, 0 }
};

static Spath_defn _aout_sec_dirs[] = {
	{ MSG_ORIG(MSG_PTH_LIBSE),		MSG_PTH_LIBSE_SIZE },
	{ 0, 0 }
};

Alist	*aout_def_dirs = NULL;
Alist	*aout_sec_dirs = NULL;

/*
 * Defines for local functions.
 */
static void	aout_dladdr(ulong_t, Rt_map *, Dl_info *, void **, int);
static int	aout_dlsym_handle(Grp_hdl *, Slookup *, Sresult *, uint_t *,
		    int *);
static Addr	aout_entry_point(void);
static int	aout_find_sym(Slookup *, Sresult *, uint_t *, int *);
static int	aout_fix_name(const char *, Rt_map *, Alist **, Aliste, uint_t);
static Alist	**aout_get_def_dirs(void);
static Alist	**aout_get_sec_dirs(void);
static char	*aout_get_so(const char *, const char *, size_t, size_t);
static int	aout_needed(Lm_list *, Aliste, Rt_map *, int *);

/*
 * Functions and data accessed through indirect pointers.
 */
Fct aout_fct = {
	aout_verify,
	aout_new_lmp,
	aout_entry_point,
	aout_needed,
	aout_lookup_sym,
	aout_reloc,
	aout_get_def_dirs,
	aout_get_sec_dirs,
	aout_fix_name,
	aout_get_so,
	aout_dladdr,
	aout_dlsym_handle
};

/*
 * Default and secure dependency search paths.
 */
static Alist **
aout_get_def_dirs()
{
	if (aout_def_dirs == NULL)
		set_dirs(&aout_def_dirs, _aout_def_dirs, LA_SER_DEFAULT);
	return (&aout_def_dirs);
}

static Alist **
aout_get_sec_dirs()
{
	if (aout_sec_dirs == NULL)
		set_dirs(&aout_sec_dirs, _aout_sec_dirs, LA_SER_SECURE);
	return (&aout_sec_dirs);
}

/*
 * In 4.x, a needed file or a dlopened file that was a simple file name implied
 * that the file be found in the present working directory.  To simulate this
 * lookup within the ELF rules it is necessary to add a preceding `./' to the
 * filename.
 */
/* ARGSUSED4 */
static int
aout_fix_name(const char *oname, Rt_map *clmp, Alist **alpp, Aliste alni,
    uint_t orig)
{
	size_t		len;
	Pdesc		*pdp;
	const char	*nname;

	/*
	 * Check for slash in name, if none, prepend "./", otherwise just
	 * return name given.
	 */
	if (strchr(oname, '/')) {
		len = strlen(oname) + 1;
		if ((nname = stravl_insert(oname, 0, len, 0)) == NULL)
			return (0);
	} else {
		char	buffer[PATH_MAX];

		len = strlen(oname) + 3;
		(void) snprintf(buffer, len, MSG_ORIG(MSG_FMT_4XPATH), oname);
		if ((nname = stravl_insert(buffer, 0, len, 0)) == NULL)
			return (0);
	}

	if ((pdp = alist_append(alpp, NULL, sizeof (Pdesc), alni)) == NULL)
		return (0);

	pdp->pd_pname = nname;
	pdp->pd_plen = len;
	pdp->pd_flags = PD_FLG_PNSLASH;

	DBG_CALL(Dbg_file_fixname(LIST(clmp), nname, oname));
	return (1);
}

/*
 * Determine if we have been given an A_OUT file.  Returns 1 if true.
 */
Fct *
/* ARGSUSED1 */
aout_verify(caddr_t addr, size_t size, Fdesc *fdp, const char *name,
    Rej_desc *rej)
{
	/* LINTED */
	struct exec *exec = (struct exec *)addr;

	if (size < sizeof (exec) || (exec->a_machtype != M_SPARC) ||
	    (N_BADMAG(*exec))) {
		return (NULL);
	}
	return (&aout_fct);
}

/*
 * Return the entry point of the A_OUT executable.  Although the entry point
 * within an ELF file is flexible, the entry point of an A_OUT executable is
 * always zero.
 */
static Addr
aout_entry_point()
{
	return (0);
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
	Alist	*palp = NULL;
	void	*need;

	for (need = &TEXTBASE(clmp)[AOUTDYN(clmp)->v2->ld_need];
	    need != &TEXTBASE(clmp)[0];
	    need = &TEXTBASE(clmp)[((Lnk_obj *)(need))->lo_next]) {
		Rt_map	*nlmp;
		char	*name;

		name = &TEXTBASE(clmp)[((Lnk_obj *)(need))->lo_name];

		if (((Lnk_obj *)(need))->lo_library) {
			/*
			 * If lo_library field is not NULL then this needed
			 * library was linked in using the "-l" option.
			 * Thus we need to rebuild the library name before
			 * trying to load it.
			 */
			char	*file;
			size_t	len;

			/*
			 * Allocate name length plus 20 for full library name.
			 * lib.so.. = 7 + (2 * short) + NULL = 7 + 12 + 1 = 20
			 */
			len = strlen(name) + 20;
			if ((file = malloc(len)) == NULL)
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
				Spath_desc	sd = { search_rules, NULL, 0 };
				Pdesc		*pdp;
				char		*path = NULL;

				for (pdp = get_next_dir(&sd, clmp, 0); pdp;
				    pdp = get_next_dir(&sd, clmp, 0)) {
					if (pdp->pd_pname == NULL)
						continue;

					if (path = aout_get_so(pdp->pd_pname,
					    file, 0, 0))
						break;
				}
				if (path == NULL) {
					eprintf(lml, ERR_FATAL,
					    MSG_INTL(MSG_SYS_OPEN), file,
					    strerror(ENOENT));
					return (0);
				}
				name = path;
			}
			if (expand_paths(clmp, name, &palp,
			    AL_CNT_NEEDED, 0, 0) == 0)
				return (0);
		} else {
			/*
			 * If the library is specified as a pathname, see if
			 * it must be fixed to specify the current working
			 * directory (ie. libc.so.1.2 -> ./libc.so.1.2).
			 */
			if (aout_fix_name(name, clmp, &palp,
			    AL_CNT_NEEDED, 0) == 0)
				return (0);
		}

		DBG_CALL(Dbg_file_needed(clmp, name));

		nlmp = load_one(lml, lmco, palp, clmp, MODE(clmp), 0, 0,
		    in_nfavl);
		remove_alist(&palp, 1);
		if (((nlmp == NULL) ||
		    (bind_one(clmp, nlmp, BND_NEEDED) == 0)) &&
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
	static struct rtc_symb	*rtcp = NULL;
	struct rtc_symb		*rs, *trs;
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
	if ((rs = malloc(sizeof (struct rtc_symb))) == NULL)
		return (NULL);
	if ((rs->rtc_sp = malloc(sizeof (struct nlist))) == NULL)
		return (NULL);
	trs = rtcp;
	rtcp = rs;
	rs->rtc_next = trs;
	*(rs->rtc_sp) = *sp;
	if ((rs->rtc_sp->n_un.n_name = malloc(strlen(name) + 1)) == NULL)
		return (NULL);
	(void) strcpy(rs->rtc_sp->n_un.n_name, name);
	rs->rtc_sp->n_type = N_COMM;
	if ((rs->rtc_sp->n_value =
	    (long)calloc(rs->rtc_sp->n_value, 1)) == NULL)
		return (NULL);
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

	if (p->fssymbno != -1) {
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
			if (p->next == NULL)
				return (NULL);		/* not found */
			else
				continue;
		} while ((p = &LM2LP(lmp)->lp_hash[p->next]) != NULL);
	}
	return (NULL);
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
int
aout_lookup_sym(Slookup *slp, Sresult *srp, uint_t *binfo, int *in_nfavl)
{
	char	name[PATH_MAX];
	Slookup	sl = *slp;

	DBG_CALL(Dbg_syms_lookup_aout(LIST(slp->sl_cmap), slp->sl_name));

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
	return (lookup_sym(&sl, srp, binfo, in_nfavl));
}

/*
 * Symbol lookup for an a.out format module.
 */
/* ARGSUSED3 */
static int
aout_find_sym(Slookup *slp, Sresult *srp, uint_t *binfo, int *in_nfavl)
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
				if ((sp = aout_find_com(sp, name)) == NULL)
					return (0);
			}
			srp->sr_dmap = ilmp;
			srp->sr_sym = aout_symconvert(sp);
			*binfo |= DBG_BINFO_FOUND;
			return (1);
		}
	}
	return (0);
}

/*
 * Create a new Rt_map structure for an a.out format object and
 * initializes all values.
 */
/* ARGSUSED6 */
Rt_map *
aout_new_lmp(Lm_list *lml, Aliste lmco, Fdesc *fdp, Addr addr, size_t msize,
    void *odyn, Rt_map *clmp, int *in_nfavl)
{
	const char	*name = fdp->fd_nname;
	Rt_map		*lmp;
	caddr_t		base, caddr = (caddr_t)addr;
	Link_dynamic	*ld = (Link_dynamic *)odyn;
	size_t		lmsz, rtsz, prsz;

	DBG_CALL(Dbg_file_aout(lml, name, addr, msize, lml->lm_lmidstr, lmco));

	/*
	 * Allocate space for the link-map and private a.out information.  Once
	 * these are allocated and initialized, we can use remove_so(0, lmp) to
	 * tear down the link-map should any failures occur.
	 */
	rtsz = S_DROUND(sizeof (Rt_map));
	prsz = S_DROUND(sizeof (Rt_aoutp));
	lmsz = rtsz + prsz + sizeof (struct ld_private);
	if ((lmp = calloc(lmsz, 1)) == NULL)
		return (NULL);
	AOUTPRV(lmp) = (void *)((uintptr_t)lmp + rtsz);
	((Rt_aoutp *)AOUTPRV(lmp))->lm_lpd =
	    (void *)((uintptr_t)lmp + rtsz + prsz);
	LMSIZE(lmp) = lmsz;

	/*
	 * All fields not filled in were set to 0 by calloc.
	 */
	NAME(lmp) = (char *)name;
	ADDR(lmp) = addr;
	MSIZE(lmp) = msize;
	SYMINTP(lmp) = aout_find_sym;
	FCT(lmp) = &aout_fct;
	LIST(lmp) = lml;
	OBJFLTRNDX(lmp) = FLTR_DISABLED;
	SORTVAL(lmp) = -1;

	/*
	 * Specific settings for a.out format.
	 */
	if (lml->lm_head == NULL) {
		base = (caddr_t)MAIN_BASE;
		FLAGS(lmp) |= FLG_RT_FIXED;
	} else
		base = caddr;

	/*
	 * Fill in all AOUT information.  Applications provide the Link_dynamic
	 * offset via the boot block, but if this is a shared object that
	 * ld.so.1 has mapped, then determine the Link_dynamic offset from the
	 * mapped image.
	 */
	if (ld == NULL) {
		/* LINTED */
		struct exec	*exec = (struct exec *)caddr;
		struct nlist	*nl;

		/* LINTED */
		nl = (struct nlist *)&caddr[N_SYMOFF(*exec)];
		/* LINTED */
		ld = (Link_dynamic *)&caddr[nl->n_value];

		ld->v2 = (struct link_dynamic_2 *)((int)ld->v2 + (int)caddr);
	}
	AOUTDYN(lmp) = ld;

	if ((RPATH(lmp) = (char *)&base[ld->v2->ld_rules]) == base)
		RPATH(lmp) = NULL;
	LM2LP(lmp)->lp_symbol_base = caddr;
	/* LINTED */
	LM2LP(lmp)->lp_plt = (struct jbind *)(&caddr[JMPOFF(ld)]);
	LM2LP(lmp)->lp_rp =
	/* LINTED */
	    (struct relocation_info *)(&base[RELOCOFF(ld)]);
	/* LINTED */
	LM2LP(lmp)->lp_hash = (struct fshash *)(&base[HASHOFF(ld)]);
	/* LINTED */
	LM2LP(lmp)->lp_symtab = (struct nlist *)(&base[SYMOFF(ld)]);
	LM2LP(lmp)->lp_symstr = &base[STROFF(ld)];
	LM2LP(lmp)->lp_textbase = base;
	LM2LP(lmp)->lp_refcnt++;
	LM2LP(lmp)->lp_dlp = NULL;

	/*
	 * Add the mapped object to the end of the link map list.
	 */
	lm_append(lml, lmco, lmp);
	return (lmp);
}

/*
 * Build full pathname of shared object from the given directory name and
 * filename.
 */
static char *
/* ARGSUSED2 */
aout_get_so(const char *dir, const char *file, size_t dlen, size_t flen)
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

	for (_sym = NULL, _value = 0, ndx = 0; ndx < cnt; ndx++, sym++) {
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
			*info = NULL;
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
static int
aout_dlsym_handle(Grp_hdl *ghp, Slookup *slp, Sresult *srp, uint_t *binfo,
    int *in_nfavl)
{
	char	buffer[PATH_MAX];
	Slookup	sl;

	if (dlsym_handle(ghp, slp, srp, binfo, in_nfavl))
		return (1);

	/*
	 * Symbol not found as supplied.  However, most of our symbols will
	 * be in the "C" name space, where the implementation prepends a "_"
	 * to the symbol as it emits it.  Therefore, attempt to find the
	 * symbol with the "_" prepend.
	 */
	buffer[0] = '_';
	(void) strcpy(&buffer[1], slp->sl_name);

	sl = *slp;
	sl.sl_name = (const char *)buffer;

	return (dlsym_handle(ghp, &sl, srp, binfo, in_nfavl));
}

/*
 * The initial mapping of the a.out occurs through exec(2), and presently this
 * implementation doesn't provide a mmapobj_result_t array to ld.so.1.  Thus,
 * aout_get_mmap() is called to create the mapping information.  Unlike ELF,
 * the information that can be gathered from a mapped AOUT file, can be limited.
 * In some cases the AOUT header isn't available in the mapped image, and thus
 * this can't be inspected to determine the files size (the kernel always
 * returns a pointer to the AOUT dynamic structure, but this is only sufficient
 * to determine the size of the text segment).
 *
 * Therefore, the only generic mechanism of determining the AOUT's mapping is
 * to use /proc.  Only two mappings are required, the text (to determine any
 * read-only region), and the data.  The two mapping validate the range in
 * which any relocations will occur.  Should there be an additional bss segment,
 * we don't care, as this can't be relocated, and we're never going to try
 * unmapping the a.out.
 */
#define	PROCSIZE	20

int
aout_get_mmap(Lm_list *lml, mmapobj_result_t *mpp)
{
	prmap_t	*maps;
	char	proc[PROCSIZE];
	int	num, err, fd;

	(void) snprintf(proc, PROCSIZE, MSG_ORIG(MSG_FMT_PROC),
	    EC_SWORD(getpid()));
	if ((fd = open(proc, O_RDONLY)) == -1) {
		err = errno;
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN), proc,
		    strerror(err));
		return (1);
	}

	if (ioctl(fd, PIOCNMAP, (void *)&num) == -1) {
		err = errno;
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_PROC), strerror(err));
		return (1);
	}

	if ((maps = malloc((num + 1) * sizeof (prmap_t))) == NULL)
		return (1);

	if (ioctl(fd, PIOCMAP, (void *)maps) == -1) {
		err = errno;
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_PROC), strerror(err));
		free(maps);
		return (1);
	}

	mpp->mr_addr = maps->pr_vaddr;
	mpp->mr_fsize = mpp->mr_msize = maps->pr_size;
	mpp->mr_prot = (PROT_READ | PROT_EXEC);

	mpp++, maps++;

	mpp->mr_addr = maps->pr_vaddr;
	mpp->mr_fsize = mpp->mr_msize = maps->pr_size;
	mpp->mr_prot = (PROT_READ | PROT_WRITE | PROT_EXEC);

	maps--;
	free(maps);
	return (0);
}
