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

/*
 * Analyze the versioning information within a file.
 *
 *   -C		demangle C++ symbol names.
 *
 *   -d		dump version definitions.
 *
 *   -l		print reduced (local) symbols.
 *
 *   -n		normalize any version definitions.
 *
 *   -o		dump output in one-line fashion	(more suitable for grep'ing
 *		and diff'ing).
 *
 *   -r		dump the version requirements on library dependencies
 *
 *   -s		display the symbols associated with each version definition.
 *
 *   -v		verbose output.  With the -r and -d options any WEAK attribute
 *		is displayed.  With the -d option, any version inheritance,
 *		and the base version are displayed.  With the -s option the
 *		version symbol is displayed.
 *
 *   -N name	only print the specifed `name'.
 */
#include	<fcntl.h>
#include	<stdio.h>
#include	<libelf.h>
#include	<link.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<locale.h>
#include	<errno.h>
#include	<sgs.h>
#include	<conv.h>
#include	<gelf.h>
#include	<debug.h>
#include	"msg.h"

#define		FLG_VER_AVAIL	0x10

typedef struct cache {
	Elf_Scn		*c_scn;
	Elf_Data	*c_data;
	char		*c_name;
} Cache;

typedef struct gver_desc {
	const char	*vd_name;
	unsigned long	vd_hash;
	GElf_Half	vd_ndx;
	GElf_Half	vd_flags;
	List		vd_deps;
} GVer_desc;

static const char	*cname;
static int		Cflag, dflag, lflag, nflag, oflag, rflag, sflag, vflag;

static const char
	* Format_ofil = "%s -",
	* Format_tnco =	"\t%s:\n",
	* Format_tnse =	"\t%s;\n",
	* Format_bgnl = "\t%s (%s",
	* Format_next = ", %s",
	* Format_weak = " [WEAK]",
	* Format_endl = ");\n";

#define	DEF_DEFINED	1
#define	USR_DEFINED	2

/*
 * Determine whether a symbol name should be demangled.
 */
static const char *
demangle(const char *name)
{
	if (Cflag)
		return (Elf_demangle_name(name));
	else
		return (name);
}

/*
 * Print any reduced symbols.  The convention is that reduced symbols exist as
 * LOCL entries in the .symtab, between the FILE symbol for the output file and
 * the first FILE symbol for any input file used to build the output file.
 */
static void
sym_local(Cache *cache, Cache *csym, const char *file)
{
	int		symn, _symn, found = 0;
	GElf_Shdr	shdr;
	GElf_Sym	sym;
	char		*strs, *local = "_LOCAL_";

	(void) gelf_getshdr(csym->c_scn, &shdr);
	strs = (char *)cache[shdr.sh_link].c_data->d_buf;
	/* LINTED */
	symn = shdr.sh_info;

	/*
	 * Verify symtab[1] is the output file symbol.
	 */
	(void) gelf_getsym(csym->c_data, 1, &sym);
	if (GELF_ST_TYPE(sym.st_info) != STT_FILE) {
		(void) fprintf(stderr, MSG_INTL(MSG_VER_UNREDSYMS), cname,
		    file);
		(void) fprintf(stderr, MSG_INTL(MSG_VER_NOTSTTFILE),
		    csym->c_name);
		return;
	}

	/*
	 * Scan the remaining symbols until the next file symbol is found.
	 */
	for (_symn = 2; _symn < symn; _symn++) {
		const char	*name;

		(void) gelf_getsym(csym->c_data, _symn, &sym);
		if (GELF_ST_TYPE(sym.st_info) == STT_SECTION)
			continue;
		if (GELF_ST_TYPE(sym.st_info) == STT_FILE)
			break;

		/*
		 * Its possible that section symbols are followed immediately
		 * by globals.  This is the case if an object (filter) is
		 * generated exclusively from mapfile symbol definitions.
		 */
		if (GELF_ST_BIND(sym.st_info) != STB_LOCAL)
			break;

		name = demangle(strs + sym.st_name);

		if (oflag) {
			(void) printf(Format_ofil, file);
			(void) printf("\t%s: %s\n", local, name);
		} else {
			if (found == 0) {
				found = 1;
				(void) printf(Format_tnco, local);
			}
			(void) printf("\t\t%s;\n", name);
		}
	}
}

/*
 * Print the files version needed sections.
 */
static int
gvers_need(Cache *cache, Cache *need, const char *file, const char *name)
{
	unsigned int	num, _num;
	char		*strs;
	GElf_Verneed	*vnd = need->c_data->d_buf;
	GElf_Shdr	shdr;
	int		error = 0;

	(void) gelf_getshdr(need->c_scn, &shdr);

	/*
	 * Verify the version revision.  We only check the first version
	 * structure as it is assumed all other version structures in this
	 * data section will be of the same revision.
	 */
	if (vnd->vn_version > VER_DEF_CURRENT)
		(void) fprintf(stderr, MSG_INTL(MSG_VER_HIGHREV), cname, file,
		    vnd->vn_version, VER_DEF_CURRENT);

	/*
	 * Get the data buffer for the associated string table.
	 */
	strs = (char *)cache[shdr.sh_link].c_data->d_buf;
	num = shdr.sh_info;

	for (_num = 1; _num <= num; _num++,
	    vnd = (GElf_Verneed *)((uintptr_t)vnd + vnd->vn_next)) {
		GElf_Vernaux	*vnap = (GElf_Vernaux *)
					((uintptr_t)vnd + vnd->vn_aux);
		GElf_Half	cnt = vnd->vn_cnt;
		const char	*_name, * dep;

		/*
		 * Obtain the version name and determine if we need to process
		 * it further.
		 */
		_name = (char *)(strs + vnd->vn_file);
		if (name && (strcmp(name, _name) == 0))
			continue;

		error = 1;

		/*
		 * If one-line ouput is called for display the filename being
		 * processed.
		 */
		if (oflag)
			(void) printf(Format_ofil, file);

		/*
		 * Determine the version name required from this file.
		 */
		if (cnt--)
			dep = (char *)(strs + vnap->vna_name);
		else
			dep = MSG_ORIG(MSG_STR_EMPTY);

		(void) printf(Format_bgnl, _name, dep);
		if (vflag && (vnap->vna_flags == VER_FLG_WEAK))
			(void) printf(Format_weak);

		/*
		 * Extract any other version dependencies for this file
		 */
		/* CSTYLED */
		for (vnap = (GElf_Vernaux *)((uintptr_t)vnap + vnap->vna_next);
		    cnt; cnt--,
		    vnap = (GElf_Vernaux *)((uintptr_t)vnap + vnap->vna_next)) {
			dep = (char *)(strs + vnap->vna_name);
			(void) printf(Format_next, dep);
			if (vflag && (vnap->vna_flags == VER_FLG_WEAK))
				(void) printf(Format_weak);
		}
		(void) printf(Format_endl);
	}
	return (error);
}

/*
 * Append an item to the specified list, and return a pointer to the list
 * node created.
 */
static Listnode *
list_append(List *lst, const void *item, const char *file)
{
	Listnode	*_lnp;

	if ((_lnp = malloc(sizeof (Listnode))) == 0) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC), cname, file,
		    strerror(err));
		exit(1);
	}

	_lnp->data = (void *)item;
	_lnp->next = NULL;

	if (lst->head == NULL)
		lst->tail = lst->head = _lnp;
	else {
		lst->tail->next = _lnp;
		lst->tail = lst->tail->next;
	}
	return (_lnp);
}

static GVer_desc *
gvers_find(const char *name, unsigned long hash, List *lst)
{
	Listnode	*lnp;
	GVer_desc	*vdp;

	for (LIST_TRAVERSE(lst, lnp, vdp)) {
		if (vdp->vd_hash != hash)
			continue;
		if (strcmp(vdp->vd_name, name) == 0)
			return (vdp);
	}
	return (0);
}

static GVer_desc *
gvers_desc(const char *name, unsigned long hash, List *lst, const char *file)
{
	GVer_desc	*vdp;

	if ((vdp = gvers_find(name, hash, lst)) == 0) {
		if ((vdp = calloc(sizeof (GVer_desc), 1)) == 0) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC), cname,
			    file, strerror(err));
			exit(1);
		}

		vdp->vd_name = name;
		vdp->vd_hash = hash;

		if (list_append(lst, vdp, file) == 0)
			return (0);
	}
	return (vdp);
}

static GVer_desc *
gvers_depend(const char *name, unsigned long hash, GVer_desc *vdp, List *lst,
    const char *file)
{
	GVer_desc	*_vdp;

	if ((_vdp = gvers_desc(name, hash, lst, file)) == 0)
		return (0);

	if (list_append(&vdp->vd_deps, _vdp, file) == 0)
		return (0);

	return (vdp);
}

static void
gvers_syms(GElf_Versym *vsp, Elf_Data *sym_data, int symn, char *strs,
    GVer_desc *vdp, const char *file)
{
	GElf_Sym	sym;
	int		_symn;

	for (_symn = 0; _symn < symn; _symn++) {
		size_t		size =	0;
		const char	*name;

		if (vsp[_symn] != vdp->vd_ndx)
			continue;

		/*
		 * For data symbols determine the size.
		 */
		(void) gelf_getsym(sym_data, _symn, &sym);
		if ((GELF_ST_TYPE(sym.st_info) == STT_OBJECT) ||
		    (GELF_ST_TYPE(sym.st_info) == STT_COMMON) ||
		    (GELF_ST_TYPE(sym.st_info) == STT_TLS))
			size = (size_t)sym.st_size;

		name = demangle(strs + sym.st_name);

		/*
		 * Only output the version symbol when the verbose flag is used.
		 */
		if (!vflag && (sym.st_shndx == SHN_ABS)) {
			if (strcmp(name, vdp->vd_name) == 0)
				continue;
		}

		if (oflag) {
			(void) printf(Format_ofil, file);
			(void) printf("\t%s: ", vdp->vd_name);
			if (size)
				(void) printf("%s (%ld);\n", name,
				    (ulong_t)size);
			else
				(void) printf("%s;\n", name);
		} else {
			if (size)
				(void) printf("\t\t%s (%ld);\n", name,
				    (ulong_t)size);
			else
				(void) printf("\t\t%s;\n", name);
		}
	}
}

static void
gvers_derefer(GVer_desc * vdp, int weak)
{
	Listnode *	_lnp;
	GVer_desc *	_vdp;

	/*
	 * If the head of the list was a weak then we only clear out
	 * weak dependencies, but if the head of the list was 'strong'
	 * we clear the REFER bit on all dependencies.
	 */
	if ((weak && (vdp->vd_flags & VER_FLG_WEAK)) || (!weak))
		vdp->vd_flags &= ~FLG_VER_AVAIL;

	for (LIST_TRAVERSE(&vdp->vd_deps, _lnp, _vdp))
		gvers_derefer(_vdp, weak);
}


static void
recurse_syms(GElf_Versym *vsp, Elf_Data *sym_data, int symn, char *strs,
    GVer_desc *vdp, const char *file)
{
	Listnode	*_lnp;
	GVer_desc	*_vdp;

	for (LIST_TRAVERSE(&vdp->vd_deps, _lnp, _vdp)) {
		if (!oflag)
			(void) printf(Format_tnco, _vdp->vd_name);
		gvers_syms(vsp, sym_data, symn, strs, _vdp, file);
		if (_vdp->vd_deps.head)
			recurse_syms(vsp, sym_data, symn, strs, _vdp, file);
	}
}


/*
 * Print the files version definition sections.
 */
static int
gvers_def(Cache *cache, Cache *def, Cache *csym, const char *file,
    const char *name)
{
	unsigned int	num, _num;
	char		*strs;
	GElf_Versym	*vsp;
	GElf_Verdef	*vdf = def->c_data->d_buf;
	GElf_Shdr	shdr;
	Elf_Data	*sym_data;
	int		symn;
	GVer_desc	*vdp, *bvdp = 0;
	Listnode	*lnp;
	List		verdefs = {0, 0};
	int		error = 0;

	/*
	 * Verify the version revision.  We only check the first version
	 * structure as it is assumed all other version structures in this
	 * data section will be of the same revision.
	 */
	if (vdf->vd_version > VER_DEF_CURRENT) {
		(void) fprintf(stderr, MSG_INTL(MSG_VER_HIGHREV), cname, file,
		    vdf->vd_version, VER_DEF_CURRENT);
	}

	/*
	 * Get the data buffer for the associated string table.
	 */
	(void) gelf_getshdr(def->c_scn, &shdr);
	strs = (char *)cache[shdr.sh_link].c_data->d_buf;
	num = shdr.sh_info;

	/*
	 * Process the version definitions placing each on a version dependency
	 * list.
	 */
	for (_num = 1; _num <= num; _num++,
	    vdf = (GElf_Verdef *)((uintptr_t)vdf + vdf->vd_next)) {
		GElf_Half	cnt = vdf->vd_cnt;
		GElf_Half	ndx = vdf->vd_ndx;
		GElf_Verdaux	*vdap = (GElf_Verdaux *)((uintptr_t)vdf +
				    vdf->vd_aux);
		const char	*_name;

		/*
		 * Determine the version name and any dependencies.
		 */
		_name = (char *)(strs + vdap->vda_name);

		if ((vdp = gvers_desc(_name, elf_hash(_name), &verdefs,
		    file)) == 0)
			return (0);
		vdp->vd_ndx = ndx;
		vdp->vd_flags = vdf->vd_flags | FLG_VER_AVAIL;

		vdap = (GElf_Verdaux *)((uintptr_t)vdap + vdap->vda_next);
		for (cnt--; cnt; cnt--,
		    vdap = (GElf_Verdaux *)((uintptr_t)vdap + vdap->vda_next)) {
			_name = (char *)(strs + vdap->vda_name);
			if (gvers_depend(_name, elf_hash(_name), vdp,
			    &verdefs, file) == 0)
				return (0);
		}

		/*
		 * Remember the base version for possible later use.
		 */
		if (ndx == VER_NDX_GLOBAL)
			bvdp = vdp;
	}

	/*
	 * Normalize the dependency list if required.
	 */
	if (nflag) {
		for (LIST_TRAVERSE(&verdefs, lnp, vdp)) {
			Listnode *	_lnp;
			GVer_desc *	_vdp;
			int		type = vdp->vd_flags & VER_FLG_WEAK;

			for (LIST_TRAVERSE(&vdp->vd_deps, _lnp, _vdp))
				gvers_derefer(_vdp, type);
		}

		/*
		 * Always dereference the base version.
		 */
		if (bvdp)
			bvdp->vd_flags &= ~FLG_VER_AVAIL;
	}


	/*
	 * Traverse the dependency list and print out the appropriate
	 * information.
	 */
	for (LIST_TRAVERSE(&verdefs, lnp, vdp)) {
		Listnode *	_lnp;
		GVer_desc *	_vdp;
		int		count;

		if (name && (strcmp(name, vdp->vd_name) != 0))
			continue;

		if (!name && !(vdp->vd_flags & FLG_VER_AVAIL))
			continue;

		error = 1;

		if (vflag) {
			/*
			 * If the verbose flag is set determine if this version
			 * has a `weak' attribute, and print any version
			 * dependencies this version inherits.
			 */
			if (oflag)
				(void) printf(Format_ofil, file);
			(void) printf("\t%s", vdp->vd_name);
			if (vdp->vd_flags & VER_FLG_WEAK)
				(void) printf(Format_weak);

			count = 1;
			for (LIST_TRAVERSE(&vdp->vd_deps, _lnp, _vdp)) {
				const char	*_name = _vdp->vd_name;

				if (count++ == 1) {
					if (oflag)
						(void) printf(": {%s", _name);
					else if (vdp->vd_flags & VER_FLG_WEAK)
						(void) printf(":\t{%s", _name);
					else
						(void) printf(":       \t{%s",
						    _name);
				} else
					(void) printf(Format_next, _name);
			}

			if (count != 1)
				(void) printf("}");

			if (csym && !oflag)
				(void) printf(":\n");
			else
				(void) printf(";\n");
		} else {
			if (csym && !oflag)
				(void) printf(Format_tnco, vdp->vd_name);
			else if (!csym) {
				if (oflag)
					(void) printf(Format_ofil, file);
				(void) printf(Format_tnse, vdp->vd_name);
			}
		}

		/*
		 * If we need to print symbols get the associated symbol table.
		 */
		if (csym) {
			(void) gelf_getshdr(csym->c_scn, &shdr);
			vsp = (GElf_Versym *)csym->c_data->d_buf;
			sym_data = cache[shdr.sh_link].c_data;
			(void) gelf_getshdr(cache[shdr.sh_link].c_scn, &shdr);
			/* LINTED */
			symn = (int)(shdr.sh_size / shdr.sh_entsize);
		} else
			continue;

		/*
		 * If a specific version name has been specified then display
		 * any of its own symbols plus any inherited from other
		 * versions.  Otherwise simply print out the symbols for this
		 * version.
		 */
		gvers_syms(vsp, sym_data, symn, strs, vdp, file);
		if (name) {
			recurse_syms(vsp, sym_data, symn, strs, vdp, file);

			/*
			 * If the verbose flag is set add the base version as a
			 * dependency (unless it's the list we were asked to
			 * print in the first place).
			 */
			if (vflag && bvdp && strcmp(name, bvdp->vd_name)) {
				if (!oflag)
				    (void) printf(Format_tnco, bvdp->vd_name);
				gvers_syms(vsp, sym_data, symn, strs, bvdp,
				    file);
			}
		}
	}
	return (error);
}

int
main(int argc, char **argv, char **envp)
{
	GElf_Shdr	shdr;
	Elf		*elf;
	Elf_Scn		*scn;
	Elf_Data	*data;
	GElf_Ehdr 	ehdr;
	int		nfile, var;
	const char	*name;
	char		*names;
	Cache		*cache, *_cache;
	Cache		*_cache_def, *_cache_need, *_cache_sym, *_cache_loc;
	int		error = 0;

	/*
	 * Check for a binary that better fits this architecture.
	 */
	(void) conv_check_native(argv, envp);

	/*
	 * Establish locale.
	 */
	(void) setlocale(LC_MESSAGES, MSG_ORIG(MSG_STR_EMPTY));
	(void) textdomain(MSG_ORIG(MSG_SUNW_OST_SGS));

	cname = argv[0];
	name = NULL;
	Cflag = dflag = lflag = nflag = oflag = rflag = sflag = vflag = 0;

	opterr = 0;
	while ((var = getopt(argc, argv, "CdlnorsvN:")) != EOF) {
		switch (var) {
		case 'C':
			Cflag = USR_DEFINED;
			break;
		case 'd':
			dflag = USR_DEFINED;
			break;
		case 'l':
			lflag = USR_DEFINED;
			break;
		case 'n':
			nflag = USR_DEFINED;
			break;
		case 'o':
			oflag = USR_DEFINED;
			break;
		case 'r':
			rflag = USR_DEFINED;
			break;
		case 's':
			sflag = USR_DEFINED;
			break;
		case 'v':
			vflag = USR_DEFINED;
			break;
		case 'N':
			name = optarg;
			break;
		case '?':
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF),
			    cname);
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL));
			exit(1);
		default:
			break;
		}
	}

	/*
	 * No files specified on the command line?
	 */
	if ((nfile = argc - optind) == 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF), cname);
		exit(1);
	}

	/*
	 * By default print both version definitions and needed dependencies.
	 */
	if ((dflag == 0) && (rflag == 0))
		dflag = rflag = DEF_DEFINED;

	/*
	 * Open the input file and initialize the elf interface.
	 */
	for (; optind < argc; optind++) {
		int		derror = 0, nerror = 0,	err;
		const char	*file = argv[optind];

		if ((var = open(file, O_RDONLY)) == -1) {
			err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
			    cname, file, strerror(err));
			error = 1;
			continue;
		}
		(void) elf_version(EV_CURRENT);
		if ((elf = elf_begin(var, ELF_C_READ, NULL)) == NULL) {
			(void) fprintf(stderr, MSG_ORIG(MSG_ELF_BEGIN), cname,
			    file, elf_errmsg(elf_errno()));
			error = 1;
			(void) close(var);
			continue;
		}
		if (elf_kind(elf) != ELF_K_ELF) {
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_NOTELF), cname,
			    file);
			error = 1;
			(void) close(var);
			(void) elf_end(elf);
			continue;
		}
		if (gelf_getehdr(elf, &ehdr) == NULL) {
			(void) fprintf(stderr, MSG_ORIG(MSG_ELF_GETEHDR), cname,
			    file, elf_errmsg(elf_errno()));
			error = 1;
			(void) close(var);
			(void) elf_end(elf);
			continue;
		}

		/*
		 *  Obtain the .shstrtab data buffer to provide the required
		 * section name strings.
		 */
		if ((scn = elf_getscn(elf, ehdr.e_shstrndx)) == NULL) {
			(void) fprintf(stderr, MSG_ORIG(MSG_ELF_GETSCN), cname,
			    file, elf_errmsg(elf_errno()));
			error = 1;
			(void) close(var);
			(void) elf_end(elf);
			continue;
		}
		if ((data = elf_getdata(scn, NULL)) == NULL) {
			(void) fprintf(stderr, MSG_ORIG(MSG_ELF_GETDATA), cname,
			    file, elf_errmsg(elf_errno()));
			error = 1;
			(void) close(var);
			(void) elf_end(elf);
			continue;
		}
		names = data->d_buf;

		/*
		 * Fill in the cache descriptor with information for each
		 * section we might need.   We probably only need to save
		 * read-only allocable sections as this is where the version
		 * structures and their associated symbols and strings live.
		 * However, God knows what someone can do with a mapfile, and
		 * as elf_begin has already gone through all the overhead we
		 * might as well set up the cache for every section.
		 */
		if ((cache = calloc(ehdr.e_shnum, sizeof (Cache))) == 0) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC), cname,
			    file, strerror(err));
			exit(1);
		}

		_cache_def = _cache_need = _cache_sym = _cache_loc = 0;
		_cache = cache;
		_cache++;
		for (scn = NULL; scn = elf_nextscn(elf, scn); _cache++) {
			if (gelf_getshdr(scn, &shdr) == NULL) {
				(void) fprintf(stderr,
				    MSG_ORIG(MSG_ELF_GETSHDR), cname, file,
				    elf_errmsg(elf_errno()));
				error = 1;
				continue;
			}
			if ((_cache->c_data = elf_getdata(scn, NULL)) ==
			    NULL) {
				(void) fprintf(stderr,
				    MSG_ORIG(MSG_ELF_GETDATA), cname, file,
				    elf_errmsg(elf_errno()));
				error = 1;
				continue;
			}
			_cache->c_scn = scn;
			_cache->c_name = names + shdr.sh_name;

			/*
			 * Remember the version sections and symbol table.
			 */
			switch (shdr.sh_type) {
			case SHT_SUNW_verdef:
				if (dflag)
					_cache_def = _cache;
				break;
			case SHT_SUNW_verneed:
				if (rflag)
					_cache_need = _cache;
				break;
			case SHT_SUNW_versym:
				if (sflag)
					_cache_sym = _cache;
				break;
			case SHT_SYMTAB:
				if (lflag)
					_cache_loc = _cache;
				break;
			}
		}

		/*
		 * Before printing anything out determine if any warnings are
		 * necessary.
		 */
		if (lflag && (_cache_loc == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_VER_UNREDSYMS),
			    cname, file);
			(void) fprintf(stderr, MSG_INTL(MSG_VER_NOSYMTAB));
		}

		/*
		 * If there is more than one input file, and we're not printing
		 * one-line output, display the filename being processed.
		 */
		if ((nfile > 1) && !oflag)
			(void) printf("%s:\n", file);

		/*
		 * Print the files version needed sections.
		 */
		if (_cache_need)
			nerror = gvers_need(cache, _cache_need, file, name);

		/*
		 * Print the files version definition sections.
		 */
		if (_cache_def)
			derror = gvers_def(cache, _cache_def, _cache_sym,
			    file, name);

		/*
		 * Print any local symbol reductions.
		 */
		if (_cache_loc)
			sym_local(cache, _cache_loc, file);

		/*
		 * Determine the error return.  There are three conditions that
		 * may produce an error (a non-zero return):
		 *
		 *  o	if the user specified -d and no version definitions
		 *	were found.
		 *
		 *  o	if the user specified -r and no version requirements
		 *	were found.
		 *
		 *  o	if the user specified neither -d or -r, (thus both are
		 *	enabled by default), and no version definitions or
		 *	version dependencies were found.
		 */
		if (((dflag == USR_DEFINED) && (derror == 0)) ||
		    ((rflag == USR_DEFINED) && (nerror == 0)) ||
		    (rflag && dflag && (derror == 0) && (nerror == 0)))
			error = 1;

		(void) close(var);
		(void) elf_end(elf);
		free(cache);
	}
	return (error);
}

const char *
_pvs_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}
