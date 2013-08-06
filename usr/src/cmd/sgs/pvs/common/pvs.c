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
 * Analyze the versioning information within a file.
 *
 *   -C		demangle C++ symbol names.
 *
 *   -d		dump version definitions.
 *
 *   -l		print reduced (local) symbols. Implies -s.
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
 *		and the base version are displayed.  With the -r option,
 *		WEAK and INFO attributes are displayed. With the -s option
 *		the version symbol is displayed.
 *
 *   -I index	only print the specifed version index, or index range.
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
#include	<ctype.h>
#include	<alist.h>
#include	"msg.h"

/*
 * Define Alist initialization sizes.
 */
#define	AL_CNT_MATCH_LIST	5	/* match_list initial alist count */
#define	AL_CNT_GVER_DESC	25	/* version tracking descriptors */

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
	APlist		*vd_deps;
} GVer_desc;

/* Versym related data used by gvers_syms() */
typedef struct {
	GElf_Versym	*vsd_vsp;   	/* ptr to versym data */
	Elf_Data	*vsd_sym_data;	/* ptr to symtab data */
	Word		vsd_symn;	/* # of symbols in symtab */
	const char	*vsd_strs;	/* string table data */
} Gver_sym_data;

/*
 * Type used to manage -I and -N options:
 *
 * The -I option specifies a VERSYM index, or index range. The
 * result is to select the VERDEF or VERNEED records with
 * indexes that match those given.
 *
 * -N options come in two forms:
 *
 *	1) name
 *	2) needobj (version)
 *
 * The meaning of the first case depends on the type of
 * version record being matched:
 *
 *	VERDEF - name is the name of a version defined
 *		by the object being processed (i.e. SUNW_1.1).
 *
 *	VERNEED - name is the name of the object file
 *		on which the dependency exists (i.e. libc.so.1).
 *
 * -N options of the second form only apply to VERNEED records.
 * They are used to specify a version from a needed object.
 */
/* match_opt_t is  used to note which match option was used */
typedef enum {
	MATCH_OPT_NAME,		/* Record contains a name */
	MATCH_OPT_NEED_VER,	/* Record contains needed object and version */
	MATCH_OPT_NDX,		/* Record contains a single index */
	MATCH_OPT_RANGE,	/* Record contains an index range */
} match_opt_t;

typedef struct {
	match_opt_t	opt_type;
	union {
		struct {
			const char *version;	/* MATCH_OPT_{NAME|NEED_VER} */
			const char *needobj;	/* MATCH_OPT_NEED_VER only */
		} name;
		struct {
			int start;		/* MATCH_OPT_{NDX|RANGE} */
			int end;		/* MATCH_OPT_RANGE only) */
		} ndx;
	} value;
} match_rec_t;



static const char	*cname;
static int		Cflag, dflag, lflag, nflag, oflag, rflag, sflag, vflag;
static Alist		*match_list;

/* Used to track whether an option defaulted to on, or was explicitly set */
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
 * Append an item to the specified list, and return a pointer to the list
 * node created.
 *
 * exit:
 *	On success, a new list node is created and the item is
 *	added to the list. On failure, a fatal error is issued
 *	and the process exits.
 */
static void
pvs_aplist_append(APlist **lst, const void *item, const char *file)
{
	if (aplist_append(lst, item, AL_CNT_GVER_DESC) == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC), cname, file,
		    strerror(err));
		exit(1);
	}
}

/*
 * Add an entry to match_list for use by match(). This routine is for
 * use during getopt() processing.
 *
 * entry:
 *	opt - One of 'N' or 'I', indicating the option
 *	str - Value string corresponding to opt
 *
 * exit:
 *	The new match record has been added. On error, a fatal
 *	error is issued and and the process exits.
 */
static void
add_match_record(int opt, const char *str)
{
	/*
	 * Macros for removing leading and trailing whitespace:
	 *	WS_SKIP - Advance _str without passing the NULL termination,
	 *		until the first character is not whitespace.
	 *	WS_SKIP_LIMIT - Advance _str without passing _limit,
	 *		until the first character is not whitespace.
	 *	WS_RSKIP_LIMIT - Move _tail back without passing _str,
	 *		until the character before it is not whitespace.
	 *		Write a NULL termination at that point.
	 */
#define	WS_SKIP(_str) for (; *(_str) && isspace(*(_str)); (_str)++)
#define	WS_SKIP_LIMIT(_str, _limit) \
	while (((_str) < s2) && isspace(*(_str))) \
		(_str)++
#define	WS_RSKIP_LIMIT(_str, _tail) \
	while (((_tail) > (_str)) && isspace(*((_tail) - 1)))	\
		(_tail)--;					\
	*(_tail) = '\0'


	match_rec_t	*rec;
	char		*lstr, *s1, *s2;

	rec = alist_append(&match_list, NULL, sizeof (match_rec_t),
	    AL_CNT_MATCH_LIST);
	if (rec == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC), cname,
		    MSG_INTL(MSG_STR_MATCH_RECORD), strerror(err));
		exit(1);
	}

	if (opt == 'N') {
		if ((lstr = strdup(str)) == NULL) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC),
			    cname, MSG_INTL(MSG_STR_MATCH_RECORD),
			    strerror(err));
			exit(1);
		}

		/* Strip leading/trailing whitespace */
		s2 = lstr + strlen(lstr);
		WS_SKIP_LIMIT(lstr, s2);
		WS_RSKIP_LIMIT(lstr, s2);

		/* Assume this is a plain string */
		rec->opt_type = MATCH_OPT_NAME;
		rec->value.name.version = lstr;

		/*
		 * If s2 points at a closing paren, then this might
		 * be a MATCH_OPT_NEED_VER case. Otherwise we're done.
		 */
		if ((s2 == lstr) || (*(s2 - 1) != ')'))
			return;

		/* We have a closing paren. Locate the opening one. */
		for (s1 = lstr; *s1 && (*s1 != '('); s1++)
			;
		if (*s1 != '(')
			return;

		rec->opt_type = MATCH_OPT_NEED_VER;
		rec->value.name.needobj = lstr;
		rec->value.name.version = s1 + 1;
		s2--;		/* Points at closing paren */

		/* Remove whitespace from head/tail of version */
		WS_SKIP_LIMIT(rec->value.name.version, s2);
		WS_RSKIP_LIMIT(rec->value.name.version, s2);

		/* Terminate needobj, skipping trailing whitespace */
		WS_RSKIP_LIMIT(rec->value.name.needobj, s1);

		return;
	}


	/* If we get here, we are looking at a -I index option */
	rec->value.ndx.start = strtol(str, &s2, 10);
	/* Value must use some of the input, and be positive */
	if ((str == s2) || (rec->value.ndx.start < 1))
		goto syntax_error;
	str = s2;

	WS_SKIP(str);
	if (*str != ':') {
		rec->opt_type = MATCH_OPT_NDX;
	} else {
		str++;					/* Skip the ':' */
		rec->opt_type = MATCH_OPT_RANGE;
		WS_SKIP(str);
		if (*str == '\0') {
			rec->value.ndx.end = -1;	/* Indicates "to end" */
		} else {
			rec->value.ndx.end = strtol(str, &s2, 10);
			if ((str == s2) || (rec->value.ndx.end < 0))
				goto syntax_error;
			str = s2;
			WS_SKIP(str);
		}
	}

	/* If we are successful, there is nothing left to parse */
	if (*str == '\0')
		return;

	/*
	 * If we get here, there is leftover input. Fall through
	 * to issue a syntax error.
	 */
syntax_error:
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF), cname);
	exit(1);

#undef	WS_SKIP
#undef	WS_SKIP_LIMIT
#undef	WS_RSKIP_LIMIT
}

/*
 * Returns True (1) if the version with the given name or index should
 * be displayed, and False (0) if it should not be.
 *
 * entry:
 *	needobj - NULL for VERDEF records, the name of the
 *		needed object for VERNEED.
 *	version - NULL, or needed version
 *	ndx - Versym index of version under consideration, or a value less
 *		than 1 to indicate that no valid index is given.
 *
 * exit:
 *	True will be returned if the given name/index matches those given
 *	by one of the -I or -N command line options, or if no such option
 *	was used in the command invocation.
 */
int
match(const char *needobj, const char *version, int ndx)
{
	Aliste		_idx;
	match_rec_t	*rec;
	const char	*str;

	/* If there is no match list, then we approve everything */
	if (alist_nitems(match_list) == 0)
		return (1);

	/* Run through the match records and check for a hit */
	for (ALIST_TRAVERSE(match_list, _idx, rec)) {
		switch (rec->opt_type) {
		case MATCH_OPT_NAME:
			if (needobj)
				str = needobj;
			else if (version)
				str = version;
			else
				break;
			if (strcmp(rec->value.name.version, str) == 0)
				return (1);
			break;
		case MATCH_OPT_NEED_VER:
			if (needobj && version &&
			    (strcmp(rec->value.name.needobj, needobj) == 0) &&
			    (strcmp(rec->value.name.version, version) == 0))
				return (1);
			break;
		case MATCH_OPT_NDX:
			if ((ndx > 0) && (ndx == rec->value.ndx.start))
				return (1);
			break;
		case MATCH_OPT_RANGE:
			/*
			 * A range end value less than 0 means that any value
			 * above the start is acceptible.
			 */
			if ((ndx > 0) &&
			    (ndx >= rec->value.ndx.start) &&
			    ((rec->value.ndx.end < 0) ||
			    (ndx <= rec->value.ndx.end)))
				return (1);
			break;
		}
	}

	/* Nothing matched */
	return (0);
}

/*
 * List the symbols that belong to a specified version
 *
 * entry:
 *	vsdata - VERSYM related data from the object
 *	vd_ndx - The VERSYM index for symbols to display
 *	vd_name - Version name
 *	needobj - NULL for symbols corresponding to a VERDEF
 *		record. Name of the needed object in the case
 *		of a VERNEED record.
 *	file - Object file
 */
static void
gvers_syms(const Gver_sym_data *vsdata, GElf_Half vd_ndx,
    const char *vd_name, const char *needobj, const char *file)
{
	GElf_Sym	sym;
	int		_symn;

	for (_symn = 0; _symn < vsdata->vsd_symn; _symn++) {
		size_t		size =	0;
		const char	*name;

		if (vsdata->vsd_vsp[_symn] != vd_ndx)
			continue;

		(void) gelf_getsym(vsdata->vsd_sym_data, _symn, &sym);
		name = demangle(vsdata->vsd_strs + sym.st_name);

		/*
		 * Symbols that reference a VERDEF record
		 * have some extra details to handle.
		 */
		if (needobj == NULL) {
			/*
			 * For data symbols defined by this object,
			 * determine the size.
			 */
			if ((GELF_ST_TYPE(sym.st_info) == STT_OBJECT) ||
			    (GELF_ST_TYPE(sym.st_info) == STT_COMMON) ||
			    (GELF_ST_TYPE(sym.st_info) == STT_TLS))
				size = (size_t)sym.st_size;

			/*
			 * Only output the version symbol when the verbose
			 * flag is used.
			 */
			if (!vflag && (sym.st_shndx == SHN_ABS) &&
			    (strcmp(name, vd_name) == 0))
				continue;
		}

		if (oflag) {
			if (needobj == NULL)
				(void) printf(MSG_ORIG(MSG_FMT_SYM_OFIL),
				    file, vd_name);
			else
				(void) printf(MSG_ORIG(MSG_FMT_SYM_NEED_OFIL),
				    file, needobj, vd_name);

			if (size)
				(void) printf(MSG_ORIG(MSG_FMT_SYM_SZ_OFLG),
				    name, (ulong_t)size);
			else
				(void) printf(MSG_ORIG(MSG_FMT_SYM_OFLG), name);
		} else {
			if (size)
				(void) printf(MSG_ORIG(MSG_FMT_SYM_SZ), name,
				    (ulong_t)size);
			else
				(void) printf(MSG_ORIG(MSG_FMT_SYM), name);
		}
	}
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
	char		*strs;

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
			(void) printf(MSG_ORIG(MSG_FMT_LOCSYM_OFLG),
			    file, name);
		} else {
			if (found == 0) {
				found = 1;
				(void) printf(MSG_ORIG(MSG_FMT_LOCSYM_HDR));
			}
			(void) printf(MSG_ORIG(MSG_FMT_LOCSYM), name);
		}
	}
}

/*
 * Print data from the files VERNEED section.
 *
 * If we have been asked to display symbols, then the
 * output format follows that used for verdef sections,
 * with each version displayed separately. For instance:
 *
 *	libc.so.1 (SUNW_1.7):
 *		sym1;
 *		sym2;
 *	libc.so.1 (SUNW_1.9):
 *		sym3;
 *
 * If we are not displaying symbols, then a terse format
 * is used, which combines all the needed versions from
 * a given object into a single line. In this case, the
 * versions are shown whether or not they contribute symbols.
 *
 *	libc.so.1 (SUNW_1.7, SUNW_1.9);
 */
static int
gvers_need(Cache *cache, Cache *need, const Gver_sym_data *vsdata,
    const char *file)
{
	unsigned int	num, _num;
	char		*strs;
	GElf_Verneed	*vnd = need->c_data->d_buf;
	GElf_Shdr	shdr;
	int		error = 0;
	int		show = vflag || (vsdata == NULL) || !oflag;


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
		GElf_Vernaux	*vnap;
		Word		ndx;
		const char	*needobj, *dep;
		int		started = 0, listcnt = 0;

		vnap = (GElf_Vernaux *) ((uintptr_t)vnd + vnd->vn_aux);

		/* Obtain the needed object file name */
		needobj = (char *)(strs + vnd->vn_file);

		error = 1;

		/* Process the versions needed from this object */
		for (ndx = 0; ndx < vnd->vn_cnt; ndx++,
		    vnap = (GElf_Vernaux *)((uintptr_t)vnap + vnap->vna_next)) {
			Conv_ver_flags_buf_t	ver_flags_buf;

			dep = (char *)(strs + vnap->vna_name);

			if (!match(needobj, dep, vnap->vna_other))
				continue;

			if (show) {
				if ((started == 0) || (vsdata != NULL))  {
					/*
					 * If one-line ouput is called for
					 * display the filename being processed.
					 */
					if (oflag && show)
						(void) printf(
						    MSG_ORIG(MSG_FMT_OFIL),
						    file);

					(void) printf(
					    MSG_ORIG(MSG_FMT_LIST_BEGIN),
					    needobj);
					started = 1;
				}

				/*
				 * If not showing symbols, only show INFO
				 * versions in verbose mode. They don't
				 * actually contribute to the version
				 * interface as seen by rtld, so listing them
				 * without qualification can be misleading.
				 */
				if (vflag || (vsdata != NULL) ||
				    (alist_nitems(match_list) != 0) ||
				    !(vnap->vna_flags & VER_FLG_INFO)) {
					const char *fmt = (listcnt == 0) ?
					    MSG_ORIG(MSG_FMT_LIST_FIRST) :
					    MSG_ORIG(MSG_FMT_LIST_NEXT);

					if (vsdata == NULL)
						listcnt++;
					(void) printf(fmt, dep);

					/* Show non-zero flags */
					if (vflag && (vnap->vna_flags != 0))
						(void) printf(
						    MSG_ORIG(MSG_FMT_VER_FLG),
						    conv_ver_flags(
						    vnap->vna_flags,
						    CONV_FMT_NOBKT,
						    &ver_flags_buf));
				}
				if (vsdata != NULL)
					(void) printf(oflag ?
					    MSG_ORIG(MSG_FMT_LIST_END_SEM) :
					    MSG_ORIG(MSG_FMT_LIST_END_COL));
			}

			/*
			 * If we are showing symbols, and vna_other is
			 * non-zero, list them here.
			 *
			 * A value of 0 means that this object uses
			 * traditional Solaris versioning rules, under
			 * which VERSYM does not contain indexes to VERNEED
			 * records. In this case, there is nothing to show.
			 */
			if (vsdata && (vnap->vna_other > 0))
				gvers_syms(vsdata, vnap->vna_other,
				    dep, needobj, file);
		}
		if (show && started && (vsdata == NULL))
			(void) printf(MSG_ORIG(MSG_FMT_LIST_END_SEM));
	}
	return (error);
}

/*
 * Return a GVer_desc descriptor for the given version if one
 * exists.
 *
 * entry:
 *	name - Version name
 *	hash - ELF hash of name
 *	lst - APlist of existing descriptors.
 *	file - Object file containing the version
 *
 * exit:
 *	Return the corresponding GVer_desc struct if it
 *	exists, and NULL otherwise.
 */
static GVer_desc *
gvers_find(const char *name, unsigned long hash, APlist *lst)
{
	Aliste		idx;
	GVer_desc	*vdp;

	for (APLIST_TRAVERSE(lst, idx, vdp))
		if ((vdp->vd_hash == hash) &&
		    (strcmp(vdp->vd_name, name) == 0))
			return (vdp);

	return (NULL);
}

/*
 * Return a GVer_desc descriptor for the given version.
 *
 * entry:
 *	name - Version name
 *	hash - ELF hash of name
 *	lst - List of existing descriptors.
 *	file - Object file containing the version
 *
 * exit:
 *	Return the corresponding GVer_desc struct. If the
 * 	descriptor does not already exist, it is created.
 *	On error, a fatal error is issued and the process exits.
 */
static GVer_desc *
gvers_desc(const char *name, unsigned long hash, APlist **lst, const char *file)
{
	GVer_desc	*vdp;

	if ((vdp = gvers_find(name, hash, *lst)) == NULL) {
		if ((vdp = calloc(sizeof (GVer_desc), 1)) == NULL) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC), cname,
			    file, strerror(err));
			exit(1);
		}

		vdp->vd_name = name;
		vdp->vd_hash = hash;

		pvs_aplist_append(lst, vdp, file);
	}
	return (vdp);
}

/*
 * Insert a version dependency for the given GVer_desc descriptor.
 *
 * entry:
 *	name - Dependency version name
 *	hash - ELF hash of name
 *	lst - List of existing descriptors.
 *	vdp - Existing version descriptor to which the dependency
 *		is to be added.
 *	file - Object file containing the version
 *
 * exit:
 *	A descriptor for the dependency version is looked up
 *	(created if necessary), and then added to the dependency
 *	list for vdp. Returns the dependency descriptor. On error,
 *	a fatal error is issued and the process exits.
 */
static GVer_desc *
gvers_depend(const char *name, unsigned long hash, GVer_desc *vdp, APlist **lst,
    const char *file)
{
	GVer_desc	*_vdp;

	_vdp = gvers_desc(name, hash, lst, file);
	pvs_aplist_append(&vdp->vd_deps, _vdp, file);
	return (vdp);
}

static void
gvers_derefer(GVer_desc *vdp, int weak)
{
	Aliste		idx;
	GVer_desc 	*_vdp;

	/*
	 * If the head of the list was a weak then we only clear out
	 * weak dependencies, but if the head of the list was 'strong'
	 * we clear the REFER bit on all dependencies.
	 */
	if ((weak && (vdp->vd_flags & VER_FLG_WEAK)) || (!weak))
		vdp->vd_flags &= ~FLG_VER_AVAIL;

	for (APLIST_TRAVERSE(vdp->vd_deps, idx, _vdp))
		gvers_derefer(_vdp, weak);
}


static void
recurse_syms(const Gver_sym_data *vsdata, GVer_desc *vdp, const char *file)
{
	Aliste		idx;
	GVer_desc	*_vdp;

	for (APLIST_TRAVERSE(vdp->vd_deps, idx, _vdp)) {
		if (!oflag)
			(void) printf(MSG_ORIG(MSG_FMT_TNCO), _vdp->vd_name);
		gvers_syms(vsdata, _vdp->vd_ndx, _vdp->vd_name, NULL, file);
		if (aplist_nitems(_vdp->vd_deps) != 0)
			recurse_syms(vsdata, _vdp, file);
	}
}


/*
 * Print the files version definition sections.
 */
static int
gvers_def(Cache *cache, Cache *def, const Gver_sym_data *vsdata,
    const char *file)
{
	unsigned int	num, _num;
	char		*strs;
	GElf_Verdef	*vdf = def->c_data->d_buf;
	GElf_Shdr	shdr;
	GVer_desc	*vdp, *bvdp = NULL;
	Aliste		idx1;
	APlist		*verdefs = NULL;
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
		GElf_Verdaux	*vdap;
		const char	*_name;

		vdap = (GElf_Verdaux *)((uintptr_t)vdf + vdf->vd_aux);

		/*
		 * Determine the version name and any dependencies.
		 */
		_name = (char *)(strs + vdap->vda_name);

		vdp = gvers_desc(_name, elf_hash(_name), &verdefs, file);
		vdp->vd_ndx = ndx;
		vdp->vd_flags = vdf->vd_flags | FLG_VER_AVAIL;

		vdap = (GElf_Verdaux *)((uintptr_t)vdap + vdap->vda_next);
		for (cnt--; cnt; cnt--,
		    vdap = (GElf_Verdaux *)((uintptr_t)vdap + vdap->vda_next)) {
			_name = (char *)(strs + vdap->vda_name);
			if (gvers_depend(_name, elf_hash(_name), vdp,
			    &verdefs, file) == NULL)
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
		for (APLIST_TRAVERSE(verdefs, idx1, vdp)) {
			Aliste		idx2;
			GVer_desc 	*_vdp;
			int		type = vdp->vd_flags & VER_FLG_WEAK;

			for (APLIST_TRAVERSE(vdp->vd_deps, idx2, _vdp))
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
	for (APLIST_TRAVERSE(verdefs, idx1, vdp)) {
		Aliste		idx2;
		GVer_desc 	*_vdp;
		int		count;

		if (!match(NULL, vdp->vd_name, vdp->vd_ndx))
			continue;
		if ((alist_nitems(match_list) == 0) &&
		    !(vdp->vd_flags & FLG_VER_AVAIL))
			continue;

		error = 1;

		if (vflag) {
			/*
			 * If the verbose flag is set determine if this version
			 * has a `weak' attribute, and print any version
			 * dependencies this version inherits.
			 */
			if (oflag)
				(void) printf(MSG_ORIG(MSG_FMT_OFIL), file);
			(void) printf(MSG_ORIG(MSG_FMT_VER_NAME), vdp->vd_name);
			if ((vdp->vd_flags & MSK_VER_USER) != 0) {
				Conv_ver_flags_buf_t	ver_flags_buf;

				(void) printf(MSG_ORIG(MSG_FMT_VER_FLG),
				    conv_ver_flags(
				    vdp->vd_flags & MSK_VER_USER,
				    CONV_FMT_NOBKT, &ver_flags_buf));
			}

			count = 1;
			for (APLIST_TRAVERSE(vdp->vd_deps, idx2, _vdp)) {
				const char	*_name = _vdp->vd_name;

				if (count++ == 1) {

					if (oflag)
						(void) printf(
						    MSG_ORIG(MSG_FMT_IN_OFLG),
						    _name);
					else if (vdp->vd_flags & VER_FLG_WEAK)
						(void) printf(
						    MSG_ORIG(MSG_FMT_IN_WEAK),
						    _name);
					else
						(void) printf(
						    MSG_ORIG(MSG_FMT_IN),
						    _name);
				} else
					(void) printf(
					    MSG_ORIG(MSG_FMT_LIST_NEXT), _name);
			}

			if (count != 1)
				(void) printf(MSG_ORIG(MSG_FMT_IN_END));

			if (vsdata && !oflag)
				(void) printf(MSG_ORIG(MSG_FMT_COL_NL));
			else
				(void) printf(MSG_ORIG(MSG_FMT_SEM_NL));
		} else {
			if (vsdata && !oflag)
				(void) printf(MSG_ORIG(MSG_FMT_TNCO),
				    vdp->vd_name);
			else if (!vsdata) {
				if (oflag)
					(void) printf(MSG_ORIG(MSG_FMT_OFIL),
					    file);
				(void) printf(MSG_ORIG(MSG_FMT_TNSE),
				    vdp->vd_name);
			}
		}

		/* If we are not printing symbols, we're done */
		if (vsdata == NULL)
			continue;

		/*
		 * If a specific version to match has been specified then
		 * display any of its own symbols plus any inherited from
		 * other versions. Otherwise simply print out the symbols
		 * for this version.
		 */
		gvers_syms(vsdata, vdp->vd_ndx, vdp->vd_name, NULL, file);
		if (alist_nitems(match_list) != 0) {
			recurse_syms(vsdata, vdp, file);

			/*
			 * If the verbose flag is set, and this is not
			 * the base version, then add the base version as a
			 * dependency.
			 */
			if (vflag && bvdp &&
			    !match(NULL, bvdp->vd_name, bvdp->vd_ndx)) {
				if (!oflag)
					(void) printf(MSG_ORIG(MSG_FMT_TNCO),
					    bvdp->vd_name);
				gvers_syms(vsdata, bvdp->vd_ndx,
				    bvdp->vd_name, NULL, file);
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
	char		*names;
	Cache		*cache, *_cache;
	Cache		*_cache_def, *_cache_need, *_cache_sym, *_cache_loc;
	int		error = 0;
	Gver_sym_data 	vsdata_s;
	const Gver_sym_data	*vsdata = NULL;

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
	Cflag = dflag = lflag = nflag = oflag = rflag = sflag = vflag = 0;

	opterr = 0;
	while ((var = getopt(argc, argv, MSG_ORIG(MSG_STR_OPTIONS))) != EOF) {
		switch (var) {
		case 'C':
			Cflag = USR_DEFINED;
			break;
		case 'd':
			dflag = USR_DEFINED;
			break;
		case 'l':
			lflag = sflag = USR_DEFINED;
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
		case 'I':
		case 'N':
			add_match_record(var, optarg);
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
	if ((dflag == 0) && (rflag == 0) && (lflag == 0))
		dflag = rflag = DEF_DEFINED;

	/*
	 * Open the input file and initialize the elf interface.
	 */
	for (; optind < argc; optind++) {
		int		derror = 0, nerror = 0,	err;
		const char	*file = argv[optind];
		size_t		shnum = 0;

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
		if (elf_getshdrnum(elf, &shnum) == -1) {
			(void) fprintf(stderr, MSG_ORIG(MSG_ELF_GETSHDRNUM),
			    cname, file, elf_errmsg(elf_errno()));
			exit(1);
		}

		if ((cache = calloc(shnum, sizeof (Cache))) == NULL) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC), cname,
			    file, strerror(err));
			exit(1);
		}

		_cache_def = _cache_need = _cache_sym = _cache_loc = NULL;
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
		if (lflag && (_cache_loc == NULL)) {
			(void) fprintf(stderr, MSG_INTL(MSG_VER_UNREDSYMS),
			    cname, file);
			(void) fprintf(stderr, MSG_INTL(MSG_VER_NOSYMTAB));
		}

		/*
		 * If there is more than one input file, and we're not printing
		 * one-line output, display the filename being processed.
		 */
		if ((nfile > 1) && !oflag)
			(void) printf(MSG_ORIG(MSG_FMT_FILE), file);

		/*
		 * If we're printing symbols, then collect the data
		 * necessary to do that.
		 */
		if (_cache_sym != NULL) {
			vsdata = &vsdata_s;
			(void) gelf_getshdr(_cache_sym->c_scn, &shdr);
			vsdata_s.vsd_vsp =
			    (GElf_Versym *)_cache_sym->c_data->d_buf;
			vsdata_s.vsd_sym_data = cache[shdr.sh_link].c_data;
			(void) gelf_getshdr(cache[shdr.sh_link].c_scn, &shdr);
			vsdata_s.vsd_symn = shdr.sh_size / shdr.sh_entsize;
			vsdata_s.vsd_strs =
			    (const char *)cache[shdr.sh_link].c_data->d_buf;
		}


		/*
		 * Print the files version needed sections.
		 */
		if (_cache_need)
			nerror = gvers_need(cache, _cache_need, vsdata, file);

		/*
		 * Print the files version definition sections.
		 */
		if (_cache_def)
			derror = gvers_def(cache, _cache_def, vsdata, file);

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
