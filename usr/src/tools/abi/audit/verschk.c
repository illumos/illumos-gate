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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "abi_audit.h"

/* Variables */
int			Debug;
static const char 	*Numstr = "01234567689.";

/* Internal functions */
static int		compare_ver_inc(char *, char *);
static void		check_ver_inc(liblist_t *);
static void		check_lib_ver(liblist_t *, char *);
static void		check_sym_ver(symbol_t *);

/*
 * assign_versions() will assign vt_lib_ver and vt_sym_ver for a given release.
 * lib_ver should be the highest version of the library and sym_ver should be
 * the lowest version this symbol was exported.
 * The intf_check output will be read in with the highest version of the
 * library first.  So, for a new release, the lib_ver will need to be set,
 * whereas, on subsequent calls to this function, only the sym_ver needs to be
 * reset.
 */

void
assign_versions(liblist_t *orig_lib, liblist_t *new_lib, int rel_num)
{
	char *oldlibver;
	char *newlibver;
	char *newsymver;

	oldlibver = get_lib_ver(orig_lib, rel_num);

	/* Start of a new release */
	if (oldlibver == NULL) {
		newlibver = get_lib_ver(new_lib, rel_num);
		assign_lib_ver(orig_lib, newlibver, rel_num);
	}

	newsymver = get_sym_ver(new_lib, rel_num);
	assign_sym_ver(orig_lib, newsymver, rel_num);
}

/*
 * Returns the first release which is exported.  Returns FAIL if the symbol was
 * never exported
 */

int
find_exported_release(liblist_t *lib, int first_exported)
{
	int		release = 0;
	int		count = 0;
	bvlist_t	*bitmask;

	bitmask =  get_rel_bitmask(0);

	while (count < Total_relcnt) {
		if ((bv_and(bitmask, lib->lt_release) == TRUE) &&
		    (bv_and(bitmask, lib->lt_cat->ct_unexported) != TRUE)) {
			if (first_exported)
				return (count);
			release = count;
		}
		bitmask = bv_bitmask_rshift(bitmask);
		count ++;
	}

	/*
	 * symbol was never exported or it was scoped local during its lifetime.
	 */
	if ((!get_lib_ver(lib, release)) &&
	    (bv_all_zero(lib->lt_cat->ct_public) == TRUE) &&
	    (bv_all_zero(lib->lt_cat->ct_private) == TRUE)) {
		free_bv_list(bitmask);
		return (FAIL);
	}
	free_bv_list(bitmask);
	return (release);
}

/*
 * Version Checker recursively checks for versioning errors in each node of
 * the tree.
 */

void
version_checker(tree_t *rootptr)
{
	if (rootptr) {
		version_checker(rootptr->tt_left);
		check_sym_ver(rootptr->tt_sym);
		version_checker(rootptr->tt_right);
	}
}

/*
 * check_sym_ver() will traverse through the liblist_t and ensure
 * versioning policies are maintained in each library of a given symbol.
 */

static void
check_sym_ver(symbol_t *symbol)
{
	liblist_t	*lib = symbol->st_lib;

	while (lib != NULL) {
		check_lib_ver(lib, symbol->st_sym_name);
		lib = lib->lt_next;
	}
}

/*
 * check_lib_ver() prints error if:
 * 	- base version is not maintained
 * 	- base_vers is not < lib_vers
 * 	- version incrementing between new releases of a lib does not
 * 	follow library versioning policies of incrementing by only ".1"
 */

static void
check_lib_ver(liblist_t *lib, char *sym_name)
{
	int	i = 0;
	int	first_vers, prev_ver_num, var;
	char	*libver;
	char	*next_libver;
	char	*prev_sym_ver, *curr_sym_ver;

	if (!lib->lt_check_me) {
		return;
	}
	if ((first_vers = find_exported_release(lib, 1)) == FAIL) {
		if (Debug)
			(void) fprintf(stderr,
				"%s: check_lib_ver: %s was never exported",
				program, sym_name);
	}
	if (!iflag) {
		if (get_sym_ver(lib, Total_relcnt - 2) != NULL) {
			/* symbol existed in last Solaris Release */
			first_vers = Total_relcnt - 2;
		} else {
			/* symbol is unexported in last Solaris Release */
			first_vers = Total_relcnt - 1;
		}
	}
	curr_sym_ver = get_sym_ver(lib, first_vers);
	prev_ver_num = first_vers;

	for (i = first_vers; i < Total_relcnt; i ++) {
		libver = get_lib_ver(lib, i);

		/*
		 * flag WARNING if SUNWobsolete->SUNWprivate_m.o
		 * flag ERROR if SUNWobsolete->SUNW_m.n.o or any new version
		 * ASSERTION check to make sure it does not happen
		 */
		if (libver && (strstr(libver, "SUNWobsolete") != NULL) &&
		    (i < Total_relcnt - 1)) {
			next_libver = get_lib_ver(lib, i + 1);
			if (next_libver) {
				if (strstr(next_libver, "SUNWprivate") != NULL)
					(void) fprintf(Msgout, "WARNING: ");
				else
					(void) fprintf(Msgout, "ERROR: ");
				(void) fprintf(Msgout,
				    "%s: %s->%s: ", lib->lt_lib_name, libver,
				    next_libver);
				(void) fprintf(Msgout,
				    "new interface introduced to the "
				    "obsolete library\n");
			}
		}

		/*
		 * only do base and new version checking for public symbols.
		 * current_sym_ver can be NULL for releases in which the
		 * symbol is unexported.
		 */
		if (!get_sym_ver(lib, i)) {
			continue;
		}
		if (!curr_sym_ver) {
			continue;
		}
		prev_sym_ver = curr_sym_ver;
		curr_sym_ver = get_sym_ver(lib, i);

		if ((strstr(curr_sym_ver, "SUNW_") == NULL) ||
		    (strstr(prev_sym_ver, "SUNW_") == NULL)) {
			continue;
		}

		/*
		 * ensure the base version is maintained through all
		 * releases of a library
		 */
		if (strcmp(curr_sym_ver, prev_sym_ver) != 0) {
			(void) fprintf(Msgout,
			    "ERROR: %s: %s: "
			    "base version not maintained, was %s in %s, "
			    "becomes %s in ",
			    lib->lt_lib_name, sym_name, prev_sym_ver,
			    get_rel_name(prev_ver_num), curr_sym_ver);
			if (i != (Total_relcnt - 1)) {
				(void) fprintf(Msgout, "%s\n",
				    get_rel_name(i));
			} else {
				(void) fprintf(Msgout, "current release\n");
			}
		}

		/*
		 * ensure new symbols are versioned with the
		 * highest lib_version.  Sym's base version must equal
		 * it's highest lib_version.
		 */
		if (libver &&
		    ((lib->lt_scenario == SCENARIO_01) ||
		    (lib->lt_scenario == SCENARIO_05))) {

			/*
			 * new symbols could have been introduced in update
			 * releases and they have to be versioned in micro
			 * number if only a subset of the new symbols are
			 * backported from the market release to a update
			 * or patch release.  The new version name needs
			 * to be validated.
			 */
			if (strcmp(libver, curr_sym_ver) != 0) {
				if (!iflag &&
				    (first_vers != Total_relcnt - 1)) {
					continue;
				}
				if ((var =
				    count_num_char('.', curr_sym_ver) == 1) ||
				    ((var == 2) &&
				    (compare_ver_inc(curr_sym_ver, libver)
				    == FAIL))) {
					(void) fprintf(Msgout,
					    "ERROR: %s: %s:"
					    " invalid new version, %s "
					    "should be %s in ",
					    lib->lt_lib_name, sym_name,
					    curr_sym_ver, libver);
					if (i != (Total_relcnt - 1)) {
						(void) fprintf(Msgout, "%s\n",
						    get_rel_name(i));
					} else {
						(void) fprintf(Msgout,
						    "current release\n");
					}
				}
				break;
			}
		}
		prev_ver_num = i;
	}
	/*
	 * ensure that the version is incremented by at most ".1"
	 * between previous and new releases of a library
	 */
	check_ver_inc(lib);
}

/*
 * It ensures the integrity of version incrementing is maintained between
 * multiple releases of a library. If not, an error message is printed
 */

static void
check_ver_inc(liblist_t *lib)
{
	char	*prev_ver;
	int	prev_ver_num;
	char	*current_ver;
	int	i;
	int	first_rel;

	if ((first_rel = find_exported_release(lib, 1)) == FAIL) {
		if (Debug)
			(void) fprintf(stderr,
				"%s: check_ver_inc: never exported", program);
	}
	/* current_ver can only be NULL when a symbol is always scoped_local */
	if ((current_ver = get_lib_ver(lib, first_rel)) == NULL)
		return;

	/*
	 * Only check versioning for public symbols, but skip checking of
	 * SYSVABI and SISCD standards versions
	 */
	if ((strstr(current_ver, "SUNW_") == NULL) ||
	    (first_rel+1 >= Total_relcnt))
		return;

	/* prev_ver refers to first release this symbol was exported */
	prev_ver_num = first_rel;

	/*
	 * compare prev_ver to current_ver by always comparing the versions
	 * pairwise.  Reset prev_ver to the last version exported.
	 */
	for (i = first_rel + 1; i < Total_relcnt; i ++) {

		if (get_lib_ver(lib, i) != NULL) {
			prev_ver = current_ver;
			current_ver = get_lib_ver(lib, i);

			/*
			 * check to make sure that increments between releases
			 * of a lib are no greater than .1
			 */
			if ((strstr(current_ver, "SUNW_") != NULL) &&
			    (compare_ver_inc(prev_ver, current_ver) == FAIL)) {
				if (!iflag && (i < Total_relcnt - 1)) {
					continue;
				}
				(void) fprintf(Msgout,
				    "ERROR: %s: was %s in %s, becomes %s in ",
				    lib->lt_lib_name, prev_ver,
				    get_rel_name(prev_ver_num), current_ver);
				if (i != (Total_relcnt - 1)) {
					(void) fprintf(Msgout, "%s:",
					    get_rel_name(i));
				} else {
					(void) fprintf(Msgout,
					    "current release:");
				}
				(void) fprintf(Msgout,
				    " inconsistent increment of version\n");
			}
			prev_ver_num = i;
		}
	}
}

/*
 * compare_ver_inc() checks the major, minor and micro numbers
 * of two public version strings to ensure that the new version hasn't been
 * incremented by more than ".1" per release. Versioning prior to SUNW_1.1
 * is ignored.  Strings matching "SUNW_m.n.o" where "o" is optional, will
 * be checked for this version incrementing scheme.
 */

static int
compare_ver_inc(char *old_version, char *new_version)
{
	char	*oversion;
	char 	*nversion;
	int 	omajor, nmajor, ominor, nminor;
	int	omicro = 0;
	int 	nmicro = 0;

	/* scoped local symbols contain no version numbering */
	if ((strstr(old_version, "_LOCAL_") != NULL) &&
	    (strstr(new_version, "_LOCAL_") != NULL)) {
		return (SUCCEED);
	}

	if (((oversion = strpbrk(old_version, Numstr)) == NULL) ||
	    ((nversion = strpbrk(new_version, Numstr)) == NULL)) {
		return (FAIL);
	}

	/* extracting major, minor and micro number from old version */
	omajor = atoi(oversion);
	if ((oversion = strchr(oversion, '.')) == NULL) {
		return (FAIL);
	}
	oversion ++;
	ominor = atoi(oversion);
	if ((oversion = strrchr(oversion, '.')) != NULL) {
		oversion ++;
		omicro = atoi(oversion);
	}

	/* extracting major, minor and micro number from new version */
	nmajor = atoi(nversion);
	if ((nversion = strchr(nversion, '.')) == NULL) {
		return (FAIL);
	}
	nversion ++;
	nminor = atoi(nversion);
	if ((nversion = strrchr(nversion, '.')) != NULL) {
		nversion ++;
		nmicro = atoi(nversion);
	}

	/* new symbol should be versioned with major >= 1 & minor >= 1 */
	if (omajor == 0 && ominor == 0 && (nmajor < 1 || nminor < 1))
		return (FAIL);

	/* ignore all versioning prior to 1.1 */
	if (omajor == 0 && nmajor == 1 && nminor == 1)
		return (SUCCEED);

	/*
	 * omajor < nmajor; incompatible changes within a library
	 * i.e., SUNW_1.n.o vs. SUNW_2.n.o
	 * omajor > nmajor; impossible to have within a library
	 * i.e., SUNW_2.n.o vs. SUNW_1.n.o
	 */
	if (omajor < nmajor || omajor > nmajor) {
		return (FAIL);

	/* omajor == nmajor */
	} else if (omajor == nmajor) {
		/*
		 * m stays, n is incremented with optional o
		 */
		if (ominor < nminor) {
			/* i.e., SUNW_1.2	vs. SUNW_1.4 */
			if (ominor + 1 != nminor)
				return (FAIL);
			/* i.e., SUNW_1.2	vs. SUNW_1.3.1 */
			/* i.e., SUNW_1.2.1	vs. SUNW_1.3.1 */
			else if (nmicro != 0)
				return (FAIL);
			else
				return (SUCCEED);
		/*
		 * m & n stay the same but o is incremented
		 */
		} else if (ominor == nminor) {
				/* old m.n.o equals to new m.n.o */
				/* i.e., SUNW_1.20.3 vs. SUNW_1.20.3 */
				if (omicro == nmicro)
					return (SUCCEED);
				/* i.e., SUNW_1.20	vs. SUNW_1.20.2 */
				/* i.e., SUNW_1.20.1	vs. SUNW_1.20.3 */
				if (omicro + 1 != nmicro)
					return (FAIL);
				else
					/* i.e., SUNW_1.20 vs. SUNW_1.20.1 */
					/* i.e., SUNW_1.8.2 vs. SUNW_1.8.3 */
					return (SUCCEED);
		/*
		 * m stays & old minor > new minor version
		 * i.e., SUNW_1.21	vs. SUNW_1.20
		 */
		} else if (ominor > nminor)
			return (FAIL);
		else
			return (SUCCEED);
	} else {
		/* It's impossible to reach here but just in case */
		(void) fprintf(Msgout, "ERROR: verschk.c:compare_ver_inc():");
		(void) fprintf(Msgout, "%d.%d.%d <-> %d.%d.%d\n",
		    omajor, ominor, omicro, nmajor, nminor, nmicro);
	}
	return (FAIL);
}
