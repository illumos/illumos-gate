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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
*	File: symintLoad.c
*	Date: 12/15/88
*
*	This file provides code to build the profiling symbol array
*	(array of PROF_SYMBOL).  This array contains all of the
*	symbol table information plus selected debug information for
*	each file and each function that has a coverage array.
*	
*	The symbol table contains entries for every file, every
*	function, and every coverage array.  The debug information
*	has corresponding entries except that there are no entries
*	for the coverage arrays.  (This may change later.)
*
*	The algorithm for building the profiling symbol array
*	consists of scanning the symbol table for file, function,
*	and coverage array entries and building an entry for each.
*	The construction of an entry is constrained by the
*	following factors:
*
*		- An entry is built for every file.
*
*		- An entry is built for a function only if there
*		is a corresponding coverage array for the function.
*
*		- Entries must be ordered in the sense that each
*		non-file entry points to its owner file and each
*		file entry points to the next file (or null).
*
*		- The assembler specification (see C Issue 5 3B2
*		Assembler System Test Specification by Howe, p. 28)
*		states that all local symbols follow their file
*		symbol in the symbol table.  This allows us to relate
*		a function and its coverage array to the file that
*		contains it.
*
*		- For each symbol included in the profiling symbol
*		array, all corresponding symbol table information must
*		be present together with selected debug information.
*		Therefore, the correspondence between a symbol table
*		entry and a debug entry must be established.
*
*		- Although duplicate (static) function names may appear,
*		the names are unique within a given file.  Also, the
*		value (address) of each function is included in both
*		the symbol table information and the debug information.
*		This provides a verifable correspondence between these
*		information sets.
*
*	The algorithm used in this file is as follows:
*/



/*
* This is a discussion of the problem of multiple files with a single
* name.  (See also, the _err_exit call in the routine "add_function".)
*
* Currently, when the executable contains more than one file with
* a common name, we sometimes mix a set of functions with the wrong
* file.  Because the addresses don't match, add_profsymbol tends to
* fail (with _err_exit).  The problem is to consistently choose the
* correct file for the set of functions that are about to be processed.
* This aspect of the problem has been addressed by the code below,
* but there is another part to the story.
*
* In order to match the symbol table with the debug information, we
* have to strip the path (if any) off of the file name; that is,
* the function _CAleaf is used to find the name of the file.  This
* means that even if we make the match, we may still have trouble
* finding the file.  One solution might be to retain a pointer to
* the full name for use at the proper point (when lprof is trying
* to find the source file).  I have not traced this down completely;
* it may or may not work depending upon whether the full path is
* always included in the debug information.  If it is not possible
* to depend on the complete path, then there may be no way to completely
* solve the problem.  (Consider talking to the debugger people about
* this problem; they have to deal with it also.)
*
* Below I have included the code I used to solve the first part of
* the problem.  I have also included an explanation of what each part
* of the code does.  When the code is implemented this way, it does
* work for some cases, but I'm not sure that the assumptions it makes
* are valid.  In particular, it makes implicit assumptions about the
* ordering of names and pointers; you should check that these assumptions
* do not include that the values returned from malloc are monotone
* increasing (which I think they do).
*
* With the following change, add_profsymbol will scan to the first
* file entry of the given name that has not yet been processed.  It
* detects that a file has been processed by noting that sn_value_p
* has been set to zero; it accepts the first one whose value is not
* zero and calls dbfill_tag to "refill" the tag.  Warning: setting
* sn_value_p to zero is dangerous; in particular, you must avoid
* trying to use this value when it is zero.  Some cpus will produce
* a segmentation violation, but the 3b2 does not.
*
* add_profsymbol()
* {
* ...
* 	} else if (stchk_file(prsym_p)) {
* 		if (
* 			(sn_p + 1) < (dblist + dblist_cnt)
* 			&& strcmp(sn_p[0].sn_name_p, sn_p[1].sn_name_p) == 0
* 		) {
* 			_err_warn(
* 				"File name %s was used more than once.",
* 				sn_p->sn_name_p
* 			);
* 			while (
* 				sn_p->sn_value_p == 0
* 				&& sn_p < (dblist + dblist_cnt)
* 			) {
* 				sn_p++;
* 			}
* 			dbfill_tag(sn_p->sn_value_p, &tag);
* 		}
* 		sn_p->sn_value_p = 0;
* 		add_file(&tag);
* 	} else {
* ...
* }
*
* The change to sn_search is only to prepare for a call to sn_compare
* which has been changed to compare on both the name and the pointer
* value (instead of just the name).  (Here, we might be using the
* incorrect assumption that malloc is monotone increasing; this scheme
* should be carefully thought out.)  The change consists of setting
* the sn_value_p in the local tnode to zero; this allows sn_compare
* to ignore the value and compare only the name.
* 
* sn_search()
* {
* ...
* 	tnode.sn_name_p = name_p;
* 	tnode.sn_value_p = 0;
* ...
* }
* 
* This routine used to compare only the name; now it compares both
* the name and  the sn_value_p pointer (see note above sn_search).
* When the value pointer is zero, there is no use in comparing
* that part of the item.
*
* sn_compare()
* {
* 	register int i;
* 
* 	if (i = strcmp(a_p->sn_name_p, b_p->sn_name_p)) {
* 		return(i);
*  	} else if (a_p->sn_value_p == 0 || b_p->sn_value_p == 0) {
*  		return(i);
*  	} else if (a_p->sn_value_p < b_p->sn_value_p) {
*  		return(-1);
*  	} else {
*  		return(1);
*  	}
* }
*/


#include "string.h"
#include "symint.h"
#include "debug.h"

/* search node */
typedef struct {
	char *sn_name_p;
	char *sn_value_p;
} SEARCH_NODE;


PROF_SYMBOL * _symintLoad();

#if isLPROF
static int addcovset();
static SEARCH_NODE *build_stlist();
static int stscan();
static int stchk_focov();
static int stchk_filowog();
static int stchk_gowf();
static int stchk_func();
static int stchk_file();
static int stchk_cov();
static int stchk_match();
static void init_dblist();
static int dbscan_tag();
static void dbfill_tag();
static char * dbseek_att();
static int dbchk_stmnts();
static int dbchk_lowpc();
static int dbchk_highpc();
static int dbchk_filosub();
static PROF_SYMBOL * add_profsymbol();
static int add_function();
static void add_file();
static void check_capacity();
static char * debName();
static LEN4 bytesFor();
static SEARCH_NODE * sn_search();
static int sn_compare();
#ifdef DEBUG
static void sn_dump();
static void profsym_dump();
#endif
static LEN2 alignval2();
static LEN4 alignval4();
static void verify_match();
#endif


/* debug tag */
typedef struct {
	LEN4	tg_length;
	LEN2	tg_value;
	char	*tg_att_p;
	int	tg_attlen;
} DB_TAG;

/*
*	Debug list used to connect a symbol table entry to a debug entry.
*/
static SEARCH_NODE	*dblist;	/* array */
static int		dblist_cnt;	/* number of elements in array */

/*
*	Global symbol table list used to connect coverage array entries
*	with their (global) owner functions.  This list contains all
*	global and weak functions.
*/
static SEARCH_NODE	*gstlist;	/* array */
static int		gstlist_cnt;	/* number of elements in array */

static PROF_FILE	*profPtr;

#define ST_NAME(a)	&profPtr->pf_symstr_p[(a)->st_name]
#define PS_NAME(a)	&profPtr->pf_symstr_p[(a)->ps_sym.st_name]
#define DB_NAME(a)	(a)->ps_dbg.pd_name
#define DB_TAGLEN(ap)	alignval4(ap)
#define DB_STMNTOS(ap)	alignval4((ap) + sizeof(LEN2))
#define DB_PCVALUE(ap)	alignval4((ap) + sizeof(LEN2))

/*
*	NOTE: When you change MATCH_STR, also change pcrt1.s.
*	(See notes on "verify_match" below.)
*/
#ifdef __STDC__
#define	MATCH_NAME	_edata
#define	MATCH_STR	"_edata"
#else
#define	MATCH_NAME	edata
#define	MATCH_STR	"edata"
#endif

static PROF_SYMBOL	*prsym_list_p = 0;	/* the list to return. */
static int		prsym_cnt = 0;	/* #entries in the list */
static int		prsym_cap = 0;	/* #entries capacity allocated */

static int		prstsym_size;	/* size of a symbol table symbol */

static int		add_profsym_search_fail; /* see add_profsymbol() */

#if isLPROF
static int		prsym_size;	/* size of a PROF_SYMBOL */


/* * * * * *
 * addr of line information, and of the PROF_DEBUGE,
 * associated with the last file (symbol) seen.
 * 
 * also, the DEBUGE for the file in effect Before the current one!
 */
#define DBG_LINE_SIZE	(sizeof(LEN4) + sizeof(LEN2) + sizeof(LEN4))
static char		*curf_lp;
static LEN4		curf_lncnt;
static LEN4		curf_base;
static PROF_LINE	*curf_lns_p;

static PROF_DEBUGE	*curf_dbp;
static PROF_DEBUGE	*priorFile_dbp;

#endif

/* * * * * *
 * _symintLoad(proffilePtr)
 * proffilePtr	- PROF_FILE pointer returned by _symintOpen().
 * 
 * returns PROF_SYMBOL * - pointer to the malloc-ed array of
 * 			   symbol information entries, or
 * 			   NULL if fails.
 * 
 * 
 * This routine builds the interface data structure from the data
 * already loaded during _symintOpen().
 * 
 * There are two different incarnations of this routine:
 * one for Prof, and one for Lprof.
 * 
 * Lprof:
 * 
 * 	1. Pass through the symbol table and
 * 	   populate an extended PROF_SYMBOL array.
 * 
 * 	2. Include only certain symbols (see intro).
 * 
 * 	3. Find and include the debug information
 * 	   for each included symbol.
 * 
 * Prof:
 * 
 * 	1. Allocate a duplicate copy of the symbol table
 * 	   data.  (For Prof, a PROF_SYMBOL is just
 * 	   a structure containing an Elf32_Sym!)
 * 
 * 	2. Set internal parameters to reflect this.
 * 
 * 
 * Problems are dealt with by issuing an _err_exit().
 * 
 */
PROF_SYMBOL *
_symintLoad(proffilePtr)
PROF_FILE	*proffilePtr;
{
	Elf_Data	*symdat_p;
	PROF_SYMBOL	*ps;
	int		symcount = 0;
#if isLPROF
	Elf32_Sym	*sym_p;
	Elf32_Sym	*sym_lim_p;
	Elf32_Sym	*next_p;
	Elf32_Sym	*tsym_p;
#endif

	DEBUG_LOC("_symintLoad: top");

	profPtr = proffilePtr;

	/* * * * * *
	 * sanity checks.
	 */
	DEBUG_EXP(printf("profPtr = %x\n", profPtr));
	DEBUG_EXP(printf("profPtr->pf_symdat_p = %x\n", profPtr->pf_symdat_p));
	DEBUG_EXP(printf("profPtr->pf_nstsyms = %x\n", profPtr->pf_nstsyms));

	assert( profPtr != 0 );
	assert( profPtr->pf_symdat_p != 0 );
	assert( profPtr->pf_nstsyms != 0 );

	symdat_p = profPtr->pf_symdat_p;
	DEBUG_EXP(printf("symdat_p->d_size = %x\n", symdat_p->d_size));

	prstsym_size = (symdat_p->d_size / profPtr->pf_nstsyms);
	DEBUG_EXP(printf("_symintLoad: prstsym_size = %d\n",prstsym_size));

#if isLPROF
	prsym_size = prstsym_size + sizeof(PROF_DEBUGE);
	DEBUG_EXP(printf("_symintLoad: prsym_size = %d\n",prsym_size));

	/* * * * * *
	 * Initialize structure parameters.  Updated by add_profsymbol().
	 */
	prsym_cnt = prsym_cap = 0;

	init_dblist();

	sym_lim_p = (Elf32_Sym *)
		(((char *) (symdat_p->d_buf)) + symdat_p->d_size);

	tsym_p = NULL;
	gstlist = build_stlist(tsym_p, sym_lim_p, stchk_gowf, &gstlist_cnt);

	verify_match();

	next_p = NULL;
	(void) stscan(&next_p, sym_lim_p, stchk_file);

	priorFile_dbp = 0;

	sym_p = next_p;
	while (sym_p < sym_lim_p) {
		NO_DEBUG(printf("index for sym_p = %d\n",sym_p->st_name));
		NO_DEBUG(printf("name for sym_p = %s\n", ST_NAME(sym_p)));

		(void) stscan(&next_p, sym_lim_p, stchk_filowog);
		tsym_p = sym_p;
		if (stscan(&tsym_p, next_p, stchk_cov)) {
			symcount += addcovset(sym_p, next_p, tsym_p);
		}
		if (!stchk_file(next_p)) {
			(void) stscan(&next_p, sym_lim_p, stchk_file);
		}
		sym_p = next_p;
	}

	free(gstlist);
	profPtr->pf_nsyms = symcount;

	DEBUG_EXP(printf("number of symbols constructed = %d\n", symcount));
#ifdef DEBUG
	printf("before profsym_dump\n");
	profsym_dump(prsym_list_p, symcount);
	printf("after profsym_dump\n");
#endif

#else	/* isPROF */

	/* * * * * *
	 * alloc a new copy of the array, and
	 *  do a bit-wise copy since the structures
	 *  ARE THE SAME SIZE & (effectively) HAVE THE SAME FIELDS!
	 *  Set the descriptive `parameters' accordingly.
	 * 
	 * (We'll take a copy, to simplify the 'Drop'
	 *  logic.)
	 */

	{
	int st_size;	/* size of symbol table data */

	st_size = symdat_p->d_size;

	NO_DEBUG_LOC("_symintLoad: before malloc for symbol list (PROF)");
	prsym_list_p = (PROF_SYMBOL *) _Malloc(st_size, 1);
	NO_DEBUG_LOC("_symintLoad: after malloc for symbol list (PROF)");
	prsym_cap = prsym_cnt = profPtr->pf_nstsyms;

	NO_DEBUG_LOC("_symintLoad: before memcpy for symbol list (PROF)");
	memcpy((char *) &(prsym_list_p->ps_sym), symdat_p->d_buf, st_size);

	profPtr->pf_nsyms = profPtr->pf_nstsyms;
	}

#endif
	DEBUG_LOC("_symintLoad: bottom");
	return( prsym_list_p );
}


#ifdef  isLPROF
/*
*	addcovset: Add coverage array set to PROF_SYMBOL array.
*
*	The (local) symbols between the given file symbol and the
*	end contain at least one coverage array.  Sort all function
*	and coverage array symbols (by name) within the given bounds
*	and process each of the coverage array symbols by finding
*	its corresponding (local or global) function and adding entries
*	for both the coverage array and the function to the profile
*	symbol array.  Note that the file is also added to the profile
*	symbol array and that pointers are managed accordingly (the file
*	entries are linked and each of the non-file entries points
*	to its owner file).
*
*	- Add the file to the PROF_SYMBOL array.  If the file is not
*	found (i.e., the filename in the debug information does not
*	match the filename in the symbol table), then fail.
*	- Build (allocate) a sorted list of all function and coverage
*	array symbols within the given limits.
*	- Find the top of the coverage array subset of the pointer list.
*	- For each coverage array pointer:
*		- Find its function (look in local list, then global list).
*		- Add function and assoc coverage array to PROF_SYMBOL array.
*	- Free the sorted list.
*
*	Note: "k" is used to avoid having "cov_p" increment beyond
*	the last allocated search node and thereby (possibly) cause
*	a segmentation violation.
*/
static int
addcovset(filsym_p, end_p, cov_p)
Elf32_Sym *filsym_p;
Elf32_Sym *end_p;
Elf32_Sym *cov_p;
{
	SEARCH_NODE	*stl_p;
	SEARCH_NODE	*sncov_p;
	SEARCH_NODE	*snfunc_p;
	PROF_SYMBOL	*ps_p;
	int		k, stlcount;
	char		*fname_p;
	int		symcount = 0;

	DEBUG_LOC("addcovset: top");
	ps_p = add_profsymbol(filsym_p);
	if (add_profsym_search_fail) {
		_err_exit("Unable to locate file %s in debug information.\n",
			ST_NAME(filsym_p)
		);
	}
	ps_p->ps_dbg.pd_file_p = 0;
	symcount++;
	DEBUG_EXP(printf("debug name for ps_p = %s\n", DB_NAME(ps_p)));

	curf_dbp = &(ps_p->ps_dbg);
	if (priorFile_dbp) {
		priorFile_dbp->pd_file_p = curf_dbp;
	}
	priorFile_dbp = curf_dbp;

	stl_p = build_stlist(filsym_p, end_p, stchk_focov, &stlcount);
	sncov_p = sn_search(ST_NAME(cov_p), stl_p, stlcount);
	while (
		(sncov_p-1) >= stl_p
		&& strncmp(
			(sncov_p-1)->sn_name_p,
			COV_PREFIX,
			sizeof(COV_PREFIX)-1
		) == 0
	) {
		sncov_p--;
	}

	k = stlcount;
	while (k-- > 0 && stchk_cov((Elf32_Sym *) (sncov_p->sn_value_p))) {
		fname_p = (char *) &(sncov_p->sn_name_p[sizeof(COV_PREFIX)-1]);
		if (
			(snfunc_p = sn_search(fname_p, stl_p, stlcount))
			|| (snfunc_p = sn_search(fname_p, gstlist, gstlist_cnt))
		) {
			ps_p = add_profsymbol(snfunc_p->sn_value_p);
			ps_p->ps_dbg.pd_file_p = curf_dbp;
			symcount++;

			ps_p = add_profsymbol(sncov_p->sn_value_p);
			ps_p->ps_dbg.pd_file_p = curf_dbp;
			symcount++;
		}
		sncov_p++;
	}

	free(stl_p);
	DEBUG_LOC("addcovset: bottom");
	return(symcount);
}


/*
*	build_stlist: Build a tailored list of symbol table entries.
*/
static SEARCH_NODE *
build_stlist(begin_p, end_p, filter_p, count_p)
Elf32_Sym	*begin_p;
Elf32_Sym	*end_p;
int		(*filter_p)();
int		*count_p;
{
	Elf32_Sym	*tsym_p;
	SEARCH_NODE	*list_p;
	int		i, count;

	DEBUG_LOC("build_stlist: top");
	DEBUG_EXP(printf("begin_p = 0x%lx,  end_p = 0x%lx\n", begin_p, end_p));

	count = 0;
	tsym_p = begin_p;
	while (stscan(&tsym_p, end_p, filter_p)) {
		count++;
	}
	DEBUG_EXP(printf("count = %d\n",count));

	list_p = (SEARCH_NODE *) _Malloc(count, sizeof(*list_p));

	i = 0;
	tsym_p = begin_p;
	while (stscan(&tsym_p, end_p, filter_p)) {
		list_p[i].sn_name_p = ST_NAME(tsym_p);
		list_p[i].sn_value_p = (char *) tsym_p;
		i++;
	}
	DEBUG_EXP(sn_dump("symbol table (pre sort)", list_p, count));

	qsort(list_p, count, sizeof(*list_p), sn_compare);

	DEBUG_EXP(sn_dump("symbol table (post sort)", list_p, count));

	DEBUG_LOC("build_stlist: bottom");
	*count_p = count;
	return(list_p);
}


/*
*	stscan - symbol table scan
*
*	Scan the symbol table until the given limit is reached or
*	the filter function returns true.  Neither the starting
*	symbol (**sym_pp) nor the limit symbol (*lim_p) are legal
*	return values.  Instead, if the starting pointer is NULL,
*	then the first item in the table is a valid return value.
*	This allows the routine to be used as a generator by
*	starting from where the last call stopped.
*/
static int
stscan(sym_pp, lim_p, filter_p)
Elf32_Sym	**sym_pp;
Elf32_Sym	*lim_p;
int		(*filter_p)();
{
	if (*sym_pp == NULL) {
		*sym_pp = (Elf32_Sym *) (profPtr->pf_symdat_p->d_buf);
	} else {
		*sym_pp = (Elf32_Sym *) ((char *) (*sym_pp) + prstsym_size);
	}

	while (*sym_pp < lim_p) {
		if ((*filter_p)(*sym_pp)) {
			return(1);
		}
		*sym_pp = (Elf32_Sym *) ((char *) (*sym_pp) + prstsym_size);
	}
	return(0);
}


/*
*	These routines check the type of a symbol table entry.
*/
static int
stchk_focov(sym_p)	/* symbol is function or coverage array  */
Elf32_Sym *sym_p; {
	return(stchk_func(sym_p) || stchk_cov(sym_p));
}
static int
stchk_filowog(sym_p)	/* symbol is a file, a weak, or a global */
Elf32_Sym *sym_p; {
	return(
		stchk_file(sym_p)
		|| ELF32_ST_BIND(sym_p->st_info) == STB_GLOBAL
		|| ELF32_ST_BIND(sym_p->st_info) == STB_WEAK
	);
}
static int
stchk_gowf(sym_p)	/* symbol is global or weak function */
Elf32_Sym *sym_p; {
	return(
		(stchk_func(sym_p) || stchk_match(sym_p))
		&& (
			ELF32_ST_BIND(sym_p->st_info) == STB_GLOBAL
			|| ELF32_ST_BIND(sym_p->st_info) == STB_WEAK
		)
	);
}
static int
stchk_func(sym_p)	/* symbol is a function */
Elf32_Sym *sym_p; {
	return(ELF32_ST_TYPE(sym_p->st_info) == STT_FUNC);
}
static int
stchk_file(sym_p)	/* symbol is a file */
Elf32_Sym *sym_p; {
	return(ELF32_ST_TYPE(sym_p->st_info) == STT_FILE);
}
static int
stchk_cov(sym_p)	/* symbol is a coverage array */
Elf32_Sym *sym_p; {
	return(
		strncmp(ST_NAME(sym_p), COV_PREFIX, sizeof(COV_PREFIX)-1) == 0
	);
}
static int
stchk_match(sym_p)	/* symbol is the match symbol */
Elf32_Sym *sym_p; {
	return(
		strncmp(ST_NAME(sym_p), MATCH_STR, sizeof(MATCH_STR)-1) == 0
	);
}


/*
*	Initialize debug array (dblist).
*
*	This routine prepares the debug array for searching (see
*	also fillout_sym_dbinfo).
*
*	Initialization proceeds as follows:
*
*		- Count the debug entries that we care about.
*		- _Malloc space to contain the pointers.
*		- Extract pointers and fill in array.
*		- Sort entries alphabetically by name.
*/
static void
init_dblist()
{
	DB_TAG		tag;
	char		*cur_p;
	char		*lim_p;
	Elf_Data	*dat_p;
	int		k;
	extern char	*_CAleaf();

	DEBUG_LOC("init_dblist: top");

	dat_p = profPtr->pf_debugdat_p;

	DEBUG_EXP(printf("dat_p = 0x%lx, d_buf = 0x%x, d_size = %d\n",
		dat_p, dat_p->d_buf, dat_p->d_size
	));

	lim_p = (char *) (dat_p->d_buf) + dat_p->d_size;

	dblist_cnt = 0;
	cur_p = NULL;
	while (dbscan_tag(&cur_p, lim_p, &tag, dbchk_filosub)) {
		dblist_cnt++;
	}

	dblist = (SEARCH_NODE *) _Malloc(dblist_cnt, sizeof(*dblist));

	DEBUG_EXP(printf("dblist_cnt = %d\n",dblist_cnt));
	DEBUG_EXP(printf("dblist = 0x%lx\n", dblist));

	k = 0;
	cur_p = NULL;
	while (dbscan_tag(&cur_p, lim_p, &tag, dbchk_filosub)) {
		dblist[k].sn_name_p = 
			_CAleaf(debName(tag.tg_att_p, tag.tg_attlen));
		dblist[k].sn_value_p = cur_p;
		k++;
	}

	DEBUG_EXP(sn_dump("debug info (pre sort)", dblist, dblist_cnt));

	qsort(dblist, dblist_cnt, sizeof(*dblist), sn_compare);

	DEBUG_EXP(sn_dump("debug info (post sort)", dblist, dblist_cnt));

	DEBUG_LOC("init_dblist: bottom");
}


/*
*	Search for a given tag from the given starting point in
*	the debug information.  If found, fill in the tag at the
*	given pointer and return 1.  Otherwise, return 0.
*/
static int
dbscan_tag(dbpos_pp, dblim_p, tag_p, filter_p)
char	**dbpos_pp;
char	*dblim_p;
DB_TAG	*tag_p;
int	(*filter_p)();
{
	NO_DEBUG_LOC("dbscan_tag: top");

	if (*dbpos_pp == NULL) {
		*dbpos_pp = profPtr->pf_debugdat_p->d_buf;
	} else {
		*dbpos_pp += DB_TAGLEN(*dbpos_pp);
	}

	while (*dbpos_pp < dblim_p) {
		dbfill_tag(*dbpos_pp, tag_p);

		if ((*filter_p)(tag_p->tg_value)) {
			goto success;
		}
		*dbpos_pp += tag_p->tg_length;
	}
	return(0);
success:;
	return(1);
}

static void
dbfill_tag(dbpos_p, tag_p)
char	*dbpos_p;
DB_TAG	*tag_p;
{
	tag_p->tg_length = DB_TAGLEN(dbpos_p);
	tag_p->tg_value = alignval2(dbpos_p + sizeof(LEN4));
	tag_p->tg_att_p = dbpos_p + sizeof(LEN4) + sizeof(LEN2);
	tag_p->tg_attlen = tag_p->tg_length - sizeof(LEN4) - sizeof(LEN2);
}


/*
*	Search the given tag for the given attribute(s).
*	Return a pointer to the attribute or NULL if not found.
*/
static char *
dbseek_att(tag_p, filter_p)
DB_TAG	*tag_p;
int	(*filter_p)();
{
	int	size;
	char	*att_p;

	NO_DEBUG_LOC("dbseek_att: top");

	size = tag_p->tg_attlen;
	att_p = tag_p->tg_att_p;
	NO_DEBUG(printf("attribute size = %d\n",size));
	while (size > 0) {
		LEN4 length;

		if ((*filter_p)(alignval2(att_p))) {
			return(att_p);
		}

		length = bytesFor(att_p);
		NO_DEBUG(printf("bytesFor returns length = %d\n",length));

		size  -= sizeof(LEN2) + length;
		att_p += sizeof(LEN2) + length;
	}
	return((char *) 0);
}


/*
*	dbchk...: Routines that check debug tags and attributes.
*/
static int
dbchk_stmnts(value)	/* statement list (line section) */
LEN2 value;
{
	return(value == AT_stmt_list);
}
static int
dbchk_lowpc(value)	/* statement list (line section) */
LEN2 value;
{
	return(value == AT_low_pc);
}
static int
dbchk_highpc(value)	/* statement list (line section) */
LEN2 value;
{
	return(value == AT_high_pc);
}
static int
dbchk_filosub(value)	/* file or subroutine */
LEN2 value;
{
	switch(value) {
	case TAG_source_file:
	case TAG_subroutine:
	case TAG_global_subroutine:
	case TAG_inline_subroutine:
		return(1);
	default:
		return(0);
	}
}



#define PS_BLKFACTOR	(64)	/* handle this many symbols at a time */

/*
*	add_profsymbol: Add a new entry to the profsymbol array.
*
*	This routine allocates the space required (as needed) for 
*	the PROF_SYMBOL array, extracts the required information
*	from the symbol table and from the debug information, if
*	available (none is recorded for the coverage structures).
*
*	- Check current capacity, assuming one new symbol is to be added.
*	- Copy all of the symbol table information.
*	- Search for the symbol in the debug list.  If this search fails,
*	then flag this failure with "add_profsym_search_fail".  This is used
*	by "addcovset()" for an error exit when a file is not found in the
*	debug information.  This applies only to files - other symbols
*	which are not found may still be valid.
*	- If the symbol is a function, it may be either global or local
*	and local functions are not unique.  Therefore we must compare the
*	address (value) in the symbol table with the address (low_pc)
*	given in the debug information to verify the match.
*	- If the symbol is a file, no verification is needed, but we
*	must change to a new statement list.
*	- If the symbol is a coverage structure, then we are finished with it.
*/
static PROF_SYMBOL *
add_profsymbol(prsym_p)
Elf32_Sym *prsym_p;
{
	DB_TAG		tag;
	PROF_SYMBOL	*ps_p;
	char		*att_p;
	SEARCH_NODE	*sn_p;
	
	DEBUG_LOC("add_profsymbol: top");

	check_capacity();

	ps_p = prsym_list_p + prsym_cnt - 1;
	memcpy((char *) &(ps_p->ps_sym), (char *) prsym_p, prstsym_size);
	memset((char *) &(ps_p->ps_dbg), '\0', sizeof(PROF_DEBUGE));

	DEBUG_EXP(printf("symbol name = %s\n", ST_NAME(prsym_p)));
	ps_p->ps_dbg.pd_name = ST_NAME(prsym_p);

	add_profsym_search_fail = 0;
	if (!(sn_p = sn_search(ST_NAME(prsym_p), dblist, dblist_cnt))) {
		add_profsym_search_fail = 1;
		goto theend;
	}
	DEBUG_EXP(printf("Post search: sn_p->sn_name_p = %s\n",sn_p->sn_name_p));
	dbfill_tag(sn_p->sn_value_p, &tag);

	if (stchk_func(prsym_p)) {
		while (strcmp(ST_NAME(prsym_p), sn_p->sn_name_p) == 0) {
			if (add_function(ps_p, &tag)) {
				break;
			}
			sn_p++;
			dbfill_tag(sn_p->sn_value_p, &tag);
		}
	} else if (stchk_file(prsym_p)) {
		if (
			(sn_p + 1) < (dblist + dblist_cnt)
			&& strcmp(sn_p[0].sn_name_p, sn_p[1].sn_name_p) == 0
		) {
			_err_warn(
				"File name %s was used more than once.",
				sn_p->sn_name_p
			);
		}
		add_file(&tag);
	} else {
		goto theend;
	}

	ps_p->ps_dbg.pd_symtag = tag.tg_value;

theend:;
	DEBUG_LOC("add_profsymbol: bottom");
	return(ps_p);
}


static void
add_file(tag_p)
DB_TAG	*tag_p;
{
	int		i;
	char		*tp;
	PROF_LINE	*lnp;
	char		*att_p;

	att_p = dbseek_att(tag_p, dbchk_stmnts);

	curf_lp = ((char *) profPtr->pf_linedat_p->d_buf) + DB_STMNTOS(att_p);
	curf_lncnt = (alignval4(curf_lp) - 2*sizeof(LEN4)) / DBG_LINE_SIZE;
	curf_base = alignval4(curf_lp + sizeof(LEN4));
	curf_lp += sizeof(LEN4) + sizeof(LEN4);

	curf_lns_p = (PROF_LINE *) _Malloc(curf_lncnt, sizeof(*curf_lns_p));

	i = 0;
	tp = curf_lp;
	lnp = curf_lns_p;
	while (i++ < curf_lncnt) {
		*lnp++ = alignval4(tp);
		tp += DBG_LINE_SIZE;
	}

#ifdef DEBUG
	printf("File Debug Line Information\n");
	printf("   DBG_LINE_SIZE = %d\n", DBG_LINE_SIZE);
	printf("   curf_lp = 0x%x\n", curf_lp);
	printf("   curf_lncnt = %d\n", curf_lncnt);
	printf("   curf_base = 0x%x\n", curf_base);
	printf("   curf_lns_p = 0x%x\n", curf_lns_p);
	printf("Dump of line numbers\n");
	for (i = 0, lnp = curf_lns_p; i < curf_lncnt; i++) {
		printf("   line %d = %d\n", i, lnp[i]);
	}
#endif
}



/*
* add_function -- add to function's PROF_DEBUGE, line# pointer info.
* 
*	Warning: Because we are reading directly from memory, we
*	cannot depend upon the form of the structures we are reading
*	(e.g., pl_delta in PROF_LINE).   Thus, line_p is a "char *"
*	and NOT a "PROF_LINE *".
* 
*
* 	Note from below(***):
* 
* 	Note that this routine finds the range of .line section
* 	entries that should be associated with this function, from
* 	those which belong to this file.
* 
* 	The FIRST line entry for a fcn is selected because
* 	it is the first with a ``delta,'' or memory offset
* 	from the file ``base address (curf_base),''
* 	whose value is GREATER OR EQUAL to the effective offset
* 	associated with this function (lo_delta).
*
* 	The LAST line entry is selected because it is
* 	the LAST with a ``delta'' whose value is LESS THAN
* 	the effective offset of the END of this function (hi_delta)
* 	- i.e. it is the last line number associated with
* 	code that is wholly included in this function!
* 
* 	If no line number is found with a delta value that
* 	exceeds hi_delta (i.e. is part of the next function),
* 	then it is assumed that the last line number entry seen
* 	should simply be accepted as part of this function's set
* 	of line numbers; it simply has no ``bounding line entry.''
*
*/

static int
add_function(ps_p, tag_p)
PROF_SYMBOL	*ps_p;
DB_TAG		*tag_p;
{
	char		*att_p;
	LEN4		high_pc, hi_delta;
	LEN4		low_pc, lo_delta;
	char		*line_p;
	int		first_found = 0;
	PROF_LINE	*pl_p;
	int		i;

	DEBUG_LOC("add_function: top");

	att_p = dbseek_att(tag_p, dbchk_lowpc);
	low_pc = DB_PCVALUE(att_p);
	if (ps_p->ps_sym.st_value != low_pc) {
		DEBUG_LOC("add_function: returning - failed");
		return(0);
	}
	att_p = dbseek_att(tag_p, dbchk_highpc);
	high_pc = DB_PCVALUE(att_p);

	hi_delta = high_pc - curf_base;
	lo_delta = low_pc - curf_base;
	DEBUG_EXP(printf("lo_delta = 0x%x\n", lo_delta));
	DEBUG_EXP(printf("hi_delta = 0x%x\n", hi_delta));

	line_p = curf_lp;
	pl_p = curf_lns_p - 1;

	DEBUG_EXP(printf("Building symbol: %s\n",SYMBOL_NAME(ps_p)));
	i = 0;
	while (i++ < curf_lncnt) {
		LEN4	delad;

		pl_p++;
		delad = alignval4(line_p + sizeof(LEN4) + sizeof(LEN2));

		NO_DEBUG(printf("delad = 0x%x\n", delad));
		NO_DEBUG(printf("line_p = 0x%x\n", line_p));

		if (!first_found && (delad >= lo_delta)) {
			DEBUG_LOC("found first line");
			first_found = 1;
			ps_p->ps_dbg.pd_line_p = pl_p;
		} else if (delad >= hi_delta) {
			DEBUG_LOC("found last line");
			ps_p->ps_dbg.pd_lali_p = pl_p-1;
			break;
		}

		line_p += DBG_LINE_SIZE;
	}

	/*
	*	If the first line is not found, then we have failed
	*	and must return zero.  It is possible (e.g., sometimes
	*	when the function is the last one in the file) for the
	*	first line to be found, but the last not.  In this case,
	*	we assume it simply the last possible line.
	*/
	if (ps_p->ps_dbg.pd_line_p == NULL) {
		_err_exit(
			"Unable to locate line information for function %s.",
			SYMBOL_NAME(ps_p)
		);
	}
	if (ps_p->ps_dbg.pd_lali_p == NULL) {
		DEBUG_LOC("found last line (by default)");
		ps_p->ps_dbg.pd_lali_p = pl_p;
	}
	DEBUG_EXP(printf("first line (pd_line_p) = 0x%x\n",ps_p->ps_dbg.pd_line_p));
	DEBUG_EXP(printf("last line (pd_lali_p) = 0x%x\n",ps_p->ps_dbg.pd_lali_p));

	DEBUG_LOC("add_function: bottom");
	return(1);
}


/* * * * * *
 * If capacity will be exceeded with a new symbol, then
 * increase the capacity.
 */
static void
check_capacity()
{
	if ( ++prsym_cnt > prsym_cap ) {
		if ( prsym_cap == 0 ) {
			prsym_cap = PS_BLKFACTOR;
			prsym_list_p = (PROF_SYMBOL *)
				_Malloc( prsym_size, prsym_cap );
		} else {
			prsym_cap += PS_BLKFACTOR;
			prsym_list_p = (PROF_SYMBOL *)
				_Realloc( (char *) prsym_list_p,
					prsym_size * prsym_cap );
		}
	}
}



/* * * * * *
 * debName -- return ptr to name value for name attr type:attr value pair.
 * 
 * this routine is called by fillout_sym_dbinfo, to scan
 * through a list of debug attributes and return a ptr
 * to the name attrib value, when that type/value pair is found.
 */

static
char *
debName( att_p, att_size )
char	*att_p;		/* ptr to list of (attr_type,attr_value) pairs */
int	att_size;	/* byte length attribute list */
{
	char *name_p = "";
	/* * * * * *
	 * loop through the entries.  when you find a name,
	 * return the addr of the related data (a char string).
	 */

	NO_DEBUG_LOC("debName: top");
	while ( att_size>0 ) {
		LEN2 typea_one;
		LEN4 lena_one;

		NO_DEBUG(printf("att_size = %d\n",att_size));
		typea_one = alignval2(att_p) ;
		NO_DEBUG(printf("typea_one = 0x%x\n",typea_one));
		lena_one  =  bytesFor(att_p) ;
		NO_DEBUG(printf("lena_one = %d\n",lena_one));
		NO_DEBUG(printf("att_p = 0x%x\n",att_p));

		if( typea_one == AT_name ) {
			name_p = att_p + sizeof(LEN2);
			break;
		}
		att_size -= sizeof(LEN2) + lena_one;
		att_p    += sizeof(LEN2) + lena_one;
	}
	NO_DEBUG(printf("name = %s\n",name_p));
	NO_DEBUG_LOC("debName: bottom");
	return( name_p );
}


/* * * * * *
 * bytesFor - indicate the number of bytes of attribute data
 * 		expected to be defined for an attribute type,
 * 		given a ptr to the attribute type:value pair.
 * 
 * we don't particularly care about the specific attribute;
 * more, we are interested in the 'form' of the value
 * associated with this attribute type; hence the 'bit un-masking'.
 * 
 * used by fillout1(). 
 */
static LEN4
bytesFor(attr_p)
char	*attr_p;
{
	LEN4 len;
	LEN2 form, type;
	char *data_p = attr_p + sizeof(LEN2);	/* beginning of attr data */


	NO_DEBUG_LOC("bytesFor: top");

	type = alignval2(attr_p);
	form = type & FORM_MASK ;
	NO_DEBUG(printf("attribute: type = 0x%x",type));
	NO_DEBUG(printf(", form = 0x%x\n",form));
	switch( form )
	{
	case FORM_STRING:	/* NUL-terminated string */
	/* * * * * *
	 * len of string is #chars plus one for NULL.
	 */
		len = strlen(data_p) + 1;
		break;

	case FORM_DATA2:	/* 2 bytes */
		len = 2;
		break;

	case FORM_ADDR:		/* relocated address */
	case FORM_REF:		/* reference to another .debug entry */
	case FORM_DATA4:	/* 4 bytes */
		len = 4;
		break;

	case FORM_DATA8:	/* 8 bytes (two 4-byte values) */
		len = 8;
		break;

	case FORM_BLOCK2:	/* block with 2-byte length, then data */
		len = alignval2(data_p) + 2 ; /* + 2 -> len of length */
		break;

	case FORM_BLOCK4:	/* block with 4-byte length, then data */
		len = alignval4(data_p) + 4 ; /* + 4 -> len of length */
		break;

	case FORM_NONE:		/* error */
	default:
		len = 0;
		break;
	}

	if (len==0)
		_err_exit("Invalid FORM_value %#x for attribute type %#x\n",
			form , type);

	NO_DEBUG_LOC("bytesFor: bottom");
	return(len);
}


/*
*	sn_search: Search sorted list of SEARCH_NODE for given name.
*
*	Search the list for the entry with the given name.  If there
*	is no such entry, return 0.  Otherwise return a pointer to
*	the *first* entry in the list that matches.
*/
static SEARCH_NODE *
sn_search(name_p, list_p, count)
char		*name_p;
SEARCH_NODE	*list_p;
int		count;
{
	SEARCH_NODE	tnode;
	SEARCH_NODE	*sn_p;
	int		index;

	tnode.sn_name_p = name_p;

	sn_p = (SEARCH_NODE *) bsearch(
		(char *) &tnode,
		(char *) list_p,
		count,
		sizeof(*list_p),
		sn_compare
	);

	if (sn_p == NULL) {
		return(NULL);
	}

	index = sn_p - list_p;
	while ((index > 0) && (sn_compare(&list_p[index-1], &tnode) == 0))
		index--;

	return(&list_p[index]);
}

static int
sn_compare(a_p, b_p)
SEARCH_NODE *a_p;
SEARCH_NODE *b_p;
{
	return(strcmp(a_p->sn_name_p, b_p->sn_name_p));
}

#ifdef DEBUG
static void
sn_dump(title_p, snlist_p, sncount)
char		*title_p;
SEARCH_NODE	*snlist_p;
int		sncount;
{
	int i;

	printf("search list for %s: count = %d\n", title_p, sncount);
	for (i = 0; i < sncount; i++) {
		printf(
			"   name = %s,	pointer = 0x%lx\n"
			, snlist_p[i].sn_name_p
			, snlist_p[i].sn_value_p
		);
	}
}

static void
profsym_dump(list_p, count)
PROF_SYMBOL	*list_p;
int		count;
{
	int		i;
	PROF_LINE	*p;

	printf("Dump of %d prof symbols found.\n", count);
	for (i = 0; i < count; i++, list_p++) {
		printf("%d: location 0x%x\n", i, list_p);
		printf("\tSymbol %s\n", ST_NAME(&(list_p->ps_sym)));
		printf("\t   st_size = %d\n", list_p->ps_sym.st_size);
		printf("\t   st_info = 0x%lx\n", list_p->ps_sym.st_info);
		printf("\tDebug Information\n");
		printf("\t   pd_name = %s\n", list_p->ps_dbg.pd_name);
		printf("\t   pd_symtag = 0x%lx\n", list_p->ps_dbg.pd_symtag);
		p = list_p->ps_dbg.pd_line_p;
		printf("\t   *pd_line_p = %d\n", (p ? *p : 0));
		p = list_p->ps_dbg.pd_lali_p;
		printf("\t   *pd_lali_p = %d\n", (p ? *p : 0));
		printf("\t   pd_file_p = 0x%lx\n", list_p->ps_dbg.pd_file_p);
	}
}
#endif


/*
*	alignment routines
*
*	These routines are used to avoid the EMT trap that occurs
*	when moving a unit of data (of 2 or more bytes) across a
*	word boundry.
*/
static LEN2
alignval2(p)
char *p;
{
	LEN2 tmp; char *tp = (char *) &tmp;

	tp[0] = p[0]; tp[1] = p[1];
	return(tmp);
}

static LEN4
alignval4(p)
char *p;
{
	LEN4 tmp; char *tp = (char *) &tmp;

	tp[0] = p[0]; tp[1] = p[1]; tp[2] = p[2]; tp[3] = p[3];
	return(tmp);
}

/*
*	Disscussion of the argv[0] problem and solution.
*
*	If a process is run with a misleading first argument (argv[0]),
*	the profiler will be confused when trying to read the file and
*	match the information against that in memory.  As a confidence
*	check, we compare the address of MATCH_STR as seen in the symbol
*	table to the address of MATCH_STR as seen while running the code.
*	If these are the same, it is *very* unlikely that the file
*	does not correspond to the code in memory.
*
*	Because this code may be run from a shared object, we must
*	insure that our reference to MATCH_STR is that of the main routine.
*	We are depending on MATCH_NAME to not be defined by any shared object
*	(including this one - libprof.so - when so built).
*
*	The search for MATCH_STR in the symbol table is done in _symintLoad
*	because SymintLoad has an ordered version of selected entries from the
*	symbol table which makes searching very efficient (O(log n)).
*
*	See also soqueue.c.
*/

int	_prof_check_match;

static void
verify_match()
{
	SEARCH_NODE	*sn_p;
	Elf32_Sym	*sym_p;
	extern char	MATCH_NAME;

	if (_prof_check_match) {
		if (!(sn_p = sn_search(MATCH_STR, gstlist, gstlist_cnt))) {
			_err_exit("Cannot find match name.");
		} 
		sym_p = (Elf32_Sym *) sn_p->sn_value_p;
		if (sym_p->st_value != (Elf32_Addr) &MATCH_NAME) {
			_err_exit("Location of file for this process unknown.");
		}
	}
}
#endif

