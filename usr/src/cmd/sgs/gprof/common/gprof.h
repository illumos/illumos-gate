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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SGS_GPROF_H
#define	_SGS_GPROF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>

#include "sparc.h"
#include "gelf.h"
#include "monv.h"
#include "sgs.h"


/*
 * who am i, for error messages.
 */
extern char	*whoami;

/*
 * booleans
 */
typedef Boolean	bool;

/*
 * Alignment related constants
 */
#define	PGSZ		4096
#define	STRUCT_ALIGN	8

/*
 * Macros related to structure alignment
 */
#define	FLOOR(x, align)	(((Address) x) & ~((align) - 1l))
#define	CEIL(x, align)	FLOOR(((Address) x) + (align) - 1l, align)

#define	PROFHDR_SZ	(CEIL(sizeof (ProfHeader), STRUCT_ALIGN))
#define	PROFMODLIST_SZ	(CEIL(sizeof (ProfModuleList), STRUCT_ALIGN))
#define	PROFMOD_SZ	(CEIL(sizeof (ProfModule), STRUCT_ALIGN))
#define	PROFBUF_SZ	(CEIL(sizeof (ProfBuffer), STRUCT_ALIGN))
#define	PROFCGRAPH_SZ	(CEIL(sizeof (ProfCallGraph), STRUCT_ALIGN))
#define	PROFFUNC_SZ	(CEIL(sizeof (ProfFunction), STRUCT_ALIGN))

#define	HDR_FILLER	(PROFHDR_SZ - sizeof (ProfHeader))
#define	MODLIST_FILLER	(PROFMODLIST_SZ - sizeof (ProfModuleList))
#define	MOD_FILLER	(PROFMOD_SZ - sizeof (ProfModule))
#define	BUF_FILLER	(PROFBUF_SZ - sizeof (ProfBuffer))
#define	CGRAPH_FILLER	(PROFCGRAPH_SZ - sizeof (ProfCallGraph))
#define	FUNC_FILLER	(PROFFUNC_SZ - sizeof (ProfFunction))

/*
 *	ticks per second
 */
long	hz;

typedef	short UNIT;		/* unit of profiling */
typedef unsigned short	unsigned_UNIT; /* to remove warnings from gprof.c */
char	*a_outname;
char	*prog_name;	/* keep the program name for error messages */
#define	A_OUTNAME		"a.out"

typedef unsigned long long pctype;
typedef uint32_t pctype32;
typedef size_t sztype;

/*
 * Type definition for the arc count.
 */
typedef long long actype;
typedef int32_t actype32;

char	*gmonname;
#define	GMONNAME		"gmon.out"
#define	GMONSUM			"gmon.sum"

/*
 * Special symbols used for profiling of shared libraries through
 * the run-time linker.
 */
#define	PRF_ETEXT		"_etext"
#define	PRF_EXTSYM		"<external>"
#define	PRF_MEMTERM		"_END_OF_VIRTUAL_MEMORY"
#define	PRF_SYMCNT		3

/*
 * Special symbol needed to determine the program exec's end addr.
 * Note that since this symbol doesn't get added to the nameslist,
 * it doesn't have to be counted in PRF_SYMCNT
 */
#define	PRF_END			"_end"

/*
 *	blurbs on the flat and graph profiles.
 */
#define	FLAT_BLURB	"/usr/share/lib/ccs/gprof.flat.blurb"
#define	CALLG_BLURB	"/usr/share/lib/ccs/gprof.callg.blurb"

/*
 *	a raw arc,
 *	    with pointers to the calling site and the called site
 *          and a count.
 */
struct rawarc {
	pctype		raw_frompc;
	pctype		raw_selfpc;
	actype		raw_count;
};

struct rawarc32 {
	pctype32	raw_frompc;
	pctype32	raw_selfpc;
	actype32	raw_count;
};

/*
 *	a constructed arc,
 *	    with pointers to the namelist entry of the parent and the child,
 *	    a count of how many times this arc was traversed,
 *	    and pointers to the next parent of this child and
 *	    the next child of this parent.
 */
struct arcstruct {
    struct nl		*arc_parentp;	/* pointer to parent's nl entry */
    struct nl		*arc_childp;	/* pointer to child's nl entry */
    actype		arc_count;	/* how calls from parent to child */
    double		arc_time;	/* time inherited along arc */
    double		arc_childtime;	/* childtime inherited along arc */
    struct arcstruct	*arc_parentlist; /* parents-of-this-child list */
    struct arcstruct	*arc_childlist;	/* children-of-this-parent list */
};
typedef struct arcstruct	arctype;


/*
 * Additions for new-style gmon.out
 */
bool	old_style;			/* gmon.out versioned/non-versioned ? */

/*
 * Executable file info.
 *
 * All info that is required to identify a file or see if it has changed
 * relative to another file.
 */
struct fl_info {
	dev_t	dev;			/* device associated with this file */
	ino_t	ino;			/* i-number of this file */
	time_t	mtime;			/* last modified time of this file */
	off_t	size;			/* size of file */
};
typedef struct fl_info	fl_info_t;

/*
 * Saved file info.
 */
fl_info_t	aout_info;		/* saved file info for program exec */
fl_info_t	gmonout_info;		/* current gmonout's info */


/*
 * Module info.
 */
struct mod_info {
	struct mod_info	*next;		/* ptr to next in the modules list */
	char		*name;		/* name of this module */
	int		id;		/* id, used while printing */
	bool		active;		/* is this module active or not ? */
	struct nl	*nl;		/* ptr to nameslist for this module */
	struct nl	*npe;		/* virtual end of module's namelist */
	sztype		nname;		/* number of funcs in this module */
	GElf_Addr	txt_origin;	/* module's start as given in file */
	GElf_Addr	data_end;	/* module's end addr as in file */
	Address		load_base;	/* actual pcaddr where modl's loaded */
	Address		load_end;	/* actual pcaddr where modl ends */
};
typedef struct mod_info	mod_info_t;

sztype		total_names;	/* from all modules */

/*
 * List of shared object modules. Note that this always includes the
 * program executable as the first element.
 */
mod_info_t	modules;
sztype		n_modules;



/*
 * The symbol table;
 * for each external in the specified file we gather
 * its address, the number of calls and compute its share of cpu time.
 */
struct nl {
    char		*name;		/* the name */
    mod_info_t		*module;	/* module to which this belongs */
    pctype		value;		/* the pc entry point */
    pctype		svalue;		/* entry point aligned to histograms */
    unsigned long	sz;		/* function size */
    unsigned char	syminfo;	/* sym info */
    size_t		nticks;		/* ticks in this routine */
    double		time;		/* ticks in this routine as double */
    double		childtime;	/* cumulative ticks in children */
    actype		ncall;		/* how many times called */
    actype		selfcalls;	/* how many calls to self */
    double		propfraction;	/* what % of time propagates */
    double		propself;	/* how much self time propagates */
    double		propchild;	/* how much child time propagates */
    bool		printflag;	/* should this be printed? */
    int			index;		/* index in the graph list */
    int			toporder;	/* graph call chain top-sort order */
    int			cycleno;	/* internal number of cycle on */
    struct nl		*cyclehead;	/* pointer to head of cycle */
    struct nl		*cnext;		/* pointer to next member of cycle */
    arctype		*parents;	/* list of caller arcs */
    arctype		*children;	/* list of callee arcs */
    unsigned long	ncallers;	/* no. of callers - dumpsum use only */
};
typedef struct nl	nltype;

/*
 *	flag which marks a nl entry as topologically ``busy''
 *	flag which marks a nl entry as topologically ``not_numbered''
 */
#define	DFN_BUSY	-1
#define	DFN_NAN		0

/*
 *	namelist entries for cycle headers.
 *	the number of discovered cycles.
 */
nltype	*cyclenl;		/* cycle header namelist */
int	ncycle;			/* number of cycles discovered */

/*
 * The header on the gmon.out file.
 * old-style gmon.out consists of one of these headers,
 * and then an array of ncnt samples
 * representing the discretized program counter values.
 *	this should be a struct phdr, but since everything is done
 *	as UNITs, this is in UNITs too.
 */
struct hdr {
	pctype		lowpc;
	pctype		highpc;
	pctype		ncnt;
};

struct hdr32 {
	pctype32	lowpc;
	pctype32	highpc;
	pctype32	ncnt;
};

struct hdr	h;		/* header of profiled data */

int	debug;
int 	number_funcs_toprint;

/*
 * Each discretized pc sample has
 * a count of the number of samples in its range
 */
unsigned short	*samples;

pctype	s_lowpc;		/* lowpc from profile file in o-s gmon.out */
pctype	s_highpc;		/* highpc from profile file in o-s gmon.out */
sztype	sampbytes;		/* number of bytes of samples in o-s gmon.out */
sztype	nsamples;		/* number of samples for old-style gmon.out */

double	actime;			/* accumulated time thus far for putprofline */
double	totime;			/* total time for all routines */
double	printtime;		/* total of time being printed */
double	scale;			/* scale factor converting samples to pc */
				/* values: each sample covers scale bytes */
				/* -- all this is for old-style gmon.out only */

unsigned char	*textspace;		/* text space of a.out in core */
bool	first_file;			/* for difference option */

/*
 * Total number of pcsamples read so far (across gmon.out's)
 */
Size	n_pcsamples;

/*
 *	option flags, from a to z.
 */
bool	aflag;				/* suppress static functions */
bool	bflag;				/* blurbs, too */
bool	Bflag;				/* big pc's (i.e. 64 bits) */
bool	cflag;				/* discovered call graph, too */
bool	Cflag;				/* gprofing c++ -- need demangling */
bool	dflag;				/* debugging options */
bool	Dflag;				/* difference option */
bool	eflag;				/* specific functions excluded */
bool	Eflag;				/* functions excluded with time */
bool	fflag;				/* specific functions requested */
bool	Fflag;				/* functions requested with time */
bool	lflag;				/* exclude LOCAL syms in output */
bool	sflag;				/* sum multiple gmon.out files */
bool	zflag;				/* zero time/called functions, too */
bool 	nflag;				/* print only n functions in report */
bool	rflag;				/* profiling input generated by */
					/* run-time linker */


/*
 *	structure for various string lists
 */
struct stringlist {
    struct stringlist	*next;
    char		*string;
};
extern struct stringlist	*elist;
extern struct stringlist	*Elist;
extern struct stringlist	*flist;
extern struct stringlist	*Flist;

/*
 *	function declarations
 */
void	addlist(struct stringlist *, char *);
void	addarc(nltype *, nltype *, actype);
int	arccmp(arctype *, arctype *);
arctype	*arclookup(nltype *, nltype *);
void	printblurb(char *);
void	dfn(nltype *);
bool	dfn_busy(nltype *);
void	dfn_findcycle(nltype *);
bool	dfn_numbered(nltype *);
void	dfn_post_visit(nltype *);
void	dfn_pre_visit(nltype *);
void	dfn_self_cycle(nltype *);
nltype	**doarcs(void);
void	done(void);
void	findcalls(nltype *, pctype, pctype);
void	flatprofheader(void);
void	flatprofline(nltype *);
bool	is_shared_obj(char *);
void	getnfile(char *);
void	process_namelist(mod_info_t *);
void	gprofheader(void);
void	gprofline(nltype *);
int	pc_cmp(const void *arg1, const void *arg2);
int	membercmp(nltype *, nltype *);
nltype	*nllookup(mod_info_t *, pctype, pctype *);
bool	onlist(struct stringlist *, char *);
void	printchildren(nltype *);
void	printcycle(nltype *);
void	printgprof(nltype **);
void	printindex(void);
void	printmembers(nltype *);
void	printmodules(void);
void	printname(nltype *);
void	printparents(nltype *);
void	printprof(void);
void	sortchildren(nltype *);
void	sortmembers(nltype *);
void	sortparents(nltype *);
int	timecmp(const void *arg1, const void *arg2);
int	totalcmp(const void *arg1, const void *arg2);

#define	LESSTHAN	-1
#define	EQUALTO		0
#define	GREATERTHAN	1

/*
 * Macros related to debug messages.
 */
#define	DFNDEBUG	0x0001
#define	CYCLEDEBUG	0x0002
#define	ARCDEBUG	0x0004
#define	TALLYDEBUG	0x0008
#define	TIMEDEBUG	0x0010
#define	SAMPLEDEBUG	0x0020
#define	ELFDEBUG	0x0040
#define	CALLSDEBUG	0x0080
#define	LOOKUPDEBUG	0x0100
#define	PROPDEBUG	0x0200
#define	ANYDEBUG	0x0400

#define	MONOUTDEBUG	0x0800
#define	MODULEDEBUG	0x1000
#define	CGRAPHDEBUG	0x2000
#define	PCSMPLDEBUG	0x4000

#ifdef	__cplusplus
}
#endif

#endif	/* _SGS_GPROF_H */
