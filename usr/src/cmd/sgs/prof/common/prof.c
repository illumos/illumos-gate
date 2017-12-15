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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 *	Program profiling report generator.
 *
 *	Usage:
 *
 * 	prof [-ChsVz] [-a | c | n | t]  [-o  |  x]   [-g  |  l]
 *	    [-m mdata] [prog]
 *
 *	Where "prog" is the program that was profiled; "a.out" by default.
 *	Options are:
 *
 *	-n	Sort by symbol name.
 *	-t	Sort by decreasing time.
 *	-c	Sort by decreasing number of calls.
 *	-a	Sort by increasing symbol address.
 *
 *	The options that determine the type of sorting are mutually exclusive.
 *	Additional options are:
 *
 *	-o	Include symbol addresses in output (in octal).
 *	-x	Include symbol addresses in output (in hexadecimal).
 *	-g	Include non-global T-type symbols in output.
 *	-l	Do NOT include local T-type symbols in output (default).
 *	-z	Include all symbols in profiling range, even if zero
 *			number of calls or time.
 *	-h	Suppress table header.
 *	-s	Follow report with additional statistical information.
 *	-m mdata Use file "mdata" instead of MON_OUT for profiling data.
 *	-V	print version information for prof (and exit, if only V spec'd)
 *	-C	call C++ demangle routine to demangle names before printing.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <ctype.h>
#include "conv.h"
#include "symint.h"
#include "sys/param.h"			/* for HZ */
#include "mon.h"
#include "sys/stat.h"
#include "debug.h"

#define	OLD_DEBUG(x)

#define	Print	(void) printf
#define	Fprint	(void) fprintf

#if vax
	/* Max positive difference between a fnpc and sl_addr for match */
#define	CCADIFF	22
	/* Type if n_type field in file symbol table entry. */
#endif

#if (u3b || u3b15 || u3b2 || i386)
	/* Max positive difference between a fnpc and sl_addr for match */
#define	CCADIFF	20	/*  ?? (16 would probably do) */
	/* For u3b, the "type" is storage class + section number (no type_t) */
#endif

#if (sparc)
#define	CCADIFF 24	/* PIC prologue length=20 + 4 */
#endif


#define	PROFSEC(ticks) ((double)(ticks)/HZ) /* Convert clock ticks to seconds */

	/* Title fragment used if symbol addresses in output ("-o" or "-x"). */
char *atitle = " Address ";
	/* Format for addresses in output */
char *aformat = "%8o ";

#if !(vax || u3b || u3b15 || u3b2 || i386 || sparc)
	/* Make sure something we are set up for.  Else lay egg. */
#include "### No code for processor type ###"
#endif


	/* Shorthand to gimme the Precise #of addresses per cells */
#define	DBL_ADDRPERCELL		(((double)bias)/sf)


	/* Used for unsigned fixed-point fraction with binary scale at */
	/* the left of 15'th bit (0 as least significant bit) . */
#define	BIAS		((long)0200000L)

/*
 *	TS1 insures that the symbols section is executable.
 */
#define	TS1(s) (((s) > 0) && (scnhdrp[(s)-1].sh_flags & SHF_EXECINSTR))
/*
 *	TS2 insures that the symbol should be reported.  We want
 *	to report only those symbols that are functions (STT_FUNC)
 *	or "notype" (STT_NOTYPE... "printf", for example).  Also,
 *	unless the gflag is set, the symbol must be global.
 */

#define	TS2(i)	\
	(((ELF32_ST_TYPE(i) == STT_FUNC) ||		\
			(ELF32_ST_TYPE(i) == STT_NOTYPE)) &&	\
		((ELF32_ST_BIND(i) == STB_GLOBAL) ||		\
			(gflag && (ELF32_ST_BIND(i) == STB_LOCAL))))

#define	TXTSYM(s, i)	(TS1(s) && TS2(i))

int gflag = 0;			/*  replaces gmatch and gmask */
int Cflag = 0;

PROF_FILE	*ldptr; 		/* For program ("a.out") file. */

FILE	*mon_iop;		/* For profile (MON_OUT) file. */
char	*sym_fn = "a.out";	/* Default program file name. */
char	*mon_fn = MON_OUT;	/* Default profile file name. */
				/* May be changed by "-m file". */

long bias;	/* adjusted bias */
long temp;	/* for bias adjust */

extern void profver(void);

	/* For symbol table entries read from program file. */
PROF_SYMBOL nl;

/* Compare routines called from qsort() */

int c_ccaddr(const void *arg1, const void *arg2);
int c_sladdr(const void *arg1, const void *arg2);
int c_time(const void *arg1, const void *arg2);
int c_ncalls(const void *arg1, const void *arg2);
int c_name(const void *arg1, const void *arg2);

/* Other stuff. */

/* Return size of open file (arg is file descriptor) */
static off_t fsize(int fd);

static void snh(void);
static void Perror(char *s);
static void eofon(FILE *iop, char *fn);
static void usage(void);
static char *getname(PROF_FILE *ldpter, PROF_SYMBOL symbol);

	/* Memory allocation. Like malloc(), but no return if error. */
static void *_prof_Malloc(int item_count, int item_size);

	/* Scan past path part (if any) in the ... */
static char *basename(char *s);

	/* command name, for error messages. */
char	*cmdname;
/* Structure of subroutine call counters (cnt) is defined in mon.h. */

/* Structure for header of mon.out (hdr) is defined in mon.h. */

	/* Local representation of symbols and call/time information. */
struct slist {
	char *sl_name;		/* Symbol name. */
	char *sl_addr;		/* Address. */
	long sl_size;		/* size of symbol */
	long sl_count;		/* Count of subroutine calls */
	float sl_time;		/* Count of clock ticks in this routine, */
				/*		converted to secs. */
};

	/* local structure for tracking synonyms in our symbol list */
struct snymEntry {
	char	*sym_addr;	/* address which has a synonym */
	int	howMany;	/* # of synonyms for this symbol */
	int	snymReported;	/* 'was printed in a report line already'  */
				/* 	flag, */
				/*   > 0 report line printed for these syns. */
				/*  == 0 not printed yet. */
	long	tot_sl_count;	/* total subr calls for these snyms */
	float	tot_sl_time;	/* total clock ticks (a la sl_time) */
};


#define	AOUTHSZ		(filhdr.f_opthdr)
PROF_FILE	filhdr;			/* profile file descriptor */
Elf32_Shdr	*scnhdrp;	/* pointer to first section header */
					/* (space by _prof_Malloc) */

struct hdr head;	/* Profile file (MON_OUT) header. */

int	(*sort)() = NULL;	/* Compare routine for sorting output */
				/*	symbols.  Set by "-[acnt]". */

int	flags;		/* Various flag bits. */

char	*pc_l;		/* From head.lpc. */

char	*pc_h;		/*   "  head.hpc. */

short	VwasSpecified = 0;	/* 1 if -V was specified */

/*
 * Bit macro and flag bit definitions. These need to be identical to the
 * set in profv.h. Any change here should be reflected in profv.c also.
 */
#define	FBIT(pos)	(01 << (pos))	/* Returns value with bit pos set. */
#define	F_SORT		FBIT(0)		/* Set if "-[acnt]" seen. */
#define	F_VERBOSE	FBIT(1)		/* Set if "-s" seen. */
#define	F_ZSYMS		FBIT(2)		/* Set if "-z" seen. */
#define	F_PADDR		FBIT(3)		/* Set if "-o" or "-x" seen. */
#define	F_NHEAD		FBIT(4)		/* Set if "-h" seen. */


struct snymEntry *snymList;	/* Pointer to allocated list of */
				/* synonym entries.  */
struct snymEntry *snymp;
				/* for scanning entries. */

int snymCapacity;		/* #slots in snymList */
int n_snyms;			/* #used slots in snymList */

static int readnl(int symindex);
static int fprecision(long count);

/*
 * Sort flags. Mutually exclusive. These need to be identical to the ones
 * defined in profv.h
 */
#define	BY_ADDRESS	0x1
#define	BY_NCALLS	0x2
#define	BY_NAME		0x4
#define	BY_TIME		0x8

extern unsigned char sort_flag;	/* what type of sort ? */

	/*
	 * printSnymNames - print a comma-seperated list of snym names.
	 * This routine hunts down all the synonyms for the given
	 * symbol, and prints them as a comma-seperated list.
	 * NB we assume that all the synonyms _Follow_ this one,
	 * since they are only printed when the First one
	 * is seen.
	 */
void
printSnymNames(struct slist *slp, struct snymEntry *snymp)
{
	/* how many snyms for this addr, total, and their shared address */
	int i = snymp->howMany;
	char *sharedaddr = snymp->sym_addr;

	/* put out first name - it counts as one, so decr count */
	(void) fputs(slp->sl_name, stdout);
	i--;

	/* for the others: find each, print each. */
	while (--i >= 0) {
		while ((++slp)->sl_addr != sharedaddr)
			;
		Print(", %s", slp->sl_name);
	}
	/* finally.. the trailing newline */
	(void) putchar('\n');
}


	/*
	 * getSnymEntry - see if addr was noted as a aliased address
	 * (i.e. a synonym symbol) and return the address of the
	 * snym entry if it was.
	 */
struct snymEntry *
getSnymEntry(char *sl_addr)
{
	struct snymEntry *p;
	int i;

	for (p = snymList, i = n_snyms; --i >= 0; p++)
		if (sl_addr == p->sym_addr)
			return (p);

	return ((struct snymEntry *)0);
}


int
main(int argc, char **argv)
{
	char buffer[BUFSIZ];	/* buffer for printf */

	WORD *pcounts;	/* Pointer to allocated area for */
			/*	pcounts: PC clock hit counts */

	WORD *pcp;	/* For scanning pcounts. */

	struct cnt *ccounts;	/* Pointer to allocated area for cnt */
				/* structures: subr PC-call counts. */

	struct cnt *ccp;	/* For scanning ccounts. */

	struct slist *slist;	/* Pointer to allocated slist structures: */
				/* symbol name/address/time/call counts */

	struct slist *slp;	/* For scanning slist */

	int vn_cc, n_cc;	/* Number of cnt structures in profile data */
				/*	file (later # ones used). */

	int n_pc;	/* Number of pcounts in profile data file. */

	int n_syms;	/* Number of text symbols (of proper type) */
			/*	that fill in range of profiling. */

	int n_nonzero;	/* Number of (above symbols) actually printed */
			/*	because nonzero time or # calls. */

	int symttl;	/* Total # symbols in program file sym-table */

	int i;

	int fdigits = 0; /* # of digits of precision for print msecs/call */

	int n, symct;

	long sf;	/* Scale for index into pcounts: */
			/*	i(pc) = ((pc - pc_l) * sf)/bias. */

	unsigned pc_m;	/* Range of PCs profiled: pc_m = pc_h - pc_l */

	float	t, t0;
	float	t_tot;	/* Total time: PROFSEC(sum of all pcounts[i]) */
	int	callTotal = 0;

	DEBUG_LOC("main: top");
	setbuf(stdout, buffer);
	cmdname = basename(*argv);	/* command name. */

	while ((n = getopt(argc, argv, "canthsglzoxT:m:VC")) != EOF) {
		switch (n) {
		int (*fcn)();	/* For function to sort results. */

		case 'm':	/* Specify data file:	-m file */
			mon_fn = optarg;
			break;

#ifdef ddt
		case 'T':	/* Set trace flags: -T(octnum) */
			debug_value = (int)strtol(optarg, 0, 8);
			break;
#endif

		case 'n':	/* Sort by symbol name. */
			fcn = c_name;
			sort_flag |= BY_NAME;
			goto check;

		case 't':	/* Sort by decreasing time. */
			fcn = c_time;
			sort_flag |= BY_TIME;
			goto check;

		case 'c':	/* Sort by decreasing # calls. */
			fcn = c_ncalls;
			sort_flag |= BY_NCALLS;
			goto check;

		case 'a':	/* Sort by increasing symbol address */
				/*		(don't have to -- it will be) */
			fcn = NULL;
			sort_flag |= BY_ADDRESS;
		check:		/* Here to check sort option conflicts. */
			if (sort != NULL && sort != fcn) {
				Fprint(stderr, "%s: Warning: %c overrides"
				" previous specification\n", cmdname, n);
			}
			sort = fcn;	/* Store sort routine */
			flags |= F_SORT; /* Note have done so */
			break;

		case 'o':	/* Include symbol addresses in output. */
		case 'x':	/* Include symbol addresses in output. */
			aformat[2] = n;	/* 'o' or 'x' in format */
			flags |= F_PADDR;	/* Set flag. */
			break;

		case 'g':	/* Include local T symbols as well as global */
			gflag = 1;
			break;

		case 'l':	/* Do NOT include local T symbols */
			gflag = 0;
			break;

		case 'z':	/* Print all symbols in profiling range, */
				/*	 even if no time or # calls. */
			flags |= F_ZSYMS;	/* Set flag. */
			break;

		case 'h':	/* Suppress table header. */
			flags |= F_NHEAD;
			break;

		case 's':	/* Follow normal output with extra summary. */
			flags |= F_VERBOSE;	/* Set flag (...) */
			break;

		case 'V':
			(void) fprintf(stderr, "prof: %s %s\n",
			    (const char *)SGU_PKG, (const char *)SGU_REL);
			VwasSpecified = 1;
			break;

		case 'C':	/* demangle C++ names before printing. */
			Cflag = 1;
			break;

		case '?':	/* But no good. */
			usage();
		}	/* End switch (n) */
	}	/* End while (getopt) */

	DEBUG_LOC("main: following getopt");

	/* if -V the only argument, just exit. */
	if (VwasSpecified && argc == 2 && !flags)
		exit(0);

	if (optind < argc)
		sym_fn = argv[optind];	/* name other than `a.out' */

	if (sort == NULL && !(flags & F_SORT))
				/* If have not specified sort mode ... */
		sort = c_time;		/* then sort by decreasing time. */

	/*
	 * profver() checks to see if the mon.out was "versioned" and if
	 * yes, processes it and exits; otherwise, we have an *old-style*
	 * mon.out and we process it the old way.
	 */
	profver();

		/* Open monitor data file (has counts). */
	if ((mon_iop = fopen(mon_fn, "r")) == NULL)
		Perror(mon_fn);

	DEBUG_LOC("main: before _symintOpen");
	if ((ldptr = _symintOpen(sym_fn)) == NULL) {
		Perror("_symintOpen failed");
	}
	DEBUG_LOC("main: after _symintOpen");
	filhdr = *ldptr;

	scnhdrp = ldptr->pf_shdarr_p;

	{
	Elf_Kind k = elf_kind(filhdr.pf_elf_p);

	DEBUG_EXP(printf("elf_kind = %d\n", k));
	DEBUG_EXP(printf("elf_type = %d\n", filhdr.pf_elfhd_p->e_type));
	if ((k != ELF_K_ELF) || (filhdr.pf_elfhd_p->e_type != ET_EXEC)) {
		Fprint(stderr, "%s: %s: improper format\n", cmdname, sym_fn);
		exit(1);
	}
	}

	/* Compute the file address of symbol table. Machine-dependent. */

	DEBUG_EXP(printf("number of symbols (pf_nsyms) = %d\n",
	    filhdr.pf_nsyms));

		/* Number of symbols in file symbol table. */
	symttl = filhdr.pf_nsyms;
	if (symttl == 0) {		/* This is possible. */
		Fprint(stderr, "%s: %s: no symbols\n", cmdname, sym_fn);
		exit(0);		/* Note zero exit code. */
	}
	/* Get size of file containing profiling data. Read header part. */
	n = fsize(fileno(mon_iop));
	if (fread((char *)&head, sizeof (struct hdr), 1, mon_iop) != 1)
		eofon(mon_iop, mon_fn);		/* Probably junk file. */

	/* Get # cnt structures (they follow header), */
	/*		and allocate space for them. */

	n_cc = head.nfns;
	ccounts = _prof_Malloc(n_cc, sizeof (struct cnt));

		/* Read the call addr-count pairs. */
	if (fread((char *)ccounts, sizeof (struct cnt), n_cc, mon_iop) != n_cc)
		eofon(mon_iop, mon_fn);

	/*
	 * Compute # PC counters (pcounts), which occupy whatever is left
	 * of the file after the header and call counts.
	 */

	n_pc = (n - sizeof (head) - n_cc * sizeof (struct cnt))/sizeof (WORD);
	ccp = &ccounts[n_cc];	/* Point to last (+1) of call counters ... */
	do {		/* and scan backward until find highest one used. */
		if ((--ccp)->mcnt)
			break;		/* Stop when find nonzero count. */
	} while (--n_cc > 0);		/* Or all are zero. */

	if (n_cc > 0) {

	/* If less than all cnt entries are used, return unused space. */
	if (n_cc < head.nfns) {
		if ((ccounts = (struct cnt *)realloc((char *)ccounts,
		    (unsigned)n_cc * sizeof (struct cnt))) == NULL)
			snh();	/* Should not fail when reducing size. */
	}

	/* If more than 250 cnt entries used set verbose for warning */
	if (n_cc > (MPROGS0 * 5)/6)
		flags |= F_VERBOSE;

		/* Space for PC counts. */
	pcounts = (WORD *)_prof_Malloc(n_pc, sizeof (WORD));
		/* Read the PC counts from rest of MON_OUT file. */
	if (fread((char *)pcounts, sizeof (WORD), n_pc, mon_iop) != n_pc)
		eofon(mon_iop, mon_fn);
	/*
	 *
	 * Having gotten preliminaries out of the way, get down to business.
	 * The range pc_m of addresses over which profiling was done is
	 * computed from the low (pc_l) and high (pc_h) addresses, gotten
	 * from the MON_OUT header.  From this and the number of clock
	 * tick counters, n_pc, is computed the so-called "scale", sf, used
	 * in the mapping of addresses to indices, as follows:
	 *
	 *		(pc - pc_l) * sf
	 *	i(pc) = ----------------
	 *		  0200000
	 *
	 * Also, the N-to-one value, s_inv, such that
	 *
	 *	i(pc_l + K * s_inv + d) = K, for 0 <= d < s_inv
	 *
	 * Following this, the symbol table is scanned, and those symbols
	 * that qualify are counted.  These  are T-type symbols, excluding
	 * local (nonglobal) unless the "-g" option was given. Having thus
	 * determined the space requirements, space for symbols/times etc.
	 * is allocated, and the symbol table re-read, this time keeping
	 * qualified symbols.
	 *
	 * NB s_inv, as actually computed, is not sufficiently accurate
	 * (since it is truncated) for many calculations.  Since it is
	 * logically equivalent to 1/(sf/bias), and the latter is much
	 * more accurate, therefore the latter will often appear in
	 * the code when 's_inv' is mentioned.  dween
	 *
	 */


	pc_l = head.lpc;	/* Low PC of range that was profiled. */
	pc_h = head.hpc;	/* First address past range of profiling. */
	pc_m = pc_h - pc_l;	/* Range of profiled addresses. */

	/* BEGIN CSTYLED */
OLD_DEBUG(if (debug_value) Fprint(stderr,
"low pc = %#o, high pc = %#o, range = %#o = %u\n\
call counts: %u, %u used; pc counters: %u\n",
pc_l, pc_h, pc_m, pc_m, head.nfns, n_cc, n_pc));
	/* END CSTYLED */

	/*LINTED: E_ASSIGMENT_CAUSE_LOSS_PREC*/
	sf = (BIAS * (double)n_pc)/pc_m;
	/*
	 * Now adjust bias and sf so that there is no overflow
	 * when calculating indices.
	 */
	bias = BIAS;
	temp = pc_m;
	while ((temp >>= 1) > 0x7fff) {
		sf >>= 1;
		bias >>= 1;
	}

	/* BEGIN CSTYLED */
OLD_DEBUG(
	if (debug_value) {

		Fprint(stderr, "sf = %d, s_inv = %d bias = %d\n",
		    (long)sf, pc_m / n_pc, bias);
	}
);
	/* END CSTYLED */

		/* Prepare to read symbols from "a.out" (or whatever). */
	n_syms = 0;			/* Init count of qualified symbols. */
	n = symttl;			/* Total symbols. */
	while (--n >= 0)			/* Scan symbol table. */
		if (readnl(n))	/* Read and examine symbol, count qualifiers */
			n_syms++;

	/* BEGIN CSTYLED */
OLD_DEBUG(
	if (debug_value) {
		Fprint(stderr, "%u symbols, %u qualify\n", symttl, n_syms);
	}
);
	/* END CSTYLED */

		/* Allocate space for qualified symbols. */

	slist = slp = _prof_Malloc(n_syms, sizeof (struct slist));

		/*
		 * Allocate space for synonym symbols
		 * (i.e. symbols that refer to the same address).
		 * NB there can be no more than n_syms/2 addresses
		 * with symbols, That Have Aliases, that refer to them!
		 */

	snymCapacity = n_syms/2;
	snymList = snymp =
	    _prof_Malloc(snymCapacity, sizeof (struct snymEntry));
	n_snyms = 0;

/* OLD_DEBUG(debug_value &= ~020); */

	/* Loop on number of qualified symbols. */
	for (n = n_syms, symct = 0; n > 0; symct++) {
		if (readnl(symct)) {	/* Get one. Check again. */
				/* Is qualified. Move name ... */
			slp->sl_name = getname(ldptr, nl);

				/* and address into slist structure. */
			slp->sl_addr = (char *)nl.ps_sym.st_value;
			slp->sl_size = nl.ps_sym.st_size;

				/* set other slist fields to zero. */
			slp->sl_time = 0.0;
			slp->sl_count = 0;
	/* BEGIN CSTYLED */
OLD_DEBUG(
	if (debug_value & 02)
		Fprint(stderr, "%-8.8s: %#8o\n", slp->sl_name, slp->sl_addr)
);
	/* END CSTYLED */

			slp++;
			--n;
		}
	}
	/*
	 *
	 * Now attempt to match call counts with symbols.  To do this, it
	 * helps to first sort both the symbols and the call address/count
	 * pairs by ascending address, since they are generally not, to
	 * begin with.  The addresses associated with the counts are not,
	 * of course, the subroutine addresses associated with the symbols,
	 * but some address slightly past these. Therefore a given count
	 * address (in the fnpc field) is matched with the closest symbol
	 * address (sl_addr) that is:
	 *	(1) less than the fnpc value but,
	 *	(2) not more than the length of the function
	 * In other words, unreasonable matchups are avoided.
	 * Situations such as this could arise when static procedures are
	 * counted but the "-g" option was not given to this program,
	 * causing the symbol to fail to qualify.  Without this limitation,
	 * unmatched counts could be erroneously charged.
	 *
	 */


	ccp = ccounts;			/* Point to first call counter. */
	slp = slist;			/*   "		"   "   symbol. */
		/* Sort call counters and ... */
	qsort((char *)ccp, (unsigned)n_cc, sizeof (struct cnt), c_ccaddr);
		/* symbols by increasing address. */
	qsort((char *)slp, (unsigned)n_syms, sizeof (struct slist), c_sladdr);
	vn_cc = n_cc;			/* save this for verbose option */


		/* Loop to match up call counts & symbols. */
	for (n = n_syms; n > 0 && vn_cc > 0; ) {
		int	sz = slp->sl_size;

		if (sz == 0)
			sz = slp[ 1 ].sl_addr - slp->sl_addr;
		if (slp->sl_addr < ccp->fnpc &&
		    ccp->fnpc <= slp->sl_addr + sz) {
					/* got a candidate: find Closest. */
			struct slist *closest_symp;
			do {
				closest_symp = slp;
				slp++;
				--n;
			} while (n > 0 && slp->sl_addr < ccp->fnpc);

	/* BEGIN CSTYLED */
OLD_DEBUG(
if (debug_value & 04) {
	Fprint(stderr,
		"Routine %-8.8s @ %#8x+%-2d matches count address %#8x\n",
		closest_symp->sl_name,
		closest_symp->sl_addr,
		ccp->fnpc-slp->sl_addr,
		ccp->fnpc);
}
);
	/* END CSTYLED */
			closest_symp->sl_count = ccp->mcnt;  /* Copy count. */
			++ccp;
			--vn_cc;
		} else if (ccp->fnpc < slp->sl_addr) {
			++ccp;
			--vn_cc;
		} else {
			++slp;
			--n;
		}
	}

	/*
	 *
	 * The distribution of times to addresses is done on a proportional
	 * basis as follows: The t counts in pcounts[i] correspond to clock
	 * ticks for values of pc in the range pc, pc+1, ..., pc+s_inv-1
	 * (odd addresses excluded for PDP11s). Without more detailed info,
	 * it must be assumed that there is no greater probability
	 * of the clock ticking for any particular pc in this range than for
	 * any other.  Thus the t counts are considered to be equally
	 * distributed over the addresses in the range, and that the time for
	 * any given address in the range is pcounts[i]/s_inv.
	 *
	 * The values of the symbols that qualify, bounded below and above
	 * by pc_l and pc_h, respectively, partition the profiling range into
	 * regions to which are assigned the total times associated with the
	 * addresses they contain in the following way:
	 *
	 * The sum of all pcounts[i] for which the corresponding addresses are
	 * wholly within the partition are charged to the partition (the
	 * subroutine whose address is the lower bound of the partition).
	 *
	 * If the range of addresses corresponding to a given t = pcounts[i]
	 * lies astraddle the boundary of a partition, e.g., for some k such
	 * that 0 < k < s_inv-1, the addresses pc, pc+1, ..., pc+k-1 are in
	 * the lower partition, and the addresses pc+k, pc+k+1, ..., pc+s_inv-1
	 * are in the next partition, then k*pcounts[i]/s_inv time is charged
	 * to the lower partition, and (s_inv-k) * pcounts[i]/s_inv time to the
	 * upper.  It is conceivable, in cases of large granularity or small
	 * subroutines, for a range corresponding to a given pcounts[i] to
	 * overlap three regions, completely containing the (small) middle one.
	 * The algorithm is adjusted appropriately in this case.
	 *
	 */


	pcp = pcounts;				/* Reset to base. */
	slp = slist;				/* Ditto. */
	t0 = 0.0;				/* Time accumulator. */
	for (n = 0; n < n_syms; n++) {		/* Loop on symbols. */
			/* Start addr of region, low addr of overlap. */
		char *pc0, *pc00;
			/* Start addr of next region, low addr of overlap. */
		char *pc1, *pc10;
		/* First index into pcounts for this region and next region. */
		int i0, i1;
		long ticks;

			/* Address of symbol (subroutine). */
		pc0 = slp[n].sl_addr;

			/* Address of next symbol, if any or top */
			/* of profile range, if not */
		pc1 = (n < n_syms - 1) ? slp[n+1].sl_addr : pc_h;

			/* Lower bound of indices into pcounts for this range */

		i0 = (((unsigned)pc0 - (unsigned)pc_l) * sf)/bias;

			/* Upper bound (least or least + 1) of indices. */
		i1 = (((unsigned)pc1 - (unsigned)pc_l) * sf)/bias;

		if (i1 >= n_pc)				/* If past top, */
			i1 = n_pc - 1;				/* adjust. */

			/* Lowest addr for which count maps to pcounts[i0]; */
		pc00 =  pc_l + (unsigned long)((bias * i0)/sf);

			/* Lowest addr for which count maps to pcounts[i1]. */
		pc10 =  pc_l + (unsigned long)((bias * i1)/sf);

	/* BEGIN CSTYLED */
OLD_DEBUG(if (debug_value & 010) Fprint(stderr,
"%-8.8s\ti0 = %4d, pc00 = %#6o, pc0 = %#6o\n\
\t\ti1 = %4d, pc10 = %#6o, pc1 = %#6o\n\t\t",
slp[n].sl_name, i0, pc00, pc0, i1, pc10, pc1));
	/* END CSTYLED */
		t = 0;			/* Init time for this symbol. */
		if (i0 == i1) {
			/* Counter overlaps two areas? (unlikely */
			/* unless large granularity). */
			ticks = pcp[i0];	/* # Times (clock ticks). */
OLD_DEBUG(if (debug_value & 010) fprintf(stderr, "ticks = %d\n", ticks));

			    /* Time less that which overlaps adjacent areas */
			t += PROFSEC(ticks * ((double)(pc1 - pc0) * sf)/bias);

	/* BEGIN CSTYLED */
OLD_DEBUG(if (debug_value & 010)
	Fprint(stderr, "%ld/(%.1f)", (pc1 - pc0) * ticks, DBL_ADDRPERCELL)
);
	/* END CSTYLED */
		} else {
				/* Overlap with previous region? */
			if (pc00 < pc0) {
				ticks = pcp[i0];
	/* BEGIN CSTYLED */
OLD_DEBUG(if (debug_value & 010)
	fprintf(stderr, "pc00 < pc0 ticks = %d\n", ticks));

				/* Get time of overlapping area and */
				/* subtract proportion for lower region. */
				t += PROFSEC(
				ticks*(1-((double)(pc0-pc00) *sf)/bias));

				/* Do not count this time when summing times */
				/*		wholly within the region. */
				i0++;
	/* BEGIN CSTYLED */
OLD_DEBUG(if (debug_value & 010)
	Fprint(stderr, "%ld/(%.1f) + ", (pc0 - pc00) * ticks,
		DBL_ADDRPERCELL));
	/* END CSTYLED */
			}

			/* Init sum of counts for PCs not shared w/other */
			/*	routines. */
			ticks = 0;

			/* Stop at first count that overlaps following */
			/*	routine. */
			for (i = i0; i < i1; i++)
				ticks += pcp[i];

			t += PROFSEC(ticks); /* Convert to secs, add to total */
OLD_DEBUG(if (debug_value & 010) Fprint(stderr, "%ld", ticks));
			/* Some overlap with low addresses of next routine? */
			if (pc10 < pc1) {
					/* Yes. Get total count ... */
				ticks = pcp[i1];

				/* and accumulate proportion for addresses in */
				/*		range of this routine */
				t += PROFSEC(((double)ticks *
				    (pc1 - pc10)*sf)/bias);
	/* BEGIN CSTYLED */
OLD_DEBUG(if (debug_value & 010) fprintf(stderr, "ticks = %d\n", ticks));
OLD_DEBUG(if (debug_value & 010)
	Fprint(stderr, " + %ld/(%.1f)", (pc1 - pc10) * ticks, DBL_ADDRPERCELL)
);
	/* END CSTYLED */
			}
		}		/* End if (i0 == i1) ... else ... */

		slp[n].sl_time = t;	/* Store time for this routine. */
		t0 += t;		/* Accumulate total time. */
OLD_DEBUG(if (debug_value & 010) Fprint(stderr, " ticks = %.2f msec\n", t));
	}	/* End for (n = 0; n < n_syms; n++) */

	/* Final pass to total up time. */
	/* Sum ticks, then convert to seconds. */

	for (n = n_pc, temp = 0; --n >= 0; temp += *(pcp++))
		;

	t_tot = PROFSEC(temp);

	/*
	 * Now, whilst we still have the symbols sorted
	 * in address order..
	 * Loop to record duplicates, so we can display
	 * synonym symbols correctly.
	 * Synonym symbols, or symbols with the same address,
	 * are to be displayed by prof on the same line, with
	 * one statistics line, as below:
	 *			... 255  ldaopen, ldaopen
	 * The way this will be implemented, is as follows:
	 *
	 * Pass 1 - while the symbols are in address order, we
	 *  do a pre-pass through them, to determine for which
	 *  addresses there are more than one symbol (i.e. synonyms).
	 *  During this prepass we collect summary statistics in
	 *  the synonym entry, for all the synonyms.
	 *
	 * 'Pass' 2 - while printing a report,  for each report line,
	 *  if the current symbol is a synonym symbol (i.e. in the
	 *  snymList) then we scan forward and pick up all the names
	 *  which map to this address, and print them too.
	 *  If the address' synonyms have already been printed, then
	 *  we just skip this symbol and go on to process the next.
	 *
	 */

	{
	/* pass 1 */
	char *thisaddr;
	char *lastaddr = slist->sl_addr; /* use 1st sym as */
					/* 'last/prior symbol' */
	int lastWasSnym = 0;	/* 1st can't be snym yet-no aliases seen! */
	int thisIsSnym;

	/* BEGIN CSTYLED */
OLD_DEBUG(
int totsnyms = 0; int totseries = 0; struct slist *lastslp = slist;
);
	/* END CSTYLED */

	/* NB loop starts with 2nd symbol, loops over n_syms-1 symbols! */
	for (n = n_syms-1, slp = slist+1; --n >= 0; slp++) {
		thisaddr = slp->sl_addr;
		thisIsSnym = (thisaddr == lastaddr);

		if (thisIsSnym) {
			/* gotta synonym */
			if (!lastWasSnym) {
	/* BEGIN CSTYLED */
OLD_DEBUG(
if (debug_value)  {
	Fprint(stderr,
		"Synonym series:\n1st->\t%s at address %x, ct=%ld, time=%f\n",
		lastslp->sl_name, lastaddr, lastslp->sl_count,
		lastslp->sl_time);
	totseries++;
	totsnyms++;
}
);
	/* END CSTYLED */
				/* this is the Second! of a series */
				snymp = (n_snyms++ == 0 ? snymList : snymp+1);
				snymp->howMany = 1; /* gotta count 1st one!! */
				snymp->sym_addr = slp->sl_addr;
				/* zero summary statistics */
				snymp->tot_sl_count = 0;
				snymp->tot_sl_time = 0.0;
				/* Offen the Reported flag */
				snymp->snymReported = 0;
			}
	/* BEGIN CSTYLED */
OLD_DEBUG(
if (debug_value)  {
	Fprint(stderr,
		"\t%s at address %x, ct=%ld, time=%f\n",
		slp->sl_name,
		thisaddr,
		slp->sl_count,
		slp->sl_time);
	totsnyms++;
}
);
	/* END CSTYLED */
			/* ok - bump count for snym, and note its Finding */
			snymp->howMany++;
			/* and update the summary statistics */
			snymp->tot_sl_count += slp->sl_count;
			snymp->tot_sl_time += slp->sl_time;
		}
		callTotal += slp->sl_count;
		lastaddr = thisaddr;
		lastWasSnym = thisIsSnym;
	/* BEGIN CSTYLED */
OLD_DEBUG(
if (debug_value) lastslp = slp;
);
	/* END CSTYLED */

	}
	/* BEGIN CSTYLED */
OLD_DEBUG(
if (debug_value)  {
	Fprint(stderr, "Total #series %d, #synonyms %d\n", totseries, totsnyms);
}
);
	/* END CSTYLED */
	}
	/*
	 * Most of the heavy work is done now.  Only minor stuff remains.
	 * The symbols are currently in address order and must be re-sorted
	 * if desired in a different order.  Report generating options
	 * include "-o" or "-x": Include symbol address, which causes
	 * another column
	 * in the output; and "-z": Include symbols in report even if zero
	 * time and call count.  Symbols not in profiling range are excluded
	 * in any case.  Following the main body of the report, the "-s"
	 * option causes certain additional information to be printed.
	 */

	OLD_DEBUG(if (debug_value) Fprint(stderr,
	    "Time unaccounted for: %.7G\n", t_tot - t0));

	if (sort)	/* If comparison routine given then use it. */
		qsort((char *)slist, (unsigned)n_syms,
		    sizeof (struct slist), sort);

	if (!(flags & F_NHEAD)) {
		if (flags & F_PADDR)
			Print("%s", atitle);	/* Title for addresses. */
		(void) puts(" %Time Seconds Cumsecs  #Calls   msec/call  Name");
	}
	t = 0.0;			/* Init cumulative time. */
	if (t_tot != 0.0)		/* Convert to percent. */
		t_tot = 100.0/t_tot;	/* Prevent divide-by-zero fault */
	n_nonzero = 0;	/* Number of symbols with nonzero time or # calls. */
	for (n = n_syms, slp = slist; --n >= 0; slp++) {
		long count;	 /* # Calls. */
		/* t0, time in seconds. */

		/* if a snym symbol, use summarized stats, else use indiv. */
		if ((snymp = getSnymEntry(slp->sl_addr)) != 0) {
			count = snymp->tot_sl_count;
			t0 = snymp->tot_sl_time;

		} else {
			count = slp->sl_count;
			t0 = slp->sl_time;
		}

		/* if a snym and already reported, skip this entry */
		if (snymp && snymp->snymReported)
			continue;
		/* Don't do entries with no action. */
		if (t0 == 0.0 && count == 0 && !(flags & F_ZSYMS))
			continue;
		if ((strcmp(slp->sl_name, "_mcount") == 0) ||
		    (strcmp(slp->sl_name, "mcount") == 0)) {
			count = callTotal;
		}

		/* count number of entries (i.e. symbols) printed */
		if (snymp)
			n_nonzero += snymp->howMany; /* add for each snym */
		else
			n_nonzero++;

		if (flags & F_PADDR) { /* Printing address of symbol? */
			/* LINTED: variable format */
			Print(aformat, slp->sl_addr);
		}
		t += t0;	/*  move here; compiler bug  !! */
		Print("%6.1f%8.2f%8.2f", t0 * t_tot, t0, t);
		fdigits = 0;
		if (count) {		/* Any calls recorded? */
		/* Get reasonable number of fractional digits to print. */
			fdigits = fprecision(count);
			Print("%8ld%#*.*f", count, fdigits+8, fdigits,
			    1000.0*t0/count);
			Print("%*s", 6-fdigits, " ");
		} else {
			Print("%22s", " ");
		}
		/*
		 * now print the name (or comma-seperate list of names,
		 * for synonym symbols).
		 */
		if (snymp) {
			printSnymNames(slp, snymp);	/* print it, then */
			snymp->snymReported = 1;	/* mark it Done */
		}
		else
			(void) puts(slp->sl_name);	/* print the one name */
	}
	if (flags & F_VERBOSE) {		/* Extra info? */
		Fprint(stderr, "%5d/%d call counts used\n", n_cc, head.nfns);
		Fprint(stderr, "%5d/%d symbols qualified", n_syms, symttl);
		if (n_nonzero < n_syms)
			Fprint(stderr,
			    ", %d had zero time and zero call-counts\n",
			    n_syms - n_nonzero);
		else
			(void) putc('\n', stderr);
		Fprint(stderr, "%#lx scale factor\n", (long)sf);
	}

	_symintClose(ldptr);
	} else {
		Fprint(stderr, "prof: no call counts captured\n");
	}
	return (0);
}
/* Return size of file associated with file descriptor fd. */

static off_t
fsize(int fd)
{
	struct stat sbuf;

	if (fstat(fd, &sbuf) < 0)  /* Status of open file. */
		Perror("stat");
	return (sbuf.st_size);			/* This is a long. */
}

/* Read symbol entry. Return TRUE if satisfies conditions. */

static int
readnl(int symindex)
{
	nl = ldptr->pf_symarr_p[symindex];

	/* BEGIN CSTYLED */
OLD_DEBUG(
	if (debug_value & 020) {
		Fprint(stderr,
			"`%-8.8s'\tst_info=%#4o, value=%#8.6o\n",
			ldptr->pf_symstr_p[nl.ps_sym.st_name],
			(unsigned char) nl.ps_sym.st_info,
			nl.ps_sym.st_value);
	}
);
	/* END CSTYLED */

	/*
	 * TXTSYM accepts global (and local, if "-g" given) T-type symbols.
	 * Only those in the profiling range are useful.
	 */
	return (nl.ps_sym.st_shndx < SHN_LORESERVE &&
	    TXTSYM(nl.ps_sym.st_shndx, nl.ps_sym.st_info) &&
	    (pc_l <= (char *)nl.ps_sym.st_value) &&
	    ((char *)nl.ps_sym.st_value < pc_h));
}
/*
 * Error-checking memory allocators -
 * Guarantees good return (else none at all).
 */

static void *
_prof_Malloc(int item_count, int item_size)
{
	void *p;

	if ((p = malloc((unsigned)item_count * (unsigned)item_size)) == NULL)  {
		(void) fprintf(stderr, "%s: Out of space\n", cmdname);
		exit(1);
	}
	return (p);
}



/*
 *	Given the quotient Q = N/D, where entier(N) == N and D > 0, an
 *	approximation of the "best" number of fractional digits to use
 *	in printing Q is f = entier(log10(D)), which is crudely produced
 *	by the following routine.
 */

static int
fprecision(long count)
{
	return (count < 10 ? 0 : count < 100 ? 1 : count < 1000 ? 2 :
	    count < 10000 ? 3 : 4);
}

/*
 *	Return pointer to base name(name less path) of string s.
 *	Handles case of superfluous trailing '/'s, and unlikely
 *	case of s == "/".
 */

static char *
basename(char *s)
{
	char *p;

	p = &s[strlen(s)];			/* End (+1) of string. */
	while (p > s && *--p == '/')		/* Trim trailing '/'s. */
		*p = '\0';
	p++;					/* New end (+1) of string. */
	while (p > s && *--p != '/')		/* Break backward on '/'. */
		;
	if (*p == '/')		/* If found '/', point to 1st following. */
		p++;
	if (*p == '\0')
		p = "/";			/* If NULL, must be "/". (?) */
	return (p);
}
/* Here if unexpected read problem. */

static void
eofon(FILE *iop, char *fn)
{
	if (ferror(iop))		/* Real error? */
		Perror(fn);		/* Yes. */
	Fprint(stderr, "%s: %s: Premature EOF\n", cmdname, fn);
	exit(1);
}

/*
 * Version of perror() that prints cmdname first.
 * Print system error message & exit.
 */

static void
Perror(char *s)
{
	int err = errno;	/* Save current errno in case */

	Fprint(stderr, "%s: ", cmdname);
	errno = err;			/* Put real error back. */
	perror(s);			/* Print message. */
	_symintClose(ldptr);		/* cleanup symbol information */
	exit(1);			/* Exit w/nonzero status. */
}

/* Here for things that "Should Never Happen". */

static void
snh(void)
{
	Fprint(stderr, "%s: Internal error\n", cmdname);
	(void) abort();
}

/*
 *	Various comparison routines for qsort. Uses:
 *
 *	c_ccaddr	- Compare fnpc fields of cnt structs to put
 *				call counters in increasing address order.
 *	c_sladdr	- Sort slist structures on increasing address.
 *	c_time		-  "	 "	  "      " decreasing time.
 *	c_ncalls	-  "	 "	  "      " decreasing # calls.
 *	c_name		-  "	 "	  "      " increasing symbol name
 */

#define	CMP2(v1, v2)	((v1) < (v2) ? -1 : (v1) == (v2) ? 0 : 1)
#define	CMP1(v)		CMP2(v, 0)

int
c_ccaddr(const void *arg1, const void *arg2)
{
	struct cnt *p1 = (struct cnt *)arg1;
	struct cnt *p2 = (struct cnt *)arg2;

	return (CMP2(p1->fnpc, p2->fnpc));
}

int
c_sladdr(const void *arg1, const void *arg2)
{
	struct slist *p1 = (struct slist *)arg1;
	struct slist *p2 = (struct slist *)arg2;

	return (CMP2(p1->sl_addr, p2->sl_addr));
}

int
c_time(const void *arg1, const void *arg2)
{
	struct slist *p1 = (struct slist *)arg1;
	struct slist *p2 = (struct slist *)arg2;
	float dtime = p2->sl_time - p1->sl_time; /* Decreasing time. */

	return (CMP1(dtime));
}

int
c_ncalls(const void *arg1, const void *arg2)
{
	struct slist *p1 = (struct slist *)arg1;
	struct slist *p2 = (struct slist *)arg2;
	int diff = p2->sl_count - p1->sl_count;
		/* Decreasing # calls. */
	return (CMP1(diff));
}

int
c_name(const void *arg1, const void *arg2)
{
	struct slist *p1 = (struct slist *)arg1;
	struct slist *p2 = (struct slist *)arg2;
	int diff;

		/* flex names has variable length strings for names */
	diff = strcmp(p1->sl_name, p2->sl_name);
	return (CMP1(diff));
}

#define	STRSPACE 2400		/* guess at amount of string space */

char *format_buf;
#define	FORMAT_BUF	"%s\n\t\t\t\t\t    [%s]"

static char *
demangled_name(char *s)
{
	const char *name;
	size_t	len;

	name = conv_demangle_name(s);

	if (strcmp(name, s) == 0)
		return (s);

	if (format_buf != NULL)
		free(format_buf);

	len = strlen(name) + strlen(FORMAT_BUF) + strlen(s) + 1;
	format_buf = malloc(len);
	if (format_buf == NULL)
		return (s);
	(void) snprintf(format_buf, len, FORMAT_BUF, name, s);
	return (format_buf);
}

/* getname - get the name of a symbol in a permanent fashion */
static char *
getname(PROF_FILE *ldpter, PROF_SYMBOL symbol)
{
	static char *strtable = NULL;	/* space for names */
	static int sp_used = 0;		/* space used so far */
	static int size = 0;		/* size of string table */
	char *name;			/* name to store */
	int lth;			/* space needed for name */
	int get;			/* amount of space to get */

	name = elf_strptr(ldpter->pf_elf_p, ldpter->pf_symstr_ndx,
	    symbol.ps_sym.st_name);
	if (name == NULL)
		return ("<<bad symbol name>>");

	if (Cflag)
		name = demangled_name(name);

	lth = strlen(name) + 1;
	if ((sp_used + lth) > size)  {	 /* if need more space */
		/* just in case very long name */
		get = lth > STRSPACE ? lth : STRSPACE;
		strtable = _prof_Malloc(1, get);
		size = get;
		sp_used = 0;
	}
	(void) strcpy(&(strtable[sp_used]), name);
	name = &(strtable[sp_used]);
	sp_used += lth;
	return (name);
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: %s [-ChsVz] [-a | c | n | t]  [-o  |  x]   [-g  |  l]\n"
	    "\t[-m mdata] [prog]\n",
	    cmdname);
	exit(1);
}
