/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Compress - data compression program
 */
#define	min(a, b)	((a > b) ? b : a)

/*
 * machine variants which require cc -Dmachine:  pdp11, z8000, pcxt
 */

/*
 * Set USERMEM to the maximum amount of physical user memory available
 * in bytes.  USERMEM is used to determine the maximum BITS that can be used
 * for compression.
 *
 * SACREDMEM is the amount of physical memory saved for others; compress
 * will hog the rest.
 */
#ifndef SACREDMEM
#define	SACREDMEM	0
#endif

#ifndef USERMEM
#define	USERMEM 	450000	/* default user memory */
#endif

#ifdef USERMEM
#if USERMEM >= (433484+SACREDMEM)
#define	PBITS	16
#else
#if USERMEM >= (229600+SACREDMEM)
#define	PBITS	15
#else
#if USERMEM >= (127536+SACREDMEM)
#define	PBITS	14
#else
#if USERMEM >= (73464+SACREDMEM)
#define	PBITS	13
#else
#define	PBITS	12
#endif
#endif
#endif
#endif
#undef USERMEM
#endif /* USERMEM */

#ifdef PBITS		/* Preferred BITS for this memory size */
#ifndef BITS
#define	BITS PBITS
#endif /* BITS */
#endif /* PBITS */

#if BITS == 16
#define	HSIZE	69001		/* 95% occupancy */
#endif
#if BITS == 15
#define	HSIZE	35023		/* 94% occupancy */
#endif
#if BITS == 14
#define	HSIZE	18013		/* 91% occupancy */
#endif
#if BITS == 13
#define	HSIZE	9001		/* 91% occupancy */
#endif
#if BITS <= 12
#define	HSIZE	5003		/* 80% occupancy */
#endif

#define	OUTSTACKSIZE	(2<<BITS)

/*
 * a code_int must be able to hold 2**BITS values of type int, and also -1
 */
#if BITS > 15
typedef long int	code_int;
#else
typedef int		code_int;
#endif

typedef long int	count_int;
typedef long long	count_long;

typedef	unsigned char	char_type;

static char_type magic_header[] = { "\037\235" }; /* 1F 9D */

/* Defines for third byte of header */
#define	BIT_MASK	0x1f
#define	BLOCK_MASK	0x80
/*
 * Masks 0x40 and 0x20 are free.  I think 0x20 should mean that there is
 * a fourth header byte(for expansion).
 */
#define	INIT_BITS 9			/* initial number of bits/code */

/*
 * compress.c - File compression ala IEEE Computer, June 1984.
 */
static char rcs_ident[] =
	"$Header: compress.c,v 4.0 85/07/30 12:50:00 joe Release $";

#include <ctype.h>
#include <signal.h>
#include <sys/param.h>
#include <locale.h>
#include <langinfo.h>
#include <sys/acl.h>
#include <utime.h>
#include <libgen.h>
#include <setjmp.h>
#include <aclutils.h>
#include <libcmdutils.h>
#include "getresponse.h"


static int n_bits;			/* number of bits/code */
static int maxbits = BITS;	/* user settable max # bits/code */
static code_int maxcode;	/* maximum code, given n_bits */
			/* should NEVER generate this code */
static code_int maxmaxcode = 1 << BITS;
#define	MAXCODE(n_bits)	((1 << (n_bits)) - 1)

static count_int htab [OUTSTACKSIZE];
static unsigned short codetab [OUTSTACKSIZE];

#define	htabof(i)	htab[i]
#define	codetabof(i)	codetab[i]
static code_int hsize = HSIZE; /* for dynamic table sizing */
static off_t	fsize;	/* file size of input file */

/*
 * To save much memory, we overlay the table used by compress() with those
 * used by decompress().  The tab_prefix table is the same size and type
 * as the codetab.  The tab_suffix table needs 2**BITS characters.  We
 * get this from the beginning of htab.  The output stack uses the rest
 * of htab, and contains characters.  There is plenty of room for any
 * possible stack (stack used to be 8000 characters).
 */

#define	tab_prefixof(i)		codetabof(i)
#define	tab_suffixof(i)		((char_type *)(htab))[i]
#define	de_stack		((char_type *)&tab_suffixof(1<<BITS))
#define	stack_max		((char_type *)&tab_suffixof(OUTSTACKSIZE))

static code_int free_ent = 0; /* first unused entry */
static int newline_needed = 0;
static int didnt_shrink = 0;
static int perm_stat = 0;	/* permanent status */

static code_int getcode();

	/* Use a 3-byte magic number header, unless old file */
static int nomagic = 0;
	/* Write output on stdout, suppress messages */
static int zcat_flg = 0;	/* use stdout on all files */
static int zcat_cmd = 0;	/* zcat cmd */
static int use_stdout = 0;	/* set for each file processed */
	/* Don't unlink output file on interrupt */
static int precious = 1;
static int quiet = 1;	/* don't tell me about compression */

/*
 * block compression parameters -- after all codes are used up,
 * and compression rate changes, start over.
 */
static int block_compress = BLOCK_MASK;
static int clear_flg = 0;
static long int ratio = 0;
#define	CHECK_GAP 10000	/* ratio check interval */
static count_long checkpoint = CHECK_GAP;
/*
 * the next two codes should not be changed lightly, as they must not
 * lie within the contiguous general code space.
 */
#define	FIRST	257	/* first free entry */
#define	CLEAR	256	/* table clear output code */

static int force = 0;
static char ofname [MAXPATHLEN];

static int Vflg = 0;
static int vflg = 0;
static int qflg = 0;
static int bflg = 0;
static int Fflg = 0;
static int dflg = 0;
static int cflg = 0;
static int Cflg = 0;

#ifdef DEBUG
int verbose = 0;
int debug = 0;
#endif /* DEBUG */

static void (*oldint)();
static int bgnd_flag;

static int do_decomp = 0;

static char *progname;
static char *optstr;
/*
 * Fix lint errors
 */

static char *local_basename(char *);

static int  addDotZ(char *, size_t);

static void Usage(void);
static void cl_block(count_long);
static void cl_hash(count_int);
static void compress(void);
static void copystat(char *, struct stat *, char *);
static void decompress(void);
static void ioerror(void);
static void onintr();
static void oops();
static void output(code_int);
static void prratio(FILE *, count_long, count_long);
static void version(void);

#ifdef DEBUG
static int in_stack(int, int);
static void dump_tab(void);
static void printcodes(void);
#endif

/* For error-handling */

static jmp_buf env;

/* For input and ouput */

static FILE *inp;		/* the current input file */
static FILE *infile;		/* disk-based input stream */
static FILE *outp;		/* current output file */
static FILE *outfile;		/* disk-based output stream */

/* For output() */

static char buf[BITS];

static char_type lmask[9] =
	{0xff, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80, 0x00};
static char_type rmask[9] =
	{0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff};

/* For compress () */

static int offset;
static count_long bytes_out;	/* length of compressed output */
	/* # of codes output (for debugging) */

/* For dump_tab() */

#define	STACK_SIZE	15000
#ifdef DEBUG
code_int sorttab[1<<BITS];	/* sorted pointers into htab */
#endif

/* Extended system attribute support */

static int saflg = 0;

/*
 * *************************************************************
 * TAG( main )
 *
 * Algorithm from "A Technique for High Performance Data Compression",
 * Terry A. Welch, IEEE Computer Vol 17, No 6 (June 1984), pp 8-19.
 *
 * Usage: compress [-dfvc/] [-b bits] [file ...]
 * Inputs:
 *	-d:	    If given, decompression is done instead.
 *
 *	-c:	    Write output on stdout, don't remove original.
 *
 *	-b:	    Parameter limits the max number of bits/code.
 *
 *	-f:	    Forces output file to be generated, even if one already
 *		    exists, and even if no space is saved by compressing.
 *		    If -f is not used, the user will be prompted if stdin is
 *		    a tty, otherwise, the output file will not be overwritten.
 *
 *	-/	    Copies extended attributes and extended system attributes.
 *
 *  -v:	    Write compression statistics
 *
 * 	file ...:   Files to be compressed.  If none specified, stdin
 *		    is used.
 * Outputs:
 *	file.Z:	    Compressed form of file with same mode, owner, and utimes
 * 	or stdout   (if stdin used as input)
 *
 * Assumptions:
 * When filenames are given, replaces with the compressed version
 * (.Z suffix) only if the file decreases in size.
 * Algorithm:
 * Modified Lempel-Ziv method (LZW).  Basically finds common
 * substrings and replaces them with a variable size code.  This is
 * deterministic, and can be done on the fly.  Thus, the decompression
 * procedure needs no input table, but tracks the way the table was built.
 */

int
main(int argc, char *argv[])
{
	int overwrite = 0;	/* Do not overwrite unless given -f flag */
	char tempname[MAXPATHLEN];
	char line[LINE_MAX];
	char **filelist, **fileptr;
	char *cp;
	struct stat statbuf;
	struct stat ostatbuf;
	int ch;				/* XCU4 */
	char	*p;
	extern int optind, optopt;
	extern char *optarg;
	int dash_count = 0;		/* times "-" is on cmdline */

	/* XCU4 changes */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (init_yes() < 0) {
		(void) fprintf(stderr, gettext(ERR_MSG_INIT_YES),
		    strerror(errno));
		exit(1);
	}

	/* This bg check only works for sh. */
	if ((oldint = signal(SIGINT, SIG_IGN)) != SIG_IGN) {
		(void) signal(SIGINT, onintr);
		(void) signal(SIGSEGV, oops);
	}
	bgnd_flag = oldint != SIG_DFL;

	/* Allocate room for argv + "-" (if stdin needs to be added) */

	filelist = fileptr = (char **)(malloc((argc + 1) * sizeof (*argv)));
	*filelist = NULL;

	if ((cp = rindex(argv[0], '/')) != 0) {
		cp++;
	} else {
		cp = argv[0];
	}

	if (strcmp(cp, "uncompress") == 0) {
		do_decomp = 1;
	} else if (strcmp(cp, "zcat") == 0) {
		do_decomp = 1;
		zcat_cmd = zcat_flg = 1;
	}

	progname = local_basename(argv[0]);

	/*
	 * Argument Processing
	 * All flags are optional.
	 * -D = > debug
	 * -V = > print Version; debug verbose
	 * -d = > do_decomp
	 * -v = > unquiet
	 * -f = > force overwrite of output file
	 * -n = > no header: useful to uncompress old files
	 * -b	  maxbits => maxbits.  If -b is specified,
	 *	  then maxbits MUST be given also.
	 * -c = > cat all output to stdout
	 * -C = > generate output compatible with compress 2.0.
	 * if a string is left, must be an input filename.
	 */
#ifdef DEBUG
	optstr = "b:cCdDfFnqvV/";
#else
	optstr = "b:cCdfFnqvV/";
#endif

	while ((ch = getopt(argc, argv, optstr)) != EOF) {
		/* Process all flags in this arg */
		switch (ch) {
#ifdef DEBUG
			case 'D':
				debug = 1;
				break;
			case 'V':
				verbose = 1;
				version();
				break;
#else
			case 'V':
				version();
				Vflg++;
				break;
#endif /* DEBUG */
			case 'v':
				quiet = 0;
				vflg++;
				break;
			case 'd':
				do_decomp = 1;
				dflg++;
				break;
			case 'f':
			case 'F':
				Fflg++;
				overwrite = 1;
				force = 1;
				break;
			case 'n':
				nomagic = 1;
				break;
			case 'C':
				Cflg++;
				block_compress = 0;
				break;
			case 'b':
				bflg++;
				p = optarg;
				if (!p) {
					(void) fprintf(stderr, gettext(
					    "Missing maxbits\n"));
					Usage();
					exit(1);
				}
				maxbits = strtoul(optarg, &p, 10);
				if (*p) {
					(void) fprintf(stderr, gettext(
					    "Missing maxbits\n"));
					Usage();
					exit(1);
				}
				break;

			case 'c':
				cflg++;
				zcat_flg = 1;
				break;
			case 'q':
				qflg++;
				quiet = 1;
				break;
			case '/':
				saflg++;
				break;
			default:
				(void) fprintf(stderr, gettext(
				    "Unknown flag: '%c'\n"), optopt);
				Usage();
				exit(1);
		}
	} /* while */

	/*
	 * Validate zcat syntax
	 */

	if (zcat_cmd && (Fflg | Cflg | cflg |
	    bflg | qflg | dflg | nomagic)) {
		(void) fprintf(stderr, gettext(
		    "Invalid Option\n"));
		Usage();
		exit(1);
	}

	/*
	 * Process the file list
	 */

	for (; optind < argc; optind++) {
		if (strcmp(argv[optind], "-") == 0) {
			dash_count++;
		}

		*fileptr++ = argv[optind];	/* Build input file list */
		*fileptr = NULL;
	}

	if (dash_count > 1) {
		(void) fprintf(stderr,
		    gettext("%s may only appear once in the file"
		    " list\n"), "\"-\"");
		exit(1);
	}

	if (fileptr - filelist == 0) {
		*fileptr++ = "-";
		*fileptr = NULL;
	}

	if (fileptr - filelist > 1 && cflg && !do_decomp) {
		(void) fprintf(stderr,
		    gettext("compress: only one file may be compressed"
		    " to stdout\n"));
		exit(1);
	}

	if (maxbits < INIT_BITS)
		maxbits = INIT_BITS;
	if (maxbits > BITS)
		maxbits = BITS;
	maxmaxcode = 1 << maxbits;

	/* Need to open something to close with freopen later */

	if ((infile = fopen("/dev/null", "r")) == NULL) {
		(void) fprintf(stderr, gettext("Error opening /dev/null for "
		    "input\n"));
		exit(1);
	}

	if ((outfile = fopen("/dev/null", "w")) == NULL) {
		(void) fprintf(stderr, gettext("Error opening /dev/null for "
		    "output\n"));
		exit(1);
	}

	for (fileptr = filelist; *fileptr; fileptr++) {
		int jmpval = 0;
		didnt_shrink = 0;
		newline_needed = 0;

		if (do_decomp) {
			/* DECOMPRESSION */

			if (strcmp(*fileptr, "-") == 0) {
				/* process stdin */
				inp = stdin;
				outp = stdout;
				use_stdout = 1;
				*fileptr = "stdin"; /* for error messages */
			} else {
				/* process the named file */

				inp = infile;
				outp = outfile;
				use_stdout = 0;

				if (zcat_flg) {
					use_stdout = 1;
					outp = stdout;
				}

				/* Check for .Z suffix */

				if (strcmp(*fileptr +
				    strlen(*fileptr) - 2, ".Z") != 0) {
					/* No .Z: tack one on */

					if (strlcpy(tempname, *fileptr,
					    sizeof (tempname)) >=
					    sizeof (tempname)) {
						(void) fprintf(stderr,
						    gettext("%s: filename "
						    "too long\n"),
						    *fileptr);
						perm_stat = 1;
						continue;
					}

					if (addDotZ(tempname,
					    sizeof (tempname)) < 0) {
						perm_stat = 1;
						continue;
					}

					*fileptr = tempname;
				}

				/* Open input file */

				if (stat(*fileptr, &statbuf) < 0) {
					perror(*fileptr);
					perm_stat = 1;
					continue;
				}

				if ((freopen(*fileptr, "r", inp)) == NULL) {
					perror(*fileptr);
					perm_stat = 1;
					continue;
				}
			}

			/* Check the magic number */

			if (nomagic == 0) {
				if ((getc(inp) !=
				    (magic_header[0] & 0xFF)) ||
				    (getc(inp) !=
				    (magic_header[1] & 0xFF))) {
					(void) fprintf(stderr, gettext(
					    "%s: not in compressed "
					    "format\n"),
					    *fileptr);
					perm_stat = 1;
					continue;
				}

				/* set -b from file */
				if ((maxbits = getc(inp)) == EOF &&
				    ferror(inp)) {
					perror(*fileptr);
					perm_stat = 1;
					continue;
				}

				block_compress = maxbits & BLOCK_MASK;
				maxbits &= BIT_MASK;
				maxmaxcode = 1 << maxbits;

				if (maxbits > BITS) {
					(void) fprintf(stderr,
					    gettext("%s: compressed "
					    "with %d bits, "
					    "can only handle"
					    " %d bits\n"),
					    *fileptr, maxbits, BITS);
					perm_stat = 1;
					continue;
				}
			}

			if (!use_stdout) {
				/* Generate output filename */

				if (strlcpy(ofname, *fileptr,
				    sizeof (ofname)) >=
				    sizeof (ofname)) {
					(void) fprintf(stderr,
					    gettext("%s: filename "
					    "too long\n"),
					    *fileptr);
					perm_stat = 1;
					continue;
				}

				/* Strip off .Z */

				ofname[strlen(*fileptr) - 2] = '\0';
			}
		} else {
			/* COMPRESSION */

			if (strcmp(*fileptr, "-") == 0) {
				/* process stdin */
				inp = stdin;
				outp = stdout;
				use_stdout = 1;
				*fileptr = "stdin"; /* for error messages */

				/* Use the largest possible hash table */
				hsize =  HSIZE;
			} else {
				/* process the named file */

				inp = infile;
				outp = outfile;
				use_stdout = 0;

				if (zcat_flg) {
					use_stdout = 1;
					outp = stdout;
				}

				if (strcmp(*fileptr +
				    strlen(*fileptr) - 2, ".Z") == 0) {
					(void) fprintf(stderr, gettext(
					    "%s: already has .Z "
					    "suffix -- no change\n"),
					    *fileptr);
					perm_stat = 1;
					continue;
				}
				/* Open input file */

				if (stat(*fileptr, &statbuf) < 0) {
					perror(*fileptr);
					perm_stat = 1;
					continue;
				}

				if ((freopen(*fileptr, "r", inp)) == NULL) {
					perror(*fileptr);
					perm_stat = 1;
					continue;
				}

				fsize = (off_t)statbuf.st_size;

				/*
				 * tune hash table size for small
				 * files -- ad hoc,
				 * but the sizes match earlier #defines, which
				 * serve as upper bounds on the number of
				 * output codes.
				 */
				hsize = HSIZE;
				if (fsize < (1 << 12))
					hsize = min(5003, HSIZE);
				else if (fsize < (1 << 13))
					hsize = min(9001, HSIZE);
				else if (fsize < (1 << 14))
					hsize = min(18013, HSIZE);
				else if (fsize < (1 << 15))
					hsize = min(35023, HSIZE);
				else if (fsize < 47000)
					hsize = min(50021, HSIZE);

				if (!use_stdout) {
					/* Generate output filename */

					if (strlcpy(ofname, *fileptr,
					    sizeof (ofname)) >=
					    sizeof (ofname)) {
						(void) fprintf(stderr,
						    gettext("%s: filename "
						    "too long\n"),
						    *fileptr);
						perm_stat = 1;
						continue;
					}

					if (addDotZ(ofname,
					    sizeof (ofname)) < 0) {
						perm_stat = 1;
						continue;
					}
				}
			}
		}	/* if (do_decomp) */

		/* Check for overwrite of existing file */

		if (!overwrite && !use_stdout) {
			if (stat(ofname, &ostatbuf) == 0) {
				(void) fprintf(stderr, gettext(
				    "%s already exists;"), ofname);
				if (bgnd_flag == 0 && isatty(2)) {
					int cin;

					(void) fprintf(stderr, gettext(
					    " do you wish to overwr"
					    "ite %s (%s or %s)? "),
					    ofname, yesstr, nostr);
					(void) fflush(stderr);
					for (cin = 0; cin < LINE_MAX; cin++)
						line[cin] = 0;
					(void) read(2, line, LINE_MAX);

					if (yes_check(line) == 0) {
						(void) fprintf(stderr,
						    gettext(
						    "\tnot overwri"
						    "tten\n"));
						continue;
					}
				} else {
					/*
					 * XPG4: Assertion 1009
					 * Standard input is not
					 * terminal, and no '-f',
					 * and file exists.
					 */

					(void) fprintf(stderr, gettext(
					    "%s: File exists, -f not"
					    " specified, and ru"
					    "nning in the backgro"
					    "und.\n"), *fileptr);
					perm_stat = 1;
					continue;
				}
			}
		}
		if (!use_stdout) {
			if ((pathconf(ofname, _PC_XATTR_EXISTS) == 1) ||
			    (saflg && sysattr_support(ofname,
			    _PC_SATTR_EXISTS) == 1)) {
				(void) unlink(ofname);
			}
			/* Open output file */
			if (freopen(ofname, "w", outp) == NULL) {
				perror(ofname);
				perm_stat = 1;
				continue;
			}
			precious = 0;
			if (!quiet) {
				(void) fprintf(stderr, "%s: ",
				    *fileptr);
				newline_needed = 1;
			}
		} else if (!quiet && !do_decomp) {
			(void) fprintf(stderr, "%s: ",
			    *fileptr);
			newline_needed = 1;
		}

		/* Actually do the compression/decompression */

		if ((jmpval = setjmp(env)) == 0) {
			/* We'll see how things go */
#ifndef DEBUG
			if (do_decomp == 0)  {
				compress();
			} else {
				decompress();
			}
#else
			if (do_decomp == 0)  {
				compress();
			} else if (debug == 0)  {
				decompress();
			} else {
				printcodes();
			}

			if (verbose) {
				dump_tab();
			}
#endif
		} else {
			/*
			 * Things went badly - clean up and go on.
			 * jmpval's values break down as follows:
			 *   1 == message determined by ferror() values.
			 *   2 == input problem message needed.
			 *   3 == output problem message needed.
			 */

			if (ferror(inp) || jmpval == 2) {
				if (do_decomp) {
					(void) fprintf(stderr, gettext(
					    "uncompress: %s: corrupt"
					    " input\n"), *fileptr);
				} else {
					perror(*fileptr);
				}
			}

			if (ferror(outp) || jmpval == 3) {
				/* handle output errors */

				if (use_stdout) {
					perror("");
				} else {
					perror(ofname);
				}
			}

			if (ofname[0] != '\0') {
				if (unlink(ofname) < 0)  {
					perror(ofname);
				}

				ofname[0] = '\0';
			}

			perm_stat = 1;
			continue;
		}

		/* Things went well */

		if (!use_stdout) {
				/* Copy stats */
			copystat(*fileptr, &statbuf, ofname);
			precious = 1;
			if (newline_needed) {
				(void) putc('\n', stderr);
			}
			/*
			 * Print the info. for unchanged file
			 * when no -v
			 */

			if (didnt_shrink) {
				if (!force && perm_stat == 0) {
					if (quiet) {
						(void) fprintf(stderr, gettext(
						    "%s: -- file "
						    "unchanged\n"),
						    *fileptr);
					}

					perm_stat = 2;
				}
			}
		} else {
			if (didnt_shrink && !force && perm_stat == 0) {
				perm_stat = 2;
			}

			if (newline_needed) {
				(void) fprintf(stderr, "\n");
			}
		}
	}	/* for */

	return (perm_stat);
}

static void
cinterr(int hshift)
{
	/* we have exceeded the hash table */
	(void) fprintf(stderr,
	    "internal error: hashtable exceeded - hsize = %ld\n", hsize);
	(void) fprintf(stderr, "hshift = %d, %d\n", hshift, (1 << hshift) -1);
	(void) fprintf(stderr, "maxbits = %d\n", maxbits);
	(void) fprintf(stderr, "n_bits = %d\n", n_bits);
	(void) fprintf(stderr, "maxcode = %ld\n", maxcode);
	longjmp(env, 1);
}

static code_int
adjusti(code_int i, code_int hsize_reg)
{
	while (i < 0) {
		i += hsize_reg;
	}

	while (i >= hsize_reg) {
		i -= hsize_reg;
	}
	return (i);
}

/*
 * compress inp to outp
 *
 * Algorithm:  use open addressing double hashing(no chaining) on the
 * prefix code / next character combination.  We do a variant of Knuth's
 * algorithm D (vol. 3, sec. 6.4) along with G. Knott's relatively-prime
 * secondary probe.  Here, the modular division first probe is gives way
 * to a faster exclusive-or manipulation.  Also do block compression with
 * an adaptive reset, whereby the code table is cleared when the compression
 * ratio decreases, but after the table fills.  The variable-length output
 * codes are re-sized at this point, and a special CLEAR code is generated
 * for the decompressor.  Late addition:  construct the table according to
 * file size for noticeable speed improvement on small files.  Please direct
 * questions about this implementation to ames!jaw.
 */

static void
compress()
{
	long fcode;
	code_int i = 0;
	int c;
	code_int ent;
	int disp;
	code_int hsize_reg;
	int hshift;
	int probecnt;
	count_long in_count;
	uint32_t inchi, inclo;
	int maxbits_reg;
	FILE *fin = inp;
#ifdef DEBUG
	count_long out_count = 0;
#endif

	if (nomagic == 0) {
		if ((putc(magic_header[0], outp) == EOF ||
		    putc(magic_header[1], outp) == EOF ||
		    putc((char)(maxbits | block_compress),
		    outp) == EOF) &&
		    ferror(outp)) {
			ioerror();
		}
	}

	offset = 0;
	bytes_out = 3;		/* includes 3-byte header mojo */
	clear_flg = 0;
	ratio = 0;
	in_count = 1;
	inchi = 0;
	inclo = 1;
	checkpoint = CHECK_GAP;
	maxcode = MAXCODE(n_bits = INIT_BITS);
	free_ent = ((block_compress) ? FIRST : 256);

	if ((ent = getc(fin)) == EOF && ferror(fin)) {
		ioerror();
	}

	hshift = 0;

	for (fcode = (long)hsize;  fcode < 65536L; fcode *= 2L)
		hshift++;

	hshift = 8 - hshift;		/* set hash code range bound */

	hsize_reg = hsize;
	maxbits_reg = maxbits;

	cl_hash((count_int) hsize_reg);		/* clear hash table */

	while ((c = getc(fin)) != EOF) {
		if (++inclo == 0)
			inchi++;
		fcode = (long)(((long)c << maxbits_reg) + ent);
		i = ((c << hshift) ^ ent);	/* xor hashing */

		if ((unsigned int)i >= hsize_reg)
			i = adjusti(i, hsize_reg);

		if (htabof(i) == fcode) {
			ent = codetabof(i);
			continue;
		} else if ((long)htabof(i) < 0) {
			/* empty slot */
			goto nomatch;
		}

		/* secondary hash (after G. Knott) */
		disp = hsize_reg - i;

		if (i == 0) {
			disp = 1;
		}

		probecnt = 0;
	probe:
		if (++probecnt > hsize_reg)
			cinterr(hshift);

		if ((i -= disp) < 0) {
			while (i < 0)
				i += hsize_reg;
		}

		if (htabof(i) == fcode) {
			ent = codetabof(i);
			continue;
		}

		if ((long)htabof(i) > 0) {
			goto probe;
		}
	nomatch:
		output((code_int) ent);
#ifdef DEBUG
		out_count++;
#endif
		ent = c;
		if (free_ent < maxmaxcode) {
			codetabof(i) = free_ent++;
			/* code -> hashtable */
			htabof(i) = fcode;
		} else {
			in_count = ((long long)inchi<<32|inclo);
			if ((count_long)in_count >=
			    (count_long)checkpoint && block_compress) {
				cl_block(in_count);
			}
		}
	}

	in_count = ((long long)inchi<<32|inclo);

	if (ferror(fin) != 0) {
		ioerror();
	}

	/*
	 * Put out the final code.
	 */
	output((code_int)ent);
#ifdef DEBUG
	out_count++;
#endif

	output((code_int)-1);

	/*
	 * Print out stats on stderr
	 */
	if (!quiet) {
#ifdef DEBUG
		(void) fprintf(stderr,
		    "%lld chars in, %lld codes (%lld bytes) out, "
		    "compression factor: ",
		    (count_long)in_count, (count_long)out_count,
		    (count_long) bytes_out);
		prratio(stderr, (count_long)in_count,
		    (count_long)bytes_out);
		(void) fprintf(stderr, "\n");
		(void) fprintf(stderr, "\tCompression as in compact: ");
		prratio(stderr,
		    (count_long)in_count-(count_long)bytes_out,
		    (count_long)in_count);
		(void) fprintf(stderr, "\n");
		(void) fprintf(stderr,
		    "\tLargest code (of last block) was %d"
		    " (%d bits)\n",
		    free_ent - 1, n_bits);
#else /* !DEBUG */
		(void) fprintf(stderr, gettext("Compression: "));
		prratio(stderr,
		    (count_long)in_count-(count_long)bytes_out,
		    (count_long)in_count);
#endif /* DEBUG */
	}
	/* report if no savings */
	if ((count_long)bytes_out > (count_long)in_count) {
		didnt_shrink = 1;
	}
}

/*
 * **************************************************************
 * TAG(output)
 *
 * Output the given code.
 * Inputs:
 * 	code:	A n_bits-bit integer.  If == -1, then EOF.  This assumes
 *		that n_bits = < (long)wordsize - 1.
 * Outputs:
 * 	Outputs code to the file.
 * Assumptions:
 *	Chars are 8 bits long.
 * Algorithm:
 * 	Maintain a BITS character long buffer(so that 8 codes will
 * fit in it exactly).  Use the VAX insv instruction to insert each
 * code in turn.  When the buffer fills up empty it and start over.
 */

static void
output(code_int code)
{
#ifdef DEBUG
	static int col = 0;
#endif /* DEBUG */

	int r_off = offset, bits = n_bits;
	char *bp = buf;

#ifdef DEBUG
	if (verbose)
		(void) fprintf(stderr, "%5d%c", code,
		    (col += 6) >= 74 ? (col = 0, '\n') : ' ');
#endif /* DEBUG */
	if (code >= 0) {
		/*
		 * byte/bit numbering on the VAX is simulated
		 * by the following code
		 */
		/*
		 * Get to the first byte.
		 */
		bp += (r_off >> 3);
		r_off &= 7;
		/*
		 * Since code is always >= 8 bits, only need to mask the first
		 * hunk on the left.
		 */
		*bp = (*bp & rmask[r_off]) | (code << r_off) & lmask[r_off];
		bp++;
		bits -= (8 - r_off);
		code >>= 8 - r_off;
		/*
		 * Get any 8 bit parts in the middle (<=1 for up to 16
		 * bits).
		 */
		if (bits >= 8) {
			*bp++ = code;
			code >>= 8;
			bits -= 8;
		}
		/* Last bits. */
		if (bits)
			*bp = code;
		offset += n_bits;
		if (offset == (n_bits << 3)) {
			bp = buf;
			bits = n_bits;
			bytes_out += bits;
			do {
				if (putc(*bp, outp) == EOF &&
				    ferror(outp)) {
					ioerror();
				}
				bp++;
			} while (--bits);
			offset = 0;
		}

		/*
		 * If the next entry is going to be too big for the code size,
		 * then increase it, if possible.
		 */
		if (free_ent > maxcode || (clear_flg > 0)) {
			/*
			 * Write the whole buffer, because the input
			 * side won't discover the size increase until
			 * after it has read it.
			 */
			if (offset > 0) {
				if (fwrite(buf, 1, n_bits, outp) != n_bits) {
					longjmp(env, 3);
				}
				bytes_out += n_bits;
			}
			offset = 0;

			if (clear_flg) {
				maxcode = MAXCODE(n_bits = INIT_BITS);
				clear_flg = 0;
			} else {
				n_bits++;
				if (n_bits == maxbits)
					maxcode = maxmaxcode;
				else
					maxcode = MAXCODE(n_bits);
			}
#ifdef DEBUG
			if (debug) {
				(void) fprintf(stderr,
				    "\nChange to %d bits\n", n_bits);
				col = 0;
			}
#endif /* DEBUG */
		}
	} else {
		/*
		 * At EOF, write the rest of the buffer.
		 */
		if (offset > 0) {
			if (fwrite(buf, 1, (offset + 7) / 8, outp) == 0 &&
			    ferror(outp)) {
				ioerror();
			}
			bytes_out += (offset + 7) / 8;
		}
		offset = 0;
		(void) fflush(outp);
#ifdef DEBUG
		if (verbose)
			(void) fprintf(stderr, "\n");
#endif /* DEBUG */
		if (ferror(outp))
			ioerror();
	}
}

/*
 * Decompress inp to outp.  This routine adapts to the codes in the
 * file building the "string" table on-the-fly; requiring no table to
 * be stored in the compressed file.  The tables used herein are shared
 * with those of the compress() routine.  See the definitions above.
 */

static void
decompress()
{
	char_type *stackp, *stack_lim;
	int finchar;
	code_int code, oldcode, incode;
	FILE *fout = outp;

	/*
	 * As above, initialize the first 256 entries in the table.
	 */
	maxcode = MAXCODE(n_bits = INIT_BITS);
	for (code = 255; code >= 0; code--) {
		tab_prefixof(code) = 0;
		tab_suffixof(code) = (char_type)code;
	}
	free_ent = ((block_compress) ? FIRST : 256);

	finchar = oldcode = getcode();
	if (oldcode == -1)	/* EOF already? */
		return;			/* Get out of here */
	/* first code must be 8 bits = char */
	if (putc((char)finchar, outp) == EOF && ferror(outp)) {
		/* Crash if can't write */
		ioerror();
	}
	stackp = de_stack;
	stack_lim = stack_max;

	while ((code = getcode()) > -1) {

		if ((code == CLEAR) && block_compress) {
			for (code = 255; code >= 0; code--)
				tab_prefixof(code) = 0;
			clear_flg = 1;
			free_ent = FIRST - 1;
			if ((code = getcode()) == -1)	/* O, untimely death! */
				break;
		}
		incode = code;
		/*
		 * Special case for KwKwK string.
		 */
		if (code >= free_ent) {
			if (stackp < stack_lim) {
				*stackp++ = (char_type) finchar;
				code = oldcode;
			} else {
				/* badness */
				longjmp(env, 2);
			}
		}

		/*
		 * Generate output characters in reverse order
		 */
		while (code >= 256) {
			if (stackp < stack_lim) {
				*stackp++ = tab_suffixof(code);
				code = tab_prefixof(code);
			} else {
				/* badness */
				longjmp(env, 2);
			}
		}
		*stackp++ = finchar = tab_suffixof(code);

		/*
		 * And put them out in forward order
		 */
		do {
			stackp--;
			(void) putc(*stackp, fout);
		} while (stackp > de_stack);

		if (ferror(fout))
			ioerror();

		/*
		 * Generate the new entry.
		 */
		if ((code = free_ent) < maxmaxcode) {
			tab_prefixof(code) = (unsigned short) oldcode;
			tab_suffixof(code) = (char_type) finchar;
			free_ent = code+1;
		}
		/*
		 * Remember previous code.
		 */
		oldcode = incode;
	}
	(void) fflush(outp);
	if (ferror(outp))
		ioerror();
}

/*
 * **************************************************************
 * TAG( getcode )
 *
 * Read one code from the standard input.  If EOF, return -1.
 * Inputs:
 * 	inp
 * Outputs:
 * 	code or -1 is returned.
 */

code_int
getcode() {
	code_int code;
	static int offset = 0, size = 0;
	static char_type buf[BITS];
	int r_off, bits;
	char_type *bp = buf;

	if (clear_flg > 0 || offset >= size || free_ent > maxcode) {
		/*
		 * If the next entry will be too big for the current code
		 * size, then we must increase the size.  This implies reading
		 * a new buffer full, too.
		 */
		if (free_ent > maxcode) {
			n_bits++;
			if (n_bits == maxbits)
				/* won't get any bigger now */
				maxcode = maxmaxcode;
			else
				maxcode = MAXCODE(n_bits);
		}
		if (clear_flg > 0) {
			maxcode = MAXCODE(n_bits = INIT_BITS);
			clear_flg = 0;
		}
		size = fread(buf, 1, n_bits, inp);

		if (size <= 0) {
			if (feof(inp)) {
				/* end of file */
				return (-1);
			} else if (ferror(inp)) {
				ioerror();
			}
		}

		offset = 0;
		/* Round size down to integral number of codes */
		size = (size << 3) - (n_bits - 1);
	}
	r_off = offset;
	bits = n_bits;
	/*
	 * Get to the first byte.
	 */
	bp += (r_off >> 3);
	r_off &= 7;
	/* Get first part (low order bits) */
	code = (*bp++ >> r_off);
	bits -= (8 - r_off);
	r_off = 8 - r_off;		/* now, offset into code word */
	/* Get any 8 bit parts in the middle (<=1 for up to 16 bits). */
	if (bits >= 8) {
		code |= *bp++ << r_off;
		r_off += 8;
		bits -= 8;
	}
	/* high order bits. */
	code |= (*bp & rmask[bits]) << r_off;
	offset += n_bits;

	return (code);
}

#ifdef DEBUG
static void
printcodes()
{
	/*
	 * Just print out codes from input file.  For debugging.
	 */
	code_int code;
	int col = 0, bits;

	bits = n_bits = INIT_BITS;
	maxcode = MAXCODE(n_bits);
	free_ent = ((block_compress) ? FIRST : 256);
	while ((code = getcode()) >= 0) {
		if ((code == CLEAR) && block_compress) {
			free_ent = FIRST - 1;
			clear_flg = 1;
		} else if (free_ent < maxmaxcode)
			free_ent++;
		if (bits != n_bits) {
			(void) fprintf(stderr, "\nChange to %d bits\n", n_bits);
			bits = n_bits;
			col = 0;
		}
		(void) fprintf(stderr, "%5d%c",
		    code, (col += 6) >= 74 ? (col = 0, '\n') : ' ');
	}
	(void) putc('\n', stderr);
}

#endif /* DEBUG */

#ifdef DEBUG
static void
dump_tab()	/* dump string table */
{
	int i, first;
	int ent;
	int stack_top = STACK_SIZE;
	int c;

	if (do_decomp == 0) {	/* compressing */
		int flag = 1;

		for (i = 0; i < hsize; i++) {	/* build sort pointers */
			if ((long)htabof(i) >= 0) {
				sorttab[codetabof(i)] = i;
			}
		}
		first = block_compress ? FIRST : 256;
		for (i = first; i < free_ent; i++) {
			(void) fprintf(stderr, "%5d: \"", i);
			de_stack[--stack_top] = '\n';
			de_stack[--stack_top] = '"';
			stack_top =
			    in_stack((htabof(sorttab[i]) >> maxbits) & 0xff,
			    stack_top);
			for (ent = htabof(sorttab[i]) & ((1 << maxbits) -1);
			    ent > 256;
			    ent = htabof(sorttab[ent]) & ((1<<maxbits)-1)) {
				stack_top = in_stack(
				    htabof(sorttab[ent]) >> maxbits,
				    stack_top);
			}
			stack_top = in_stack(ent, stack_top);
			(void) fwrite(&de_stack[stack_top], 1,
			    STACK_SIZE - stack_top, stderr);
			stack_top = STACK_SIZE;
		}
	} else if (!debug) {	/* decompressing */

		for (i = 0; i < free_ent; i++) {
			ent = i;
			c = tab_suffixof(ent);
			if (isascii(c) && isprint(c))
				(void) fprintf(stderr, "%5d: %5d/'%c'  \"",
				    ent, tab_prefixof(ent), c);
			else
				(void) fprintf(stderr, "%5d: %5d/\\%03o \"",
				    ent, tab_prefixof(ent), c);
			de_stack[--stack_top] = '\n';
			de_stack[--stack_top] = '"';
			for (; ent != NULL;
			    ent = (ent >= FIRST ? tab_prefixof(ent) :
			    NULL)) {
				stack_top = in_stack(tab_suffixof(ent),
				    stack_top);
			}
			(void) fwrite(&de_stack[stack_top], 1,
			    STACK_SIZE - stack_top, stderr);
			stack_top = STACK_SIZE;
		}
	}
}

#endif /* DEBUG */
#ifdef DEBUG
static int
in_stack(int c, int stack_top)
{
	if ((isascii(c) && isprint(c) && c != '\\') || c == ' ') {
		de_stack[--stack_top] = c;
	} else {
		switch (c) {
		case '\n': de_stack[--stack_top] = 'n'; break;
		case '\t': de_stack[--stack_top] = 't'; break;
		case '\b': de_stack[--stack_top] = 'b'; break;
		case '\f': de_stack[--stack_top] = 'f'; break;
		case '\r': de_stack[--stack_top] = 'r'; break;
		case '\\': de_stack[--stack_top] = '\\'; break;
		default:
			de_stack[--stack_top] = '0' + c % 8;
			de_stack[--stack_top] = '0' + (c / 8) % 8;
			de_stack[--stack_top] = '0' + c / 64;
			break;
		}
		de_stack[--stack_top] = '\\';
	}
	return (stack_top);
}

#endif /* DEBUG */
static void
ioerror()
{
	longjmp(env, 1);
}

static void
copystat(char *ifname, struct stat *ifstat, char *ofname)
{
	mode_t mode;
	struct utimbuf timep;
	acl_t *aclp = NULL;
	int error;
	int sattr_exist = 0;
	int xattr_exist = 0;

	if (pathconf(ifname, _PC_XATTR_EXISTS) == 1)
		xattr_exist = 1;
	if (saflg && sysattr_support(ifname, _PC_SATTR_EXISTS) == 1)
		sattr_exist = 1;

	if (fclose(outp)) {
		perror(ofname);
		if (!quiet) {
			(void) fprintf(stderr, gettext(" -- file unchanged"));
			newline_needed = 1;
		}
		perm_stat = 1;
	} else if (ifstat == NULL) {	/* Get stat on input file */
		perror(ifname);
		return;
	} else if ((ifstat->st_mode &
	    S_IFMT /* 0170000 */) != S_IFREG /* 0100000 */) {
		if (quiet) {
			(void) fprintf(stderr, "%s: ", ifname);
		}
		(void) fprintf(stderr, gettext(
		    " -- not a regular file: unchanged"));
		newline_needed = 1;
		perm_stat = 1;
	} else if (ifstat->st_nlink > 1) {
		if (quiet) {
			(void) fprintf(stderr, "%s: ", ifname);
		}
		(void) fprintf(stderr, gettext(
		    " -- has %d other links: unchanged"),
		    (uint_t)ifstat->st_nlink - 1);
		newline_needed = 1;
		perm_stat = 1;
	} else if (didnt_shrink && !force) {
		/* No compression: remove file.Z */
		if (!quiet) {
			(void) fprintf(stderr, gettext(
			    " -- file unchanged"));
			newline_needed = 1;
		}
	} else 	if ((xattr_exist || sattr_exist) &&
	    (mv_xattrs(progname, ifname, ofname, sattr_exist, 0)
	    != 0)) {
		(void) fprintf(stderr, gettext(
		    "%s: -- cannot preserve extended attributes or "
		    "system attributes, file unchanged"), ifname);
		newline_needed = 1;
		/* Move attributes back ... */
		xattr_exist = 0;
		sattr_exist = 0;
		if (pathconf(ofname, _PC_XATTR_EXISTS) == 1)
			xattr_exist = 1;
		if (saflg && sysattr_support(ofname, _PC_SATTR_EXISTS) == 1)
			sattr_exist = 1;
		if (sattr_exist || xattr_exist)
			(void) mv_xattrs(progname, ofname, ifname,
			    sattr_exist, 1);
		perm_stat = 1;
	} else { /* ***** Successful Compression ***** */
		mode = ifstat->st_mode & 07777;
		if (chmod(ofname, mode)) {	 /* Copy modes */
			if (errno == EPERM) {
				(void) fprintf(stderr,
				    gettext("failed to chmod %s"
				    "- permisssion denied\n"), ofname);
			}
			perror(ofname);
		}
		error = acl_get(ifname, ACL_NO_TRIVIAL, &aclp);
		if (error != 0) {
			(void) fprintf(stderr, gettext(
			    "%s: failed to retrieve acl : %s\n"),
			    ifname, acl_strerror(error));
			perm_stat = 1;
		}
		if (aclp && (acl_set(ofname, aclp) < 0)) {
			(void) fprintf(stderr,
			    gettext("%s: failed to set acl "
			    "entries\n"), ofname);
			perm_stat = 1;
		}
		if (aclp) {
			acl_free(aclp);
			aclp = NULL;
		}

		/* Copy ownership */
		(void) chown(ofname, ifstat->st_uid, ifstat->st_gid);
		timep.actime = ifstat->st_atime;
		timep.modtime = ifstat->st_mtime;
		/* Update last accessed and modified times */
		(void) utime(ofname, &timep);
		if (unlink(ifname)) { /* Remove input file */
			if (errno == EPERM) {
				(void) fprintf(stderr,
				    gettext("failed to remove %s"
				    "- permisssion denied\n"), ifname);
			}
			perror(ifname);
		}
		if (!quiet) {
			(void) fprintf(stderr, gettext(
			    " -- replaced with %s"), ofname);
			newline_needed = 1;
		}
		return;		/* Successful return */
	}

	/* Unsuccessful return -- one of the tests failed */
	if (ofname[0] != '\0') {
		if (unlink(ofname)) {
			if (errno == EPERM) {
				(void) fprintf(stderr,
				    gettext("failed to remove %s"
				    "- permisssion denied\n"), ifname);
			}
			perror(ofname);
		}

		ofname[0] = '\0';
	}
}

static void
onintr()
{
	if (!precious && !use_stdout && ofname[0] != '\0')
		(void) unlink(ofname);
	exit(1);
}

static void
oops()	/* wild pointer -- assume bad input */
{
	if (do_decomp) {
		(void) fprintf(stderr, gettext("uncompress: corrupt input\n"));
	}

	if (!use_stdout && ofname[0] != '\0') {
		(void) unlink(ofname);
	}

	exit(1);
}

static void
cl_block(count_long in_count)	/* table clear for block compress */
{
	count_long rat;

	checkpoint = (count_long)in_count + (count_long)CHECK_GAP;
#ifdef DEBUG
	if (debug) {
		(void) fprintf(stderr, "count: %lld, ratio: ",
		    (count_long)in_count);
		prratio(stderr, (count_long)in_count, (count_long)bytes_out);
		(void) fprintf(stderr, "\n");
	}
#endif /* DEBUG */

	/* shift will overflow */
	if ((count_long)in_count > 0x007fffffffffffffLL) {
		rat = (count_long)bytes_out >> 8;
		if (rat == 0) {		/* Don't divide by zero */
			rat = 0x7fffffffffffffffLL;
		} else {
			rat = (count_long)in_count / (count_long)rat;
		}
	} else {
		/* 8 fractional bits */
		rat = ((count_long)in_count << 8) /(count_long)bytes_out;
	}
	if (rat > ratio) {
		ratio = rat;
	} else {
		ratio = 0;
#ifdef DEBUG
		if (verbose)
			dump_tab();	/* dump string table */
#endif
		cl_hash((count_int) hsize);
		free_ent = FIRST;
		clear_flg = 1;
		output((code_int) CLEAR);
#ifdef DEBUG
		if (debug)
			(void) fprintf(stderr, "clear\n");
#endif /* DEBUG */
	}
}

static void
cl_hash(count_int hsize)		/* reset code table */
{
	count_int *htab_p = htab+hsize;
	long i;
	long m1 = -1;

	i = hsize - 16;
	do {				/* might use Sys V memset(3) here */
		*(htab_p-16) = m1;
		*(htab_p-15) = m1;
		*(htab_p-14) = m1;
		*(htab_p-13) = m1;
		*(htab_p-12) = m1;
		*(htab_p-11) = m1;
		*(htab_p-10) = m1;
		*(htab_p-9) = m1;
		*(htab_p-8) = m1;
		*(htab_p-7) = m1;
		*(htab_p-6) = m1;
		*(htab_p-5) = m1;
		*(htab_p-4) = m1;
		*(htab_p-3) = m1;
		*(htab_p-2) = m1;
		*(htab_p-1) = m1;
		htab_p -= 16;
	} while ((i -= 16) >= 0);

	for (i += 16; i > 0; i--)
		*--htab_p = m1;
}

static void
prratio(FILE *stream, count_long num, count_long den)
{
	int q;  /* store percentage */

	q = (int)(10000LL * (count_long)num / (count_long)den);
	if (q < 0) {
		(void) putc('-', stream);
		q = -q;
	}
	(void) fprintf(stream, "%d%s%02d%%", q / 100,
	    localeconv()->decimal_point, q % 100);
}

static void
version()
{
	(void) fprintf(stderr, "%s, Berkeley 5.9 5/11/86\n", rcs_ident);
	(void) fprintf(stderr, "Options: ");
#ifdef DEBUG
	(void) fprintf(stderr, "DEBUG, ");
#endif
	(void) fprintf(stderr, "BITS = %d\n", BITS);
}

static void
Usage()
{
#ifdef DEBUG
	(void) fprintf(stderr,
	"Usage: compress [-dDVfc/] [-b maxbits] [file ...]\n");
#else
	if (strcmp(progname, "compress") == 0) {
		(void) fprintf(stderr,
		    gettext(
		    "Usage: compress [-fv/] [-b maxbits] [file ...]\n"\
		    "       compress c [-fv] [-b maxbits] [file]\n"));
	} else if (strcmp(progname, "uncompress") == 0)
		(void) fprintf(stderr, gettext(
		    "Usage: uncompress [-fv] [-c || -/] [file ...]\n"));
	else if (strcmp(progname, "zcat") == 0)
		(void) fprintf(stderr, gettext("Usage: zcat [file ...]\n"));

#endif /* DEBUG */
}

static char *
local_basename(char *path)
{
	char *p;
	char *ret = (char *)path;

	while ((p = (char *)strpbrk(ret, "/")) != NULL)
		ret = p + 1;
	return (ret);
}

static int
addDotZ(char *fn, size_t fnsize)
{
	char *fn_dup;
	char *dir;
	long int max_name;
	long int max_path;

	fn_dup = strdup(fn);
	dir = dirname(fn_dup);
	max_name = pathconf(dir, _PC_NAME_MAX);
	max_path = pathconf(dir, _PC_PATH_MAX);
	free(fn_dup);

	/* Check for component length too long */

	if ((strlen(local_basename(fn)) + 2) > (size_t)max_name) {
		(void) fprintf(stderr,
		    gettext("%s: filename too long to tack on .Z:"
		    " %s\n"), progname, fn);
		return (-1);
	}

	/* Check for path length too long */

	if ((strlen(fn) + 2) > (size_t)max_path - 1) {
		(void) fprintf(stderr,
		    gettext("%s: Pathname too long to tack on .Z:"
		    " %s\n"), progname, fn);
		return (-1);
	}

	if (strlcat(fn, ".Z", fnsize) >= fnsize) {
		(void) fprintf(stderr,
		    gettext("%s: Buffer overflow adding .Z to %s\n"),
		    progname, fn);
		return (-1);
	}

	return (0);
}
