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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * diagcode library, Sun Private API (PSARC/2004/601)
 *
 * undocumented debugging interface:
 *	set environment variable _FM_DC_DEBUG for debug prints to stderr.
 *	set it to 1 for extended error messages only.
 *	set it to 2 to include success info too on interesting functions.
 *	set it to 3 to include success info on trivial functions too.
 * note that this environment variable is only examined in fm_dc_opendict().
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <alloca.h>
#include <errno.h>

#include <fm/diagcode.h>

/* private (opaque to callers) handle information */
struct fm_dc_handle {
	const char *dictname;
	FILE *fp;
	unsigned maxkey;
	int version;
	int debug;
	/* name/value pairs from .dict header */
	struct fm_dc_prop {
		struct fm_dc_prop *next;
		const char *lhs;
		const char *rhs;
	} *props;
};

/*
 * parameters of the various sizes of diagcodes
 *
 * table must be in ascending order from smallest databits value to largest.
 * when faced with more databits than the last entry, we know we have
 * something that won't fit into a diagcode.
 */
static const struct info {
	int databits;	/* number of bits used to hold dictionary value */
	int numx;	/* number of digits (also called X's) in code */
	int csumbits;	/* number of bits used for checksum */
	int sizeval;	/* value encoded into "size" field of code */
	unsigned long long offset;	/* databits==0 stands for this value */
} Info[] = {
	/*  diagcode is: dictname-XXXX-XX */
	{ 21, 6, 5, 0, 0ULL },

	/*  diagcode is: dictname-XXXX-XXXX-XX */
	{ 38, 10, 8, 1, 2097152ULL },

	/*  diagcode is: dictname-XXXX-XXXX-XXXX-XX */
	{ 55, 14, 11, 2, 274880004096ULL },

	/*  diagcode is: dictname-XXXX-XXXX-XXXX-XXXX-XX */
	{ 72, 18, 14, 3, 36029071898968064ULL }
};
#define	MAXDATABITS 72	/* highest entry in table above */
#define	MAXCODELEN 25	/* big enough to hold the X's, dashes, and \0 */

/* forward references for functions private to this file */
typedef struct bitv bitv;
static const struct info *dictval2info(const bitv *bv);
static const struct info *numx2info(int numx);
static void sortkey(const char *key[]);
static const char *keymatch(const char *linebuf, const char *key[]);
static int buildcode(fm_dc_handle_t *dhp, const char *rhsp,
    char *code, size_t maxcode, char *debugstr);
static bitv *code2dictval(fm_dc_handle_t *dhp, const char *code);
struct parsestate {
	char *parseptr;	/* next unparsed character in buffer */
	char *rhsp;	/* rhs associated with last lhs (or NULL) */
};
static void startparse(struct parsestate *ps, char *ptr);
static char *nextlhs(struct parsestate *ps);
static char *nextrhs(struct parsestate *ps);
static bitv *bitv_alloc(void);
static void bitv_free(bitv *bv);
static void bitv_shift(bitv *bv, unsigned bits);
static void bitv_setlo(bitv *bv, unsigned bits, unsigned val);
static void bitv_shiftin(bitv *bv, unsigned bits, unsigned val);
static void bitv_shiftinv(bitv *bv, unsigned bits, const bitv *inbv);
static int bitv_bits(const bitv *bv);
static unsigned bitv_chunk(const bitv *bv, unsigned limbit, unsigned lobit);
static int bitv_mul(bitv *bv, unsigned long long val);
static int bitv_add(bitv *bv, unsigned long long val);
static int bitv_sub(bitv *bv, unsigned long long val);
static int bitv_ge(const bitv *bv, unsigned long long val);
static bitv *bitv_strparse(const char *s, int bits);
static int bitv_cmp(const bitv *bv1, const bitv *bv2);
static void crc(unsigned long *crcp, unsigned val);

#define	DICTMAXLINE	10240	/* maximum expected dictionary line length */

#define	MAXDEBUGSTR	100	/* for debug messages */

static const char Suffix[] = ".dict";	/* suffix on dictionary filename */
static const char Defaultpath[] = "/usr/lib/fm/dict";
static const char Debugenv[] = "_FM_DC_DEBUG";	/* debug environment var */

/* properties we look for at top of dictionary */
static const char Header[] = "FMDICT: ";
static const char Name[] = "name";
static const char Version[] = "version";
static const char Maxkey[] = "maxkey";

/* the alphabet used to encode information in a diagcode (base32 digits) */
static const char Alphabet[] = "0123456789ACDEFGHJKLMNPQRSTUVWXY";

/* open a dictionary, return opaque handle */
fm_dc_handle_t *
fm_dc_opendict(int version, const char *dirpath, const char *dictname)
{
	int debug = 0;			/* set by environment variable */
	char *debugstr = "";		/* error path debug prefix text */
	fm_dc_handle_t *dhp = NULL;
	char *fname;			/* full dict file name */
	char linebuf[DICTMAXLINE];	/* line read from dict */
	int line = 0;			/* line number in dict */
	unsigned prop_version = 0;	/* version property from dict */
	char *prop_name = "";		/* name property from dict */
	char *lhsp;			/* prop left-hand-side */
	char *rhsp;			/* prop right-hand-side */
	struct parsestate pstate;	/* for startparse(), nextlhs(), etc */

	/* undocumented flag, given via environment variable */
	if ((rhsp = getenv(Debugenv)) != NULL)
		debug = atoi(rhsp);

	if (debug > 1)
		(void) fprintf(stderr,
		    "fm_dc_opendict: ver %d path \"%s\" dict \"%s\": ",
		    version, (dirpath == NULL) ? "NULL" : dirpath, dictname);
	else if (debug)
		debugstr = "fm_dc_opendict: ";	/* used in error paths */

	/* verify caller expects an API version we support */
	if (version < 0 || version > FM_DC_VERSION) {
		if (debug)
			(void) fprintf(stderr, "%sENOTSUP ver not in [0-%d]\n",
			    debugstr, FM_DC_VERSION);
		errno = ENOTSUP;
		return (NULL);
	}

	/* caller can pass in NULL for default dirpath */
	if (dirpath == NULL)
		dirpath = Defaultpath;

	/*
	 * allocate buffer for dirpath, slash, dictname, and suffix
	 * (sizeof (Suffix) includes the null).
	 */
	fname = alloca(strlen(dirpath) + 1 +
	    strlen(dictname) + sizeof (Suffix));

	/*
	 * allocate the handle.
	 *
	 * allocate the dictname copy kept in the handle.
	 *
	 * if any of these fail, send back ENOMEM.
	 */
	if ((dhp = malloc(sizeof (*dhp))) == NULL ||
	    (dhp->dictname = strdup(dictname)) == NULL) {
		if (dhp)
			free(dhp);
		if (debug)
			(void) fprintf(stderr, "%sENOMEM\n", debugstr);
		errno = ENOMEM;
		return (NULL);
	}

	/* initialize the handle */
	(void) strcpy(fname, dirpath);
	(void) strcat(fname, "/");
	(void) strcat(fname, dictname);
	(void) strcat(fname, Suffix);
	dhp->fp = NULL;
	dhp->maxkey = 0;
	dhp->version = version;
	dhp->debug = debug;
	dhp->props = NULL;

	/* open the dictionary */
	if (debug > 1)
		(void) fprintf(stderr, "\"%s\": ", fname);
	if ((dhp->fp = fopen(fname, "r")) == NULL) {
		int oerrno = errno;	/* fopen() set errno to something */

		if (debug > 1)
			perror("fopen");
		else if (debug) {
			(void) fprintf(stderr, "%s%s: ", debugstr, fname);
			errno = oerrno;
			perror("fopen");
		}
		fm_dc_closedict(dhp);
		errno = oerrno;
		return (NULL);
	}

	/* pull in the header line and parse it */
	while (fgets(linebuf, DICTMAXLINE, dhp->fp) != NULL) {
		line++;
		if (*linebuf == '\n' || *linebuf == '#')
			continue;

		/* first non-comment, non-blank line must be header */
		if (strncmp(linebuf, Header, sizeof (Header) - 1)) {
			fm_dc_closedict(dhp);
			if (debug)
				(void) fprintf(stderr,
				    "%sEINVAL: line %d: header expected.\n",
				    debugstr, line);
			errno = EINVAL;
			return (NULL);
		}

		/* just wanted header line for now */
		break;
	}

	/* walk through name=value pairs in line after Header string */
	startparse(&pstate, &linebuf[sizeof (Header) - 1]);
	while ((lhsp = nextlhs(&pstate)) != NULL) {
		struct fm_dc_prop *propp;

		if ((rhsp = nextrhs(&pstate)) == NULL) {
			if (debug)
				(void) fprintf(stderr, "%sEINVAL "
				    "%s prop has no value\n", debugstr, lhsp);
			fm_dc_closedict(dhp);
			errno = EINVAL;
			return (NULL);
		}

		propp = malloc(sizeof (*propp));
		if (propp == NULL ||
		    (propp->lhs = strdup(lhsp)) == NULL ||
		    (propp->rhs = strdup(rhsp)) == NULL) {
			if (debug)
				(void) fprintf(stderr, "%sENOMEM\n", debugstr);
			if (propp != NULL) {
				if (propp->lhs != NULL)
					free((void *) propp->lhs);
				free((void *) propp);
			}
			fm_dc_closedict(dhp);
			errno = ENOMEM;
			return (NULL);
		}
		propp->next = dhp->props;
		dhp->props = propp;

		if (strcmp(lhsp, Name) == 0)
			prop_name = rhsp;
		else if (strcmp(lhsp, Version) == 0)
			prop_version = strtoul(rhsp, NULL, 0);
		else if (strcmp(lhsp, Maxkey) == 0)
			dhp->maxkey = strtoul(rhsp, NULL, 0);
	}

	/*
	 * require version 1, expected dict name, and maxkey values
	 * (note we use "1" here and not FM_DC_VERSION because this code
	 * implements version 1, so the check below should not float to
	 * newer version numbers if the header file defines them.)
	 */
	if (prop_version != 1UL || strcmp(prop_name, dictname) ||
	    dhp->maxkey == 0) {
		fm_dc_closedict(dhp);
		if (debug)
			(void) fprintf(stderr,
			    "%sEINVAL ver %d name \"%s\" maxkey %d\n",
			    debugstr, prop_version, prop_name, dhp->maxkey);
		errno = EINVAL;
		return (NULL);
	}

	if (debug > 1)
		(void) fprintf(stderr, "fm_dc_opendict: dhp 0x%p\n",
		    (void *)dhp);
	return (dhp);
}

/* close a dictionary */
void
fm_dc_closedict(fm_dc_handle_t *dhp)
{
	struct fm_dc_prop *props;
	struct fm_dc_prop *oprops;

	if (dhp->debug > 1)
		(void) fprintf(stderr, "fm_dc_closedict: dhp 0x%p\n",
		    (void *)dhp);
	if (dhp->fp)
		(void) fclose(dhp->fp);

	free((void *) dhp->dictname);

	props = dhp->props;
	while (props) {
		if (props->lhs != NULL)
			free((void *) props->lhs);
		if (props->rhs != NULL)
			free((void *) props->rhs);
		oprops = props;
		props = props->next;
		free((void *) oprops);
	}

	free(dhp);
}

/* return maximum length (in bytes) of diagcodes for a given dictionary */
size_t
fm_dc_codelen(fm_dc_handle_t *dhp)
{
	size_t len = strlen(dhp->dictname);

	/* only one version so far, so dhp->version isn't checked */

	if (dhp->debug > 2)
		(void) fprintf(stderr, "fm_dc_codelen: dhp 0x%p: %d\n",
		    (void *)dhp, (int)(len + MAXCODELEN));
	return (len + MAXCODELEN);
}

/* return number of strings in key for a given dictionary */
int
fm_dc_maxkey(fm_dc_handle_t *dhp)
{
	/* only one version so far, so dhp->version isn't checked */

	/* this interface counts the NULL entry */
	if (dhp->debug > 2)
		(void) fprintf(stderr, "fm_dc_maxkey: dhp 0x%p: maxkey %d\n",
		    (void *)dhp, dhp->maxkey + 1);
	return (dhp->maxkey + 1);
}

/* given a key, construct a diagcode */
int
fm_dc_key2code(fm_dc_handle_t *dhp,
    const char *key[], char *code, size_t maxcode)
{
	char *debugstr = "";		/* error path debug prefix text */
	int line = 0;			/* line number in dict */
	char linebuf[DICTMAXLINE];	/* line read from dict */
	const char *rhsp;		/* right-hand-side of entry */

	/* only one version so far, so dhp->version isn't checked */

	if (dhp->debug > 1) {
		int nel;

		(void) fprintf(stderr,
		    "fm_dc_key2code: dhp 0x%p maxcode %lu ", (void *)dhp,
		    (ulong_t)maxcode);
		for (nel = 0; key[nel]; nel++)
			(void) fprintf(stderr, "\"%s\" ", key[nel]);
	} else if (dhp->debug)
		debugstr = "fm_dc_key2code: ";

	/* sort the keys */
	sortkey(key);

	rewind(dhp->fp);

	while (fgets(linebuf, DICTMAXLINE, dhp->fp) != NULL) {
		line++;
		if (*linebuf == '\n' || *linebuf == '#')
			continue;

		/* first non-comment, non-blank line must be header */
		if (strncmp(linebuf, Header, sizeof (Header) - 1) == 0)
			continue;

		if ((rhsp = keymatch(linebuf, key)) != NULL) {
			char ndebugstr[MAXDEBUGSTR];

			if (dhp->debug > 1)
				(void) fprintf(stderr, "match line %d: ", line);
			else {
				(void) snprintf(ndebugstr, MAXDEBUGSTR,
				    "fm_dc_key2code: dictionary line %d",
				    line);
				debugstr = ndebugstr;
			}

			return (buildcode(dhp, rhsp, code, maxcode, debugstr));
		}
	}

	/* no match */
	if (dhp->debug)
		(void) fprintf(stderr, "%sENOMSG no match\n", debugstr);
	errno = ENOMSG;
	return (-1);
}

/* given a diagcode, return the key (array of strings) */
int
fm_dc_code2key(fm_dc_handle_t *dhp, const char *code,
    char *key[], int maxkey)
{
	char *debugstr = "";		/* error path debug prefix text */
	int line = 0;
	char linebuf[DICTMAXLINE];
	bitv *dictval;

	/* only one version so far, so dhp->version isn't checked */

	if (dhp->debug > 1)
		(void) fprintf(stderr,
		    "fm_dc_code2key: dhp 0x%p code \"%s\" maxkey %d: ",
		    (void *)dhp, code, maxkey);
	else if (dhp->debug)
		debugstr = "fm_dc_code2key: ";

	/* convert code back to bit vector */
	if ((dictval = code2dictval(dhp, code)) == NULL) {
		/* code2dictval() sets errno */
		if (dhp->debug) {
			int oerrno = errno;

			/* handle expected types without printing a number */
			if (errno == ENOMEM)
				(void) fprintf(stderr,
				    "%sENOMEM code2dictval\n",
				    debugstr);
			else if (errno == EINVAL)
				(void) fprintf(stderr,
				    "%sEINVAL code2dictval\n",
				    debugstr);
			else
				(void) fprintf(stderr,
				    "%scode2dictval error %d\n",
				    debugstr, oerrno);
			errno = oerrno;
		}
		return (-1);
	}

	rewind(dhp->fp);

	while (fgets(linebuf, DICTMAXLINE, dhp->fp) != NULL) {
		char *ptr;
		bitv *thisval;
		char *beginp;
		char *endp;
		int nel;

		line++;
		if (*linebuf == '\n' || *linebuf == '#')
			continue;

		/* first non-comment, non-blank line must be header */
		if (strncmp(linebuf, Header, sizeof (Header) - 1) == 0)
			continue;

		if ((ptr = strchr(linebuf, '=')) == NULL)
			continue;	/* ignore malformed entries */

		*ptr++ = '\0';

		/* pull in value from dictionary */
		if ((thisval = bitv_strparse(ptr, MAXDATABITS)) == NULL) {
			/* bitv_strparse() sets errno */
			if (errno == ENOMEM) {
				bitv_free(dictval);
				if (dhp->debug)
					(void) fprintf(stderr,
					    "%sENOMEM bitv_strparse\n",
					    debugstr);
				errno = ENOMEM;
				return (-1);
			}
			/* other than ENOMEM, trudge on... */
			continue;
		}

		if (bitv_cmp(thisval, dictval)) {
			bitv_free(thisval);
			continue;
		}

		/* if we got here, we found the match */
		bitv_free(thisval);
		bitv_free(dictval);
		beginp = linebuf;
		nel = 0;
		for (;;) {
			while (*beginp && isspace(*beginp))
				beginp++;
			if (*beginp == '\0') {
				/* all done */
				key[nel] = NULL;
				return (0);
			}
			if (nel >= maxkey - 1) {
				if (dhp->debug)
					(void) fprintf(stderr,
					    "%sENOMEM maxkey %d\n",
					    debugstr, maxkey);
				errno = ENOMEM;
				return (-1);
			}
			for (endp = beginp; *endp && !isspace(*endp); endp++)
				;
			if (*endp)
				*endp++ = '\0';
			if ((key[nel++] = strdup(beginp)) == NULL) {
				if (dhp->debug)
					(void) fprintf(stderr,
					    "%sENOMEM strdup\n", debugstr);
				errno = ENOMEM;
				return (-1);
			}
			beginp = endp;
		}
	}

	bitv_free(dictval);
	if (dhp->debug)
		(void) fprintf(stderr, "%sENOMSG\n", debugstr);
	errno = ENOMSG;
	return (-1);
}

/* return the right-hand side of a names property from the dict header */
const char *
fm_dc_getprop(fm_dc_handle_t *dhp, const char *name)
{
	struct fm_dc_prop *props;

	/* only one version so far, so dhp->version isn't checked */

	if (dhp->debug > 2)
		(void) fprintf(stderr, "fm_dc_getprop: dhp 0x%p: \"%s\"",
		    (void *)dhp, name);

	for (props = dhp->props; props; props = props->next)
		if (strcmp(name, props->lhs) == 0)
			break;

	if (dhp->debug > 2)
		(void) fprintf(stderr, "= \"%s\"\n",
		    (props == NULL) ? "NULL" : props->rhs);

	return ((props == NULL) ? NULL : props->rhs);
}

/* find the appropriate diagcode format for a given dictval */
static const struct info *
dictval2info(const bitv *bv)
{
	int i;

	for (i = 0; i < sizeof (Info) / sizeof (*Info) - 1; i++)
		if (!bitv_ge(bv, Info[i + 1].offset))
			return (&Info[i]);

	/* return largest format */
	return (&Info[sizeof (Info) / sizeof (*Info) - 1]);
}

/* lookup the diagcode parameters given the number of X's used */
static const struct info *
numx2info(int numx)
{
	int i;

	for (i = 0; i < sizeof (Info) / sizeof (*Info); i++)
		if (numx == Info[i].numx)
			return (&Info[i]);

	return (NULL);
}

/* for use with qsort() */
static int
mycmp(const void *a, const void *b)
{
	return (strcmp(*(char **)a, *(char **)b));
}

/*
 * sortkey -- make sure key[] array is lexically sorted and without repeats
 */
static void
sortkey(const char *key[])
{
	int nel;
	int srci;	/* source index when iterating through key[] */
	int dsti;	/* dest index when storing elements in key[] */

	/* count the number of elements in key[] */
	for (nel = 0; key[nel]; nel++)
		;

	if (nel < 2)
		return;		/* nothing to sort */

	qsort((void *)key, nel, sizeof (char *), mycmp);

	/* go through array and remove repeats */
	dsti = 1;
	for (srci = 1; srci < nel; srci++)
		if (strcmp(key[srci], key[dsti - 1]) != 0)
			key[dsti++] = key[srci];
	key[dsti] = NULL;
}

/*
 * keymatch -- check for matching line from the dictionary
 *
 * assumes that the key[] array has already been lexically sorted.
 * returns NULL if no match, otherwise pointer to first character of RHS.
 */
static const char *
keymatch(const char *linebuf, const char *key[])
{
	int keynum = 0;
	const char *ptr;

	while (linebuf) {
		/* skip any initial whitespace in front of name */
		while (*linebuf && isspace(*linebuf))
			linebuf++;

		ptr = key[keynum];

		if (ptr == NULL && *linebuf == '=') {
			/* match */
			linebuf++;
			while (*linebuf && isspace(*linebuf))
				linebuf++;
			return (linebuf);
		} else if (ptr == NULL)
			return (NULL);	/* dict had more strings for key */

		/* match the string */
		while (*linebuf)
			if (*ptr == '\0') {
				if (isspace(*linebuf) || *linebuf == '=')
					break;	/* match */
				else
					return (NULL);	/* dict string longer */
			} else if (*linebuf != *ptr)
				return (NULL);	/* string don't match */
			else {
				linebuf++;
				ptr++;
			}

		keynum++;
	}

	return (NULL);	/* no match */
}

/*
 * buildcode -- given the val from the dictionary, create the diagcode
 */
static int
buildcode(fm_dc_handle_t *dhp, const char *rhsp,
    char *code, size_t maxcode, char *debugstr)
{
	char *codebegin = code;	/* remember start of code buffer */
	const struct info *infop;	/* Info[] table entry */
	unsigned long csum = 0;	/* checksum (CRC) of diagcode */
	const char *ptr;
	bitv *dictval;		/* value from dictionary */
	bitv *allbits;		/* assembled diagcode in binary */
	int bit;		/* for looping through bits */
	int limbit;		/* upper bit limit when looping */

	/* sanity check that buffer is large enough for diagcode */
	if (maxcode < fm_dc_codelen(dhp)) {
		if (dhp->debug)
			(void) fprintf(stderr,
			    "%sENOMEM maxcode %lu < codelen %lu\n",
			    debugstr, (ulong_t)maxcode,
			    (ulong_t)fm_dc_codelen(dhp));
		errno = ENOMEM;
		return (-1);
	}

	/* handle dictname part of checksum */
	for (ptr = dhp->dictname; *ptr; ptr++) {
		crc(&csum, (unsigned)*ptr);
		*code++ = *ptr;
	}

	/* pull in value from dictionary */
	if ((dictval = bitv_strparse(rhsp, MAXDATABITS)) == NULL) {
		/* bitv_strparse() sets errno */
		if (dhp->debug) {
			int oerrno = errno;

			/* handle expected types without printing a number */
			if (errno == ENOMEM)
				(void) fprintf(stderr,
				    "%sENOMEM bitv_strparse\n",
				    debugstr);
			else if (errno == ERANGE)
				(void) fprintf(stderr,
				    "%sERANGE bitv_strparse\n",
				    debugstr);
			else
				(void) fprintf(stderr,
				    "%sbitv_strparse error %d\n",
				    debugstr, oerrno);
			errno = oerrno;
		}
		return (-1);
	}

	/* determine which format of code we're using */
	infop = dictval2info(dictval);

	/* subtract off the offset appropriate for format of code */
	if (dhp->debug > 3)
		(void) fprintf(stderr,
		    "%ssubtract offset %llu\n", debugstr, infop->offset);
	if (bitv_sub(dictval, infop->offset) < 0) {
		/*
		 * this "cannot happen" since code format was chosen
		 * so that offset will be smaller than dictval, and
		 * dictval cannot be out of range since bitv_strparse()
		 * should have caught it.
		 */
		if (dhp->debug)
			(void) fprintf(stderr,
			    "%sERANGE from bitv_sub\n", debugstr);
		bitv_free(dictval);
		errno = ERANGE;
		return (-1);
	}

	/* assemble all the bits for the diagcode */
	if ((allbits = bitv_alloc()) == NULL) {
		bitv_free(dictval);
		if (dhp->debug)
			(void) fprintf(stderr,
			    "%sENOMEM from bitv_alloc\n", debugstr);
		errno = ENOMEM;
		return (-1);
	}

	/*
	 * construct the full diagcode by shifting in information:
	 *	- 2 bit code type, set to 01
	 *	- 2 bit size field
	 *	- the databits of the dictionary code itself
	 */

	bitv_shiftin(allbits, 2, 1);
	bitv_shiftin(allbits, 2, infop->sizeval);
	bitv_shiftinv(allbits, infop->databits, dictval);

	/* insert zeros for checksum */
	bitv_shiftin(allbits, infop->csumbits, 0);

	/* compute checksum */
	limbit = infop->numx * 5;
	for (bit = 0; bit < infop->numx; bit++) {
		crc(&csum, bitv_chunk(allbits, limbit, limbit - 5));
		limbit -= 5;
	}

	/* insert the computed checksum */
	bitv_setlo(allbits, infop->csumbits, (unsigned)csum);

	/* encode binary values according to alphabet */
	limbit = infop->numx * 5;
	for (bit = 0; bit < infop->numx; bit++) {
		if (bit % 4 == 0)
			*code++ = '-';
		*code++ = Alphabet[bitv_chunk(allbits, limbit, limbit - 5)];
		limbit -= 5;
	}

	*code = '\0';
	bitv_free(allbits);
	bitv_free(dictval);

	if (dhp->debug > 1)
		(void) fprintf(stderr, "code \"%s\"\n", codebegin);
	return (0);
}

/*
 * code2dictval -- convert a diagcode back to a bit vector
 */
static bitv *
code2dictval(fm_dc_handle_t *dhp, const char *code)
{
	const struct info *infop;
	int len = strlen(dhp->dictname);
	bitv *allbits;
	bitv *dictval;
	int numx;		/* number of X's we count */
	unsigned long ocsum;	/* original checksum in code */
	unsigned long csum;	/* our computed checksum */
	int bit;		/* for looping through bits */
	int limbit;		/* upper bit limit when looping */
	const char *ptr;

	/* check dictname part of code */
	if (strncasecmp(code, dhp->dictname, len) ||
	    code[len] != '-') {
		errno = EINVAL;
		return (NULL);
	}

	/* convert code back to a bit vector */
	if ((allbits = bitv_alloc()) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	/* we verified it began with dictname and a dash, so skip it */
	code = &code[len + 1];
	numx = 0;
	/* be forgiving about misplaced dashes */
	for (; *code; code++)
		if (*code == '-')
			continue;
		else {
			unsigned val;

			for (val = 0; Alphabet[val]; val++)
				if (*code == Alphabet[val])
					break;
			if (Alphabet[val] == '\0') {
				bitv_free(allbits);
				errno = EINVAL;
				return (NULL);
			}
			bitv_shiftin(allbits, 5, val);
			numx++;
		}

	if ((infop = numx2info(numx)) == NULL) {
		bitv_free(allbits);
		errno = EINVAL;
		return (NULL);
	}

	/* now pull out the csum */
	ocsum = bitv_chunk(allbits, infop->csumbits, 0);

	/* set the csum bits to zero */
	bitv_setlo(allbits, infop->csumbits, 0);

	/* calculate the checksum and see if it matches */
	csum = 0;
	for (ptr = dhp->dictname; *ptr; ptr++)
		crc(&csum, (unsigned)*ptr);
	limbit = numx * 5;
	for (bit = 0; bit < numx; bit++) {
		crc(&csum, bitv_chunk(allbits, limbit, limbit - 5));
		limbit -= 5;
	}
	csum &= (1 << infop->csumbits) - 1;

	if (csum != ocsum) {
		bitv_free(allbits);
		errno = EINVAL;
		return (NULL);
	}

	/* code looks okay, just return dictval portion */
	if ((dictval = bitv_alloc()) == NULL) {
		bitv_free(allbits);
		errno = ENOMEM;
		return (NULL);
	}
	limbit = infop->csumbits + infop->databits;
	while (limbit > infop->csumbits) {
		bitv_shiftin(dictval, 1,
		    bitv_chunk(allbits, limbit, limbit - 1));
		limbit--;
	}
	bitv_free(allbits);

	/* add in the offset appropriate for the length of code being used */
	if (bitv_add(dictval, infop->offset) < 0) {
		/*
		 * overflow "cannot happen" since we've pulled in
		 * a given number of bits from the code and the offset
		 * is designed not to overflow...
		 */
		bitv_free(dictval);
		errno = ERANGE;
		return (NULL);
	}

	return (dictval);
}


/*
 * private routines to parse a line into name/value pairs...
 *
 */

/*
 * startparse -- record starting of buffer containing name=value pairs
 */
static void
startparse(struct parsestate *ps, char *ptr)
{
	ps->parseptr = ptr;
}

/*
 * nextlhs -- return next left-hand-side of name=value pair, or NULL
 *
 * whitespace around the '=' is allowed for, but not required.  the
 * lhs is a simple string that does not contain any whitespace or an
 * embedded equals sign.  no escaped characters, quotes, etc. are
 * honored here.
 *
 * this routine also parses the rhs and saves a pointer to it
 * in Rhsp so that nextrhs() can return it.  if nextrhs() never
 * gets called, we continue looking for the next lhs *after* any
 * rhs that was there.
 */
static char *
nextlhs(struct parsestate *ps)
{
	char *lhsp;
	char *copyto;
	int equals = 0;
	int quote = 0;
	int backslash = 0;

	/* skip whitespace */
	while (*ps->parseptr && isspace(*ps->parseptr))
		ps->parseptr++;

	/* anything left? */
	if (*ps->parseptr == '\0')
		return (NULL);

	/* remember start of lhs, assume no rhs until we see '=' */
	lhsp = ps->parseptr;

	/* find end of token, no escaped chars, quotes, etc. on lhs */
	while (*ps->parseptr && !isspace(*ps->parseptr))
		if (*ps->parseptr == '=') {
			equals = 1;
			break;
		} else
			ps->parseptr++;

	/* null terminate the token, possibly nuking the '=' itself */
	*ps->parseptr++ = '\0';

	/* if we haven't seen an '=', see if it happens after whitespace */
	if (!equals) {
		while (*ps->parseptr && isspace(*ps->parseptr))
			ps->parseptr++;
		if (*ps->parseptr == '=') {
			equals = 1;
			ps->parseptr++;
		}
	}

	/* skip whitespace */
	while (*ps->parseptr && isspace(*ps->parseptr))
		ps->parseptr++;

	/* isolate the rhs if it is there */
	if (!equals || *ps->parseptr == '\0') {
		ps->rhsp = NULL;
		return (lhsp);
	}

	if (*ps->parseptr == '"') {
		quote = 1;
		ps->parseptr++;
	}

	/* remember the beginning of the rhs */
	ps->rhsp = copyto = ps->parseptr;

	/* now scan to the end of the rhs */
	while (*ps->parseptr) {
		if (backslash) {
			switch (*ps->parseptr) {
			case 't':
				*copyto++ = '\t';
				break;

			case 'r':
				*copyto++ = '\r';
				break;

			case 'n':
				*copyto++ = '\n';
				break;

			case 'f':
				*copyto++ = '\f';
				break;

			default:
				*copyto++ = *ps->parseptr;
				break;
			}

			backslash = 0;
		} else if (*ps->parseptr == '\\')
			backslash = 1;
		else if (quote) {
			if (*ps->parseptr == '"') {
				ps->parseptr++;
				break;		/* end of quoted string */
			} else
				*copyto++ = *ps->parseptr;
		} else if (!isspace(*ps->parseptr))
			*copyto++ = *ps->parseptr;
		else {
			ps->parseptr++;
			break;	/* rhs terminated by whitespace */
		}

		ps->parseptr++;
	}
	*copyto = '\0';

	return (lhsp);
}

/*
 * nextrhs -- return right-hand-side of name=value pair, or NULL
 *
 * this routine can only be used after a lhs has been found with
 * nextlhs().  the rhs consists of a string with no whitespace in it,
 * unless the whitespace is escaped with a backslash.  surrounding
 * a string with double quotes is also supported here, as are the
 * common C escape sequences like \t and \n.
 *
 * nextlhs() actually does all the hard work.  we just return any
 * rhs that was found by that routine.
 */
static char *
nextrhs(struct parsestate *ps)
{
	return (ps->rhsp);
}


/*
 * private routines to manipulate bit vectors (i.e. large integers)
 *
 * if these bit vector routines are ever supposed to be more
 * general, the desired length should be passed in to bitv_alloc()
 * instead of defining a maximum here.  but knowing the max ahead
 * of time allows for simpler code and we know the max that will
 * fit into a diagcode.  on the minimum side, the below define
 * must be at least sizeof (unsigned).
 */
#define	BITV_MAX_BYTES 15

/* data structure used to hold a bit vector */
struct bitv {
	unsigned char v[BITV_MAX_BYTES];
};

/* allocate a new, zeroed out bit vector */
static bitv *
bitv_alloc(void)
{
	int i;
	struct bitv *bv = malloc(sizeof (*bv));

	if (bv)
		for (i = 0; i < BITV_MAX_BYTES; i++)
			bv->v[i] = 0;

	return (bv);
}

/* free a bit vector that was allocated with bitv_alloc() */
static void
bitv_free(bitv *bv)
{
	free(bv);
}

/* shift left a bit vector by a given number of bits.  fill with zeros. */
static void
bitv_shift(bitv *bv, unsigned bits)
{
	while (bits > 0) {
		unsigned iterbits = bits;
		int i;

		/* how many bits this iteration?  8 max. */
		if (iterbits > 8)
			iterbits = 8;

		for (i = BITV_MAX_BYTES - 1; i > 0; i--) {
			bv->v[i] <<= iterbits;
			bv->v[i] |= bv->v[i - 1] >> (8 - iterbits);
		}
		bv->v[0] <<= iterbits;

		bits -= iterbits;
	}
}

/* force a given number of bits to a specific value */
static void
bitv_setlo(bitv *bv, unsigned bits, unsigned val)
{
	int i = 0;

	/* assumption: bits * 8 <= sizeof (val) */

	while (bits > 0) {
		unsigned iterbits = bits;
		unsigned mask;

		if (iterbits > 8)
			iterbits = 8;

		mask = (1 << iterbits) - 1;

		bv->v[i] &= ~mask;
		bv->v[i] |= val & mask;

		val >>= iterbits;
		bits -= iterbits;
		/*
		 * the following can't go off end of bv->v[] since
		 * BITV_MAX_BYTES is assumed to be at least sizeof
		 * unsigned and val can't be more than sizeof unsigned
		 * bytes long.
		 */
		i++;
	}
}

/* given a value and number of bits, shift it in from the right */
static void
bitv_shiftin(bitv *bv, unsigned bits, unsigned val)
{
	bitv_shift(bv, bits);
	bitv_setlo(bv, bits, val);
}

/* given a bit vector and a number of bits, shift it in from the right */
static void
bitv_shiftinv(bitv *bv, unsigned bits, const bitv *inbv)
{
	int byteindex = bits / 8;
	int iterbits = bits % 8;

	/* first handle partial byte shift in */
	bitv_shiftin(bv, iterbits, inbv->v[byteindex--]);

	/* now handle any remaining full byte shift ins */
	while (byteindex >= 0)
		bitv_shiftin(bv, 8, inbv->v[byteindex--]);
}

/* return the number of bits required to hold the current bit vector's value */
static int
bitv_bits(const bitv *bv)
{
	int i;

	for (i = BITV_MAX_BYTES - 1; i >= 0; i--)
		if (bv->v[i]) {
			int bit;

			for (bit = 7; bit >= 0; bit--)
				if ((bv->v[i] >> bit) & 1)
					return (i * 8 + bit + 1);

			/* this can't happen, so do *something* */
			return ((i + 1) * 8);
		}

	return (0);
}

/* extract chunks of bits from bit vector */
static unsigned
bitv_chunk(const bitv *bv, unsigned limbit, unsigned lobit)
{
	unsigned retval = 0;
	int bit;

	/*
	 * entry assumptions:
	 *	limbit > lobit
	 *	limbit - lobit <= sizeof (unsigned) * 8
	 */

	for (bit = limbit - 1; bit >= 0 && bit >= lobit; bit--) {
		retval <<= 1;
		retval |= (bv->v[bit / 8] >> (bit % 8)) & 1;
	}

	return (retval);
}

/*
 * multiply by a given value
 *
 *	on overflow, bit vector will hold least significant BITV_MAX_BYTES,
 *	return value will be -1, and errno will be ERANGE.  otherwise
 *	return is zero and bit vector holds the product.
 */
static int
bitv_mul(bitv *bv, unsigned long long val)
{
	unsigned short result;
	unsigned char prod[BITV_MAX_BYTES];
	unsigned k = 0;
	int valbyte;
	int bvbyte;
	int i;

	/* start with a zeroed out bit vector to hold result */
	for (i = 0; i < BITV_MAX_BYTES; i++)
		prod[i] = 0;

	/* from most-significant byte of val to least... */
	for (valbyte = 0; valbyte < sizeof (val); valbyte++)
		/* from most significant byte of bv to least */
		for (bvbyte = 0; bvbyte < BITV_MAX_BYTES; bvbyte++) {
			result = ((val >> (valbyte * 8)) & 0xff) *
			    bv->v[bvbyte] + k;

			if (valbyte + bvbyte >= BITV_MAX_BYTES) {
				/*
				 * we're not storing digits past
				 * BITV_MAX_BYTES, so if they aren't
				 * zeros, then signal an overflow.
				 */
				if (result & 0xff) {
					errno = ERANGE;
					return (-1);
				}
			} else
				prod[valbyte + bvbyte] += result & 0xff;

			/* "carry the 1..." */
			k = result >> 8;
		}

	/* store result in bv */
	for (i = 0; i < BITV_MAX_BYTES; i++)
		bv->v[i] = prod[i];

	return (0);
}

/*
 * add in a given value
 *
 *	on overflow, bit vector will hold least significant BITV_MAX_BYTES,
 *	return value will be -1, and errno will be ERANGE.  otherwise
 *	return is zero and bit vector holds the sum.
 */
static int
bitv_add(bitv *bv, unsigned long long val)
{
	int cf = 0;	/* carry flag */
	unsigned short result;
	int i;

	for (i = 0; i < BITV_MAX_BYTES; i++) {
		if (i < sizeof (val))
			result = cf + bv->v[i] + ((val >> (i * 8)) & 0xff);
		else
			result = cf + bv->v[i];

		cf = (result >> 8) & 1;
		bv->v[i] = result & 0xff;
	}

	if (cf) {
		errno = ERANGE;
		return (-1);
	}
	return (0);
}

/*
 * subtract out a given value
 *
 *	on underflow, bit vector will hold least significant BITV_MAX_BYTES,
 *	return value will be -1, and errno will be ERANGE.  otherwise
 *	return is zero and bit vector holds the difference.
 */
static int
bitv_sub(bitv *bv, unsigned long long val)
{
	int bf = 0;	/* borrow flag */
	unsigned short minuend;
	unsigned short subtrahend;
	int i;

	for (i = 0; i < BITV_MAX_BYTES; i++) {
		minuend = bv->v[i];
		if (i < sizeof (val))
			subtrahend = bf + ((val >> (i * 8)) & 0xff);
		else
			subtrahend = bf;
		if (subtrahend > minuend) {
			bf = 1;
			minuend += 1 << 8;
		} else
			bf = 0;

		bv->v[i] = minuend - subtrahend;
	}

	if (bf) {
		errno = ERANGE;
		return (-1);
	}
	return (0);
}

/*
 * see if bv is greater than or equal to a given value
 */
static int
bitv_ge(const bitv *bv, unsigned long long val)
{
	int bf = 0;	/* borrow flag */
	unsigned short minuend;
	unsigned short subtrahend;
	int i;

	for (i = 0; i < BITV_MAX_BYTES; i++) {
		minuend = bv->v[i];
		if (i < sizeof (val))
			subtrahend = bf + ((val >> (i * 8)) & 0xff);
		else
			subtrahend = bf;
		if (subtrahend > minuend)
			bf = 1;
		else
			bf = 0;
	}

	return (!bf);
}

/* parse a string into bit vector, honor leading 0/0x for octal/hex */
static bitv *
bitv_strparse(const char *s, int bits)
{
	unsigned long long base = 10;
	unsigned long long val;
	bitv *bv = bitv_alloc();

	if (bv == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	if (*s == '0') {
		s++;
		if (*s == 'x') {
			s++;
			base = 16;
		} else
			base = 8;
	}

	while (isxdigit(*s)) {
		/* isxdigit() let's in too much, depending on base */
		if (base == 8 && (*s < '0' || *s > '7'))
			break;
		else if (base == 10 && !isdigit(*s))
			break;

		/* convert the digit to binary */
		if (isdigit(*s))
			val = *s - '0';
		else
			val = tolower(*s) - 'a' + 10;

		/*
		 * multiply our big integer by base,
		 * add in the most recent digit,
		 * and check for overflow
		 */
		if (bitv_mul(bv, base) < 0 ||
		    bitv_add(bv, val) < 0 ||
		    bitv_bits(bv) > bits) {
			bitv_free(bv);
			errno = ERANGE;
			return (NULL);
		}

		s++;
	}

	return (bv);
}

/* return 0 if two bit vectors represent the same number */
static int
bitv_cmp(const bitv *bv1, const bitv *bv2)
{
	int i;

	for (i = BITV_MAX_BYTES - 1; i >= 0; i--)
		if (bv1->v[i] < bv2->v[i])
			return (-1);
		else if (bv1->v[i] > bv2->v[i])
			return (1);
	return (0);
}


/* CRC code... */
static unsigned crctab[256] = {
	0x00000000,
	0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B,
	0x1A864DB2, 0x1E475005, 0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6,
	0x2B4BCB61, 0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD,
	0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC,
	0x5BD4B01B, 0x569796C2, 0x52568B75, 0x6A1936C8, 0x6ED82B7F,
	0x639B0DA6, 0x675A1011, 0x791D4014, 0x7DDC5DA3, 0x709F7B7A,
	0x745E66CD, 0x9823B6E0, 0x9CE2AB57, 0x91A18D8E, 0x95609039,
	0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5, 0xBE2B5B58,
	0xBAEA46EF, 0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033,
	0xA4AD16EA, 0xA06C0B5D, 0xD4326D90, 0xD0F37027, 0xDDB056FE,
	0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95,
	0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4,
	0xE5FFEB43, 0xE8BCCD9A, 0xEC7DD02D, 0x34867077, 0x30476DC0,
	0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C, 0x2E003DC5,
	0x2AC12072, 0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16,
	0x018AEB13, 0x054BF6A4, 0x0808D07D, 0x0CC9CDCA, 0x7897AB07,
	0x7C56B6B0, 0x71159069, 0x75D48DDE, 0x6B93DDDB, 0x6F52C06C,
	0x6211E6B5, 0x66D0FB02, 0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1,
	0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA,
	0xACA5C697, 0xA864DB20, 0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B,
	0xBB60ADFC, 0xB6238B25, 0xB2E29692, 0x8AAD2B2F, 0x8E6C3698,
	0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D,
	0x94EA7B2A, 0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E,
	0xF3B06B3B, 0xF771768C, 0xFA325055, 0xFEF34DE2, 0xC6BCF05F,
	0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34,
	0xDC3ABDED, 0xD8FBA05A, 0x690CE0EE, 0x6DCDFD59, 0x608EDB80,
	0x644FC637, 0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB,
	0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F, 0x5C007B8A,
	0x58C1663D, 0x558240E4, 0x51435D53, 0x251D3B9E, 0x21DC2629,
	0x2C9F00F0, 0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C,
	0x3B5A6B9B, 0x0315D626, 0x07D4CB91, 0x0A97ED48, 0x0E56F0FF,
	0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623, 0xF12F560E,
	0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65,
	0xEBA91BBC, 0xEF68060B, 0xD727BBB6, 0xD3E6A601, 0xDEA580D8,
	0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604, 0xC960EBB3,
	0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2,
	0xAAFBE615, 0xA7B8C0CC, 0xA379DD7B, 0x9B3660C6, 0x9FF77D71,
	0x92B45BA8, 0x9675461F, 0x8832161A, 0x8CF30BAD, 0x81B02D74,
	0x857130C3, 0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640,
	0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C, 0x7B827D21,
	0x7F436096, 0x7200464F, 0x76C15BF8, 0x68860BFD, 0x6C47164A,
	0x61043093, 0x65C52D24, 0x119B4BE9, 0x155A565E, 0x18197087,
	0x1CD86D30, 0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC,
	0x3793A651, 0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D,
	0x2056CD3A, 0x2D15EBE3, 0x29D4F654, 0xC5A92679, 0xC1683BCE,
	0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB,
	0xDBEE767C, 0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18,
	0xF0A5BD1D, 0xF464A0AA, 0xF9278673, 0xFDE69BC4, 0x89B8FD09,
	0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5, 0x9E7D9662,
	0x933EB0BB, 0x97FFAD0C, 0xAFB010B1, 0xAB710D06, 0xA6322BDF,
	0xA2F33668, 0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4
};

static void
crc(unsigned long *crcp, unsigned val)
{
	*crcp = (*crcp<<8) ^ crctab[(unsigned char)((*crcp>>24)^val)];
}
