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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sysconf.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/pfkeyv2.h>
#include <net/pfpolicy.h>
#include <libintl.h>
#include <setjmp.h>
#include <libgen.h>

#include "ipsec_util.h"
#include "ikedoor.h"

/*
 * This file contains support functions that are shared by the ipsec
 * utilities including ipseckey(1m) and ikeadm(1m).
 */

/* Set standard default/initial values for globals... */
boolean_t pflag = B_FALSE;	/* paranoid w.r.t. printing keying material */
boolean_t nflag = B_FALSE;	/* avoid nameservice? */
boolean_t interactive = B_FALSE;	/* util not running on cmdline */
boolean_t readfile = B_FALSE;	/* cmds are being read from a file */
uint_t	lineno = 0;		/* track location if reading cmds from file */
jmp_buf	env;		/* for error recovery in interactive/readfile modes */

/*
 * Print errno and exit if cmdline or readfile, reset state if interactive
 */
void
bail(char *what)
{
	if (errno != 0)
		warn(what);
	else
		warnx(gettext("Error: %s"), what);
	if (readfile) {
		warnx(gettext("System error on line %u."), lineno);
	}
	if (interactive && !readfile)
		longjmp(env, 2);
	exit(1);
}

/*
 * Print caller-supplied variable-arg error msg, then exit if cmdline or
 * readfile, or reset state if interactive.
 */
/*PRINTFLIKE1*/
void
bail_msg(char *fmt, ...)
{
	va_list	ap;
	char	msgbuf[BUFSIZ];

	va_start(ap, fmt);
	(void) vsnprintf(msgbuf, BUFSIZ, fmt, ap);
	va_end(ap);
	if (readfile)
		warnx(gettext("ERROR on line %u:\n%s\n"), lineno,  msgbuf);
	else
		warnx(gettext("ERROR: %s\n"), msgbuf);

	if (interactive && !readfile)
		longjmp(env, 1);

	exit(1);
}


/*
 * dump_XXX functions produce ASCII output from various structures.
 *
 * Because certain errors need to do this to stderr, dump_XXX functions
 * take a FILE pointer.
 *
 * If an error occured while writing to the specified file, these
 * functions return -1, zero otherwise.
 */

int
dump_sockaddr(struct sockaddr *sa, boolean_t addr_only, FILE *where)
{
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	char			*printable_addr, *protocol;
	uint8_t			*addrptr;
	char			storage[INET6_ADDRSTRLEN];
	uint16_t		port;
	boolean_t		unspec;
	struct hostent		*hp;
	int			getipnode_errno, addrlen;

	switch (sa->sa_family) {
	case AF_INET:
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin = (struct sockaddr_in *)sa;
		addrptr = (uint8_t *)&sin->sin_addr;
		port = sin->sin_port;
		protocol = "AF_INET";
		unspec = (sin->sin_addr.s_addr == 0);
		addrlen = sizeof (sin->sin_addr);
		break;
	case AF_INET6:
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin6 = (struct sockaddr_in6 *)sa;
		addrptr = (uint8_t *)&sin6->sin6_addr;
		port = sin6->sin6_port;
		protocol = "AF_INET6";
		unspec = IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr);
		addrlen = sizeof (sin6->sin6_addr);
		break;
	default:
		return (0);
	}

	if (inet_ntop(sa->sa_family, addrptr, storage, INET6_ADDRSTRLEN) ==
	    NULL) {
		printable_addr = gettext("<inet_ntop() failed>");
	} else {
		printable_addr = storage;
	}
	if (addr_only) {
		if (fprintf(where, "%s", printable_addr) < 0)
			return (-1);
	} else {
		if (fprintf(where, gettext("%s: port %d, %s"), protocol,
		    ntohs(port), printable_addr) < 0)
			return (-1);
		if (!nflag) {
			/*
			 * Do AF_independent reverse hostname lookup here.
			 */
			if (unspec) {
				if (fprintf(where,
				    gettext(" <unspecified>")) < 0)
					return (-1);
			} else {
				hp = getipnodebyaddr((char *)addrptr, addrlen,
				    sa->sa_family, &getipnode_errno);
				if (hp != NULL) {
					if (fprintf(where,
					    " (%s)", hp->h_name) < 0)
						return (-1);
					freehostent(hp);
				} else {
					if (fprintf(where,
					    gettext(" <unknown>")) < 0)
						return (-1);
				}
			}
		}
		if (fputs(".\n", where) == EOF)
			return (-1);
	}
	return (0);
}

/*
 * Dump a key and bitlen
 */
int
dump_key(uint8_t *keyp, uint_t bitlen, FILE *where)
{
	int	numbytes;

	numbytes = SADB_1TO8(bitlen);
	/* The & 0x7 is to check for leftover bits. */
	if ((bitlen & 0x7) != 0)
		numbytes++;
	while (numbytes-- != 0) {
		if (pflag) {
			/* Print no keys if paranoid */
			if (fprintf(where, "XX") < 0)
				return (-1);
		} else {
			if (fprintf(where, "%02x", *keyp++) < 0)
				return (-1);
		}
	}
	if (fprintf(where, "/%u", bitlen) < 0)
		return (-1);
	return (0);
}

/*
 * Print an authentication or encryption algorithm
 */
static int
dump_generic_alg(uint8_t alg_num, int proto_num, FILE *where)
{
	struct ipsecalgent *alg;

	alg = getipsecalgbynum(alg_num, proto_num, NULL);
	if (alg == NULL) {
		if (fprintf(where, gettext("<unknown %u>"), alg_num) < 0)
			return (-1);
		return (0);
	}

	/*
	 * Special-case <none> for backward output compat.
	 * Assume that SADB_AALG_NONE == SADB_EALG_NONE.
	 */
	if (alg_num == SADB_AALG_NONE) {
		if (fputs(gettext("<none>"), where) == EOF)
			return (-1);
	} else {
		if (fputs(alg->a_names[0], where) == EOF)
			return (-1);
	}

	freeipsecalgent(alg);
	return (0);
}

int
dump_aalg(uint8_t aalg, FILE *where)
{
	return (dump_generic_alg(aalg, IPSEC_PROTO_AH, where));
}

int
dump_ealg(uint8_t ealg, FILE *where)
{
	return (dump_generic_alg(ealg, IPSEC_PROTO_ESP, where));
}

/*
 * Print an SADB_IDENTTYPE string
 *
 * Also return TRUE if the actual ident may be printed, FALSE if not.
 *
 * If rc is not NULL, set its value to -1 if an error occured while writing
 * to the specified file, zero otherwise.
 */
boolean_t
dump_sadb_idtype(uint8_t idtype, FILE *where, int *rc)
{
	boolean_t canprint = B_TRUE;
	int rc_val = 0;

	switch (idtype) {
	case SADB_IDENTTYPE_PREFIX:
		if (fputs(gettext("prefix"), where) == EOF)
			rc_val = -1;
		break;
	case SADB_IDENTTYPE_FQDN:
		if (fputs(gettext("FQDN"), where) == EOF)
			rc_val = -1;
		break;
	case SADB_IDENTTYPE_USER_FQDN:
		if (fputs(gettext("user-FQDN (mbox)"), where) == EOF)
			rc_val = -1;
		break;
	case SADB_X_IDENTTYPE_DN:
		if (fputs(gettext("ASN.1 DER Distinguished Name"),
		    where) == EOF)
			rc_val = -1;
		canprint = B_FALSE;
		break;
	case SADB_X_IDENTTYPE_GN:
		if (fputs(gettext("ASN.1 DER Generic Name"), where) == EOF)
			rc_val = -1;
		canprint = B_FALSE;
		break;
	case SADB_X_IDENTTYPE_KEY_ID:
		if (fputs(gettext("Generic key id"), where) == EOF)
			rc_val = -1;
		break;
	case SADB_X_IDENTTYPE_ADDR_RANGE:
		if (fputs(gettext("Address range"), where) == EOF)
			rc_val = -1;
		break;
	default:
		if (fprintf(where, gettext("<unknown %u>"), idtype) < 0)
			rc_val = -1;
		break;
	}

	if (rc != NULL)
		*rc = rc_val;

	return (canprint);
}

/*
 * Slice an argv/argc vector from an interactive line or a read-file line.
 */
static int
create_argv(char *ibuf, int *newargc, char ***thisargv)
{
	unsigned int argvlen = START_ARG;
	char **current;
	boolean_t firstchar = B_TRUE;
	boolean_t inquotes = B_FALSE;

	*thisargv = malloc(sizeof (char *) * argvlen);
	if ((*thisargv) == NULL)
		return (MEMORY_ALLOCATION);
	current = *thisargv;
	*current = NULL;

	for (; *ibuf != '\0'; ibuf++) {
		if (isspace(*ibuf)) {
			if (inquotes) {
				continue;
			}
			if (*current != NULL) {
				*ibuf = '\0';
				current++;
				if (*thisargv + argvlen == current) {
					/* Regrow ***thisargv. */
					if (argvlen == TOO_MANY_ARGS) {
						free(*thisargv);
						return (TOO_MANY_TOKENS);
					}
					/* Double the allocation. */
					current = realloc(*thisargv,
					    sizeof (char *) * (argvlen << 1));
					if (current == NULL) {
						free(*thisargv);
						return (MEMORY_ALLOCATION);
					}
					*thisargv = current;
					current += argvlen;
					argvlen <<= 1;	/* Double the size. */
				}
				*current = NULL;
			}
		} else {
			if (firstchar) {
				firstchar = B_FALSE;
				if (*ibuf == COMMENT_CHAR) {
					free(*thisargv);
					return (COMMENT_LINE);
				}
			}
			if (*ibuf == QUOTE_CHAR) {
				if (inquotes) {
					inquotes = B_FALSE;
					*ibuf = '\0';
				} else {
					inquotes = B_TRUE;
				}
				continue;
			}
			if (*current == NULL) {
				*current = ibuf;
				(*newargc)++;
			}
		}
	}

	/*
	 * Tricky corner case...
	 * I've parsed _exactly_ the amount of args as I have space.  It
	 * won't return NULL-terminated, and bad things will happen to
	 * the caller.
	 */
	if (argvlen == *newargc) {
		current = realloc(*thisargv, sizeof (char *) * (argvlen + 1));
		if (current == NULL) {
			free(*thisargv);
			return (MEMORY_ALLOCATION);
		}
		*thisargv = current;
		current[argvlen] = NULL;
	}

	return (SUCCESS);
}

/*
 * Enter a mode where commands are read from a file.  Treat stdin special.
 */
void
do_interactive(FILE *infile, char *promptstring, parse_cmdln_fn parseit)
{
	char		ibuf[IBUF_SIZE], holder[IBUF_SIZE];
	char		*hptr, **thisargv;
	int		thisargc;
	boolean_t	continue_in_progress = B_FALSE;

	(void) setjmp(env);

	interactive = B_TRUE;
	bzero(ibuf, IBUF_SIZE);

	if (infile == stdin) {
		(void) printf("%s", promptstring);
		(void) fflush(stdout);
	} else {
		readfile = B_TRUE;
	}

	while (fgets(ibuf, IBUF_SIZE, infile) != NULL) {
		if (readfile)
			lineno++;
		thisargc = 0;
		thisargv = NULL;

		/*
		 * Check byte IBUF_SIZE - 2, because byte IBUF_SIZE - 1 will
		 * be null-terminated because of fgets().
		 */
		if (ibuf[IBUF_SIZE - 2] != '\0') {
			(void) fprintf(stderr,
			    gettext("Line %d too big.\n"), lineno);
			exit(1);
		}

		if (!continue_in_progress) {
			/* Use -2 because of \n from fgets. */
			if (ibuf[strlen(ibuf) - 2] == CONT_CHAR) {
				/*
				 * Can use strcpy here, I've checked the
				 * length already.
				 */
				(void) strcpy(holder, ibuf);
				hptr = &(holder[strlen(holder)]);

				/* Remove the CONT_CHAR from the string. */
				hptr[-2] = ' ';

				continue_in_progress = B_TRUE;
				bzero(ibuf, IBUF_SIZE);
				continue;
			}
		} else {
			/* Handle continuations... */
			(void) strncpy(hptr, ibuf,
			    (size_t)(&(holder[IBUF_SIZE]) - hptr));
			if (holder[IBUF_SIZE - 1] != '\0') {
				(void) fprintf(stderr,
				    gettext("Command buffer overrun.\n"));
				exit(1);
			}
			/* Use - 2 because of \n from fgets. */
			if (hptr[strlen(hptr) - 2] == CONT_CHAR) {
				bzero(ibuf, IBUF_SIZE);
				hptr += strlen(hptr);

				/* Remove the CONT_CHAR from the string. */
				hptr[-2] = ' ';

				continue;
			} else {
				continue_in_progress = B_FALSE;
				/*
				 * I've already checked the length...
				 */
				(void) strcpy(ibuf, holder);
			}
		}

		switch (create_argv(ibuf, &thisargc, &thisargv)) {
		case TOO_MANY_TOKENS:
			(void) fprintf(stderr,
			    gettext("Too many input tokens.\n"));
			exit(1);
			break;
		case MEMORY_ALLOCATION:
			(void) fprintf(stderr,
			    gettext("Memory allocation error.\n"));
			exit(1);
			break;
		case COMMENT_LINE:
			/* Comment line. */
			break;
		default:
			parseit(thisargc, thisargv);
			free(thisargv);
			if (infile == stdin) {
				(void) printf("%s", promptstring);
				(void) fflush(stdout);
			}
			break;
		}
		bzero(ibuf, IBUF_SIZE);
	}
	if (!readfile) {
		(void) putchar('\n');
		(void) fflush(stdout);
	}
	exit(0);
}

/*
 * Functions to parse strings that represent a debug or privilege level.
 * These functions are copied from main.c and door.c in usr.lib/in.iked/common.
 * If this file evolves into a common library that may be used by in.iked
 * as well as the usr.sbin utilities, those duplicate functions should be
 * deleted.
 *
 * A privilege level may be represented by a simple keyword, corresponding
 * to one of the possible levels.  A debug level may be represented by a
 * series of keywords, separated by '+' or '-', indicating categories to
 * be added or removed from the set of categories in the debug level.
 * For example, +all-op corresponds to level 0xfffffffb (all flags except
 * for D_OP set); while p1+p2+pfkey corresponds to level 0x38.  Note that
 * the leading '+' is implicit; the first keyword in the list must be for
 * a category that is to be added.
 *
 * These parsing functions make use of a local version of strtok, strtok_d,
 * which includes an additional parameter, char *delim.  This param is filled
 * in with the character which ends the returned token.  In other words,
 * this version of strtok, in addition to returning the token, also returns
 * the single character delimiter from the original string which marked the
 * end of the token.
 */
static char *
strtok_d(char *string, const char *sepset, char *delim)
{
	static char	*lasts;
	char		*q, *r;

	/* first or subsequent call */
	if (string == NULL)
		string = lasts;

	if (string == 0)		/* return if no tokens remaining */
		return (NULL);

	q = string + strspn(string, sepset);	/* skip leading separators */

	if (*q == '\0')			/* return if no tokens remaining */
		return (NULL);

	if ((r = strpbrk(q, sepset)) == NULL) {		/* move past token */
		lasts = 0;	/* indicate that this is last token */
	} else {
		*delim = *r;	/* save delimitor */
		*r = '\0';
		lasts = r + 1;
	}
	return (q);
}

static keywdtab_t	privtab[] = {
	{ IKE_PRIV_MINIMUM,	"base" },
	{ IKE_PRIV_MODKEYS,	"modkeys" },
	{ IKE_PRIV_KEYMAT,	"keymat" },
	{ IKE_PRIV_MINIMUM,	"0" },
};

int
privstr2num(char *str)
{
	keywdtab_t	*pp;
	char		*endp;
	int		 priv;

	for (pp = privtab; pp < A_END(privtab); pp++) {
		if (strcasecmp(str, pp->kw_str) == 0)
			return (pp->kw_tag);
	}

	priv = strtol(str, &endp, 0);
	if (*endp == '\0')
		return (priv);

	return (-1);
}

static keywdtab_t	dbgtab[] = {
	{ D_CERT,	"cert" },
	{ D_KEY,	"key" },
	{ D_OP,		"op" },
	{ D_P1,		"p1" },
	{ D_P1,		"phase1" },
	{ D_P2,		"p2" },
	{ D_P2,		"phase2" },
	{ D_PFKEY,	"pfkey" },
	{ D_POL,	"pol" },
	{ D_POL,	"policy" },
	{ D_PROP,	"prop" },
	{ D_DOOR,	"door" },
	{ D_CONFIG,	"config" },
	{ D_ALL,	"all" },
	{ 0,		"0" },
};

int
dbgstr2num(char *str)
{
	keywdtab_t	*dp;

	for (dp = dbgtab; dp < A_END(dbgtab); dp++) {
		if (strcasecmp(str, dp->kw_str) == 0)
			return (dp->kw_tag);
	}
	return (D_INVALID);
}

int
parsedbgopts(char *optarg)
{
	char	*argp, *endp, op, nextop;
	int	mask = 0, new;

	mask = strtol(optarg, &endp, 0);
	if (*endp == '\0')
		return (mask);

	op = optarg[0];
	if (op != '-')
		op = '+';
	argp = strtok_d(optarg, "+-", &nextop);
	do {
		new = dbgstr2num(argp);
		if (new == D_INVALID) {
			/* we encountered an invalid keywd */
			return (new);
		}
		if (op == '+') {
			mask |= new;
		} else {
			mask &= ~new;
		}
		op = nextop;
	} while ((argp = strtok_d(NULL, "+-", &nextop)) != NULL);

	return (mask);
}


/*
 * functions to manipulate the kmcookie-label mapping file
 */

/*
 * Open, lockf, fdopen the given file, returning a FILE * on success,
 * or NULL on failure.
 */
FILE *
kmc_open_and_lock(char *name)
{
	int	fd, rtnerr;
	FILE	*fp;

	if ((fd = open(name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)) < 0) {
		return (NULL);
	}
	if (lockf(fd, F_LOCK, 0) < 0) {
		return (NULL);
	}
	if ((fp = fdopen(fd, "a+")) == NULL) {
		return (NULL);
	}
	if (fseek(fp, 0, SEEK_SET) < 0) {
		/* save errno in case fclose changes it */
		rtnerr = errno;
		(void) fclose(fp);
		errno = rtnerr;
		return (NULL);
	}
	return (fp);
}

/*
 * Extract an integer cookie and string label from a line from the
 * kmcookie-label file.  Return -1 on failure, 0 on success.
 */
int
kmc_parse_line(char *line, int *cookie, char **label)
{
	char	*cookiestr;

	*cookie = 0;
	*label = NULL;

	cookiestr = strtok(line, " \t\n");
	if (cookiestr == NULL) {
		return (-1);
	}

	/* Everything that follows, up to the newline, is the label. */
	*label = strtok(NULL, "\n");
	if (*label == NULL) {
		return (-1);
	}

	*cookie = atoi(cookiestr);
	return (0);
}

/*
 * Insert a mapping into the file (if it's not already there), given the
 * new label.  Return the assigned cookie, or -1 on error.
 */
int
kmc_insert_mapping(char *label)
{
	FILE	*map;
	char	linebuf[MAXLINESIZE];
	char	*cur_label;
	int	max_cookie = 0, cur_cookie, rtn_cookie;
	int	rtnerr = 0;
	boolean_t	found = B_FALSE;

	/* open and lock the file; will sleep until lock is available */
	if ((map = kmc_open_and_lock(KMCFILE)) == NULL) {
		/* kmc_open_and_lock() sets errno appropriately */
		return (-1);
	}

	while (fgets(linebuf, sizeof (linebuf), map) != NULL) {

		if (kmc_parse_line(linebuf, &cur_cookie, &cur_label) < 0) {
			rtnerr = EINVAL;
			goto error;
		}

		if (cur_cookie > max_cookie)
			max_cookie = cur_cookie;

		if ((!found) && (strcmp(cur_label, label) == 0)) {
			found = B_TRUE;
			rtn_cookie = cur_cookie;
		}
	}

	if (!found) {
		rtn_cookie = ++max_cookie;
		if ((fprintf(map, "%u\t%s\n", rtn_cookie, label) < 0) ||
		    (fflush(map) < 0)) {
			rtnerr = errno;
			goto error;
		}
	}
	(void) fclose(map);

	return (rtn_cookie);

error:
	(void) fclose(map);
	errno = rtnerr;
	return (-1);
}

/*
 * Lookup the given cookie and return its corresponding label.  Return
 * a pointer to the label on success, NULL on error (or if the label is
 * not found).  Note that the returned label pointer points to a static
 * string, so the label will be overwritten by a subsequent call to the
 * function; the function is also not thread-safe as a result.
 */
char *
kmc_lookup_by_cookie(int cookie)
{
	FILE		*map;
	static char	linebuf[MAXLINESIZE];
	char		*cur_label;
	int		cur_cookie;

	if ((map = kmc_open_and_lock(KMCFILE)) == NULL) {
		return (NULL);
	}

	while (fgets(linebuf, sizeof (linebuf), map) != NULL) {

		if (kmc_parse_line(linebuf, &cur_cookie, &cur_label) < 0) {
			(void) fclose(map);
			return (NULL);
		}

		if (cookie == cur_cookie) {
			(void) fclose(map);
			return (cur_label);
		}
	}
	(void) fclose(map);

	return (NULL);
}

/*
 * Parse basic extension headers and return in the passed-in pointer vector.
 * Return values include:
 *
 *	KGE_OK	Everything's nice and parsed out.
 *		If there are no extensions, place NULL in extv[0].
 *	KGE_DUP	There is a duplicate extension.
 *		First instance in appropriate bin.  First duplicate in
 *		extv[0].
 *	KGE_UNK	Unknown extension type encountered.  extv[0] contains
 *		unknown header.
 *	KGE_LEN	Extension length error.
 *	KGE_CHK	High-level reality check failed on specific extension.
 *
 * My apologies for some of the pointer arithmetic in here.  I'm thinking
 * like an assembly programmer, yet trying to make the compiler happy.
 */
int
spdsock_get_ext(spd_ext_t *extv[], spd_msg_t *basehdr, uint_t msgsize,
    char *diag_buf, uint_t diag_buf_len)
{
	int i;

	if (diag_buf != NULL)
		diag_buf[0] = '\0';

	for (i = 1; i <= SPD_EXT_MAX; i++)
		extv[i] = NULL;

	i = 0;
	/* Use extv[0] as the "current working pointer". */

	extv[0] = (spd_ext_t *)(basehdr + 1);
	msgsize = SPD_64TO8(msgsize);

	while ((char *)extv[0] < ((char *)basehdr + msgsize)) {
		/* Check for unknown headers. */
		i++;

		if (extv[0]->spd_ext_type == 0 ||
		    extv[0]->spd_ext_type > SPD_EXT_MAX) {
			if (diag_buf != NULL) {
				(void) snprintf(diag_buf, diag_buf_len,
				    "spdsock ext 0x%X unknown: 0x%X",
				    i, extv[0]->spd_ext_type);
			}
			return (KGE_UNK);
		}

		/*
		 * Check length.  Use uint64_t because extlen is in units
		 * of 64-bit words.  If length goes beyond the msgsize,
		 * return an error.  (Zero length also qualifies here.)
		 */
		if (extv[0]->spd_ext_len == 0 ||
		    (uint8_t *)((uint64_t *)extv[0] + extv[0]->spd_ext_len) >
		    (uint8_t *)((uint8_t *)basehdr + msgsize))
			return (KGE_LEN);

		/* Check for redundant headers. */
		if (extv[extv[0]->spd_ext_type] != NULL)
			return (KGE_DUP);

		/* If I make it here, assign the appropriate bin. */
		extv[extv[0]->spd_ext_type] = extv[0];

		/* Advance pointer (See above for uint64_t ptr reasoning.) */
		extv[0] = (spd_ext_t *)
		    ((uint64_t *)extv[0] + extv[0]->spd_ext_len);
	}

	/* Everything's cool. */

	/*
	 * If extv[0] == NULL, then there are no extension headers in this
	 * message.  Ensure that this is the case.
	 */
	if (extv[0] == (spd_ext_t *)(basehdr + 1))
		extv[0] = NULL;

	return (KGE_OK);
}

const char *
spdsock_diag(int diagnostic)
{
	switch (diagnostic) {
	case SPD_DIAGNOSTIC_NONE:
		return (gettext("no error"));
	case SPD_DIAGNOSTIC_UNKNOWN_EXT:
		return (gettext("unknown extension"));
	case SPD_DIAGNOSTIC_BAD_EXTLEN:
		return (gettext("bad extension length"));
	case SPD_DIAGNOSTIC_NO_RULE_EXT:
		return (gettext("no rule extension"));
	case SPD_DIAGNOSTIC_BAD_ADDR_LEN:
		return (gettext("bad address len"));
	case SPD_DIAGNOSTIC_MIXED_AF:
		return (gettext("mixed address family"));
	case SPD_DIAGNOSTIC_ADD_NO_MEM:
		return (gettext("add: no memory"));
	case SPD_DIAGNOSTIC_ADD_WRONG_ACT_COUNT:
		return (gettext("add: wrong action count"));
	case SPD_DIAGNOSTIC_ADD_BAD_TYPE:
		return (gettext("add: bad type"));
	case SPD_DIAGNOSTIC_ADD_BAD_FLAGS:
		return (gettext("add: bad flags"));
	case SPD_DIAGNOSTIC_ADD_INCON_FLAGS:
		return (gettext("add: inconsistent flags"));
	case SPD_DIAGNOSTIC_MALFORMED_LCLPORT:
		return (gettext("malformed local port"));
	case SPD_DIAGNOSTIC_DUPLICATE_LCLPORT:
		return (gettext("duplicate local port"));
	case SPD_DIAGNOSTIC_MALFORMED_REMPORT:
		return (gettext("malformed remote port"));
	case SPD_DIAGNOSTIC_DUPLICATE_REMPORT:
		return (gettext("duplicate remote port"));
	case SPD_DIAGNOSTIC_MALFORMED_PROTO:
		return (gettext("malformed proto"));
	case SPD_DIAGNOSTIC_DUPLICATE_PROTO:
		return (gettext("duplicate proto"));
	case SPD_DIAGNOSTIC_MALFORMED_LCLADDR:
		return (gettext("malformed local address"));
	case SPD_DIAGNOSTIC_DUPLICATE_LCLADDR:
		return (gettext("duplicate local address"));
	case SPD_DIAGNOSTIC_MALFORMED_REMADDR:
		return (gettext("malformed remote address"));
	case SPD_DIAGNOSTIC_DUPLICATE_REMADDR:
		return (gettext("duplicate remote address"));
	case SPD_DIAGNOSTIC_MALFORMED_ACTION:
		return (gettext("malformed action"));
	case SPD_DIAGNOSTIC_DUPLICATE_ACTION:
		return (gettext("duplicate action"));
	case SPD_DIAGNOSTIC_MALFORMED_RULE:
		return (gettext("malformed rule"));
	case SPD_DIAGNOSTIC_DUPLICATE_RULE:
		return (gettext("duplicate rule"));
	case SPD_DIAGNOSTIC_MALFORMED_RULESET:
		return (gettext("malformed ruleset"));
	case SPD_DIAGNOSTIC_DUPLICATE_RULESET:
		return (gettext("duplicate ruleset"));
	case SPD_DIAGNOSTIC_INVALID_RULE_INDEX:
		return (gettext("invalid rule index"));
	case SPD_DIAGNOSTIC_BAD_SPDID:
		return (gettext("bad spdid"));
	case SPD_DIAGNOSTIC_BAD_MSG_TYPE:
		return (gettext("bad message type"));
	case SPD_DIAGNOSTIC_UNSUPP_AH_ALG:
		return (gettext("unsupported AH algorithm"));
	case SPD_DIAGNOSTIC_UNSUPP_ESP_ENCR_ALG:
		return (gettext("unsupported ESP encryption algorithm"));
	case SPD_DIAGNOSTIC_UNSUPP_ESP_AUTH_ALG:
		return (gettext("unsupported ESP authentication algorithm"));
	case SPD_DIAGNOSTIC_UNSUPP_AH_KEYSIZE:
		return (gettext("unsupported AH key size"));
	case SPD_DIAGNOSTIC_UNSUPP_ESP_ENCR_KEYSIZE:
		return (gettext("unsupported ESP encryption key size"));
	case SPD_DIAGNOSTIC_UNSUPP_ESP_AUTH_KEYSIZE:
		return (gettext("unsupported ESP authentication key size"));
	case SPD_DIAGNOSTIC_NO_ACTION_EXT:
		return (gettext("No ACTION extension"));
	case SPD_DIAGNOSTIC_ALG_ID_RANGE:
		return (gettext("invalid algorithm identifer"));
	case SPD_DIAGNOSTIC_ALG_NUM_KEY_SIZES:
		return (gettext("number of key sizes inconsistent"));
	case SPD_DIAGNOSTIC_ALG_NUM_BLOCK_SIZES:
		return (gettext("number of block sizes inconsistent"));
	case SPD_DIAGNOSTIC_ALG_MECH_NAME_LEN:
		return (gettext("invalid mechanism name length"));
	default:
		return (gettext("unknown diagnostic"));
	}
}

/*
 * PF_KEY Diagnostic table.
 *
 * PF_KEY NOTE:  If you change pfkeyv2.h's SADB_X_DIAGNOSTIC_* space, this is
 * where you need to add new messages.
 */

const char *
keysock_diag(int diagnostic)
{
	switch (diagnostic) {
	case  SADB_X_DIAGNOSTIC_NONE:
		return (gettext("No diagnostic"));
	case SADB_X_DIAGNOSTIC_UNKNOWN_MSG:
		return (gettext("Unknown message type"));
	case SADB_X_DIAGNOSTIC_UNKNOWN_EXT:
		return (gettext("Unknown extension type"));
	case SADB_X_DIAGNOSTIC_BAD_EXTLEN:
		return (gettext("Bad extension length"));
	case SADB_X_DIAGNOSTIC_UNKNOWN_SATYPE:
		return (gettext("Unknown Security Association type"));
	case SADB_X_DIAGNOSTIC_SATYPE_NEEDED:
		return (gettext("Specific Security Association type needed"));
	case SADB_X_DIAGNOSTIC_NO_SADBS:
		return (gettext("No Security Association Databases present"));
	case SADB_X_DIAGNOSTIC_NO_EXT:
		return (gettext("No extensions needed for message"));
	case SADB_X_DIAGNOSTIC_BAD_SRC_AF:
		return (gettext("Bad source address family"));
	case SADB_X_DIAGNOSTIC_BAD_DST_AF:
		return (gettext("Bad destination address family"));
	case SADB_X_DIAGNOSTIC_BAD_PROXY_AF:
		return (gettext("Bad proxy address family"));
	case SADB_X_DIAGNOSTIC_AF_MISMATCH:
		return (gettext("Source/destination address family mismatch"));
	case SADB_X_DIAGNOSTIC_BAD_SRC:
		return (gettext("Bad source address value"));
	case SADB_X_DIAGNOSTIC_BAD_DST:
		return (gettext("Bad destination address value"));
	case SADB_X_DIAGNOSTIC_ALLOC_HSERR:
		return (gettext("Soft allocations limit more than hard limit"));
	case SADB_X_DIAGNOSTIC_BYTES_HSERR:
		return (gettext("Soft bytes limit more than hard limit"));
	case SADB_X_DIAGNOSTIC_ADDTIME_HSERR:
		return (gettext("Soft add expiration time later "
		    "than hard expiration time"));
	case SADB_X_DIAGNOSTIC_USETIME_HSERR:
		return (gettext("Soft use expiration time later "
		    "than hard expiration time"));
	case SADB_X_DIAGNOSTIC_MISSING_SRC:
		return (gettext("Missing source address"));
	case SADB_X_DIAGNOSTIC_MISSING_DST:
		return (gettext("Missing destination address"));
	case SADB_X_DIAGNOSTIC_MISSING_SA:
		return (gettext("Missing SA extension"));
	case SADB_X_DIAGNOSTIC_MISSING_EKEY:
		return (gettext("Missing encryption key"));
	case SADB_X_DIAGNOSTIC_MISSING_AKEY:
		return (gettext("Missing authentication key"));
	case SADB_X_DIAGNOSTIC_MISSING_RANGE:
		return (gettext("Missing SPI range"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_SRC:
		return (gettext("Duplicate source address"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_DST:
		return (gettext("Duplicate destination address"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_SA:
		return (gettext("Duplicate SA extension"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_EKEY:
		return (gettext("Duplicate encryption key"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_AKEY:
		return (gettext("Duplicate authentication key"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_RANGE:
		return (gettext("Duplicate SPI range"));
	case SADB_X_DIAGNOSTIC_MALFORMED_SRC:
		return (gettext("Malformed source address"));
	case SADB_X_DIAGNOSTIC_MALFORMED_DST:
		return (gettext("Malformed destination address"));
	case SADB_X_DIAGNOSTIC_MALFORMED_SA:
		return (gettext("Malformed SA extension"));
	case SADB_X_DIAGNOSTIC_MALFORMED_EKEY:
		return (gettext("Malformed encryption key"));
	case SADB_X_DIAGNOSTIC_MALFORMED_AKEY:
		return (gettext("Malformed authentication key"));
	case SADB_X_DIAGNOSTIC_MALFORMED_RANGE:
		return (gettext("Malformed SPI range"));
	case SADB_X_DIAGNOSTIC_AKEY_PRESENT:
		return (gettext("Authentication key not needed"));
	case SADB_X_DIAGNOSTIC_EKEY_PRESENT:
		return (gettext("Encryption key not needed"));
	case SADB_X_DIAGNOSTIC_PROP_PRESENT:
		return (gettext("Proposal extension not needed"));
	case SADB_X_DIAGNOSTIC_SUPP_PRESENT:
		return (gettext("Supported algorithms extension not needed"));
	case SADB_X_DIAGNOSTIC_BAD_AALG:
		return (gettext("Unsupported authentication algorithm"));
	case SADB_X_DIAGNOSTIC_BAD_EALG:
		return (gettext("Unsupported encryption algorithm"));
	case SADB_X_DIAGNOSTIC_BAD_SAFLAGS:
		return (gettext("Invalid SA flags"));
	case SADB_X_DIAGNOSTIC_BAD_SASTATE:
		return (gettext("Invalid SA state"));
	case SADB_X_DIAGNOSTIC_BAD_AKEYBITS:
		return (gettext("Bad number of authentication bits"));
	case SADB_X_DIAGNOSTIC_BAD_EKEYBITS:
		return (gettext("Bad number of encryption bits"));
	case SADB_X_DIAGNOSTIC_ENCR_NOTSUPP:
		return (gettext("Encryption not supported for this SA type"));
	case SADB_X_DIAGNOSTIC_WEAK_EKEY:
		return (gettext("Weak encryption key"));
	case SADB_X_DIAGNOSTIC_WEAK_AKEY:
		return (gettext("Weak authentication key"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_KMP:
		return (gettext("Duplicate key management protocol"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_KMC:
		return (gettext("Duplicate key management cookie"));
	case SADB_X_DIAGNOSTIC_MISSING_NATT_LOC:
		return (gettext("Missing NATT local address"));
	case SADB_X_DIAGNOSTIC_MISSING_NATT_REM:
		return (gettext("Missing NATT remote address"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_NATT_LOC:
		return (gettext("Duplicate NATT local address"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_NATT_REM:
		return (gettext("Duplicate NATT remote address"));
	case SADB_X_DIAGNOSTIC_MALFORMED_NATT_LOC:
		return (gettext("Malformed NATT local address"));
	case SADB_X_DIAGNOSTIC_MALFORMED_NATT_REM:
		return (gettext("Malformed NATT remote address"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_NATT_PORTS:
		return (gettext("Duplicate NATT ports"));
	default:
		return (gettext("Unknown diagnostic code"));
	}
}
