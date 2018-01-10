/*
 *
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Juri. All rights reserved.
 * Copyright 2017 Joyent, Inc.
 */

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
#include <libscf.h>

#include "ipsec_util.h"
#include "ikedoor.h"

/*
 * This file contains support functions that are shared by the ipsec
 * utilities and daemons including ipseckey(1m), ikeadm(1m) and in.iked(1m).
 */


#define	EFD(file) (((file) == stdout) ? stderr : (file))

/* Limits for interactive mode. */
#define	MAX_LINE_LEN	IBUF_SIZE
#define	MAX_CMD_HIST	64000	/* in bytes */

/* Set standard default/initial values for globals... */
boolean_t pflag = B_FALSE;	/* paranoid w.r.t. printing keying material */
boolean_t nflag = B_FALSE;	/* avoid nameservice? */
boolean_t interactive = B_FALSE;	/* util not running on cmdline */
boolean_t readfile = B_FALSE;	/* cmds are being read from a file */
uint_t	lineno = 0;		/* track location if reading cmds from file */
uint_t	lines_added = 0;
uint_t	lines_parsed = 0;
jmp_buf	env;		/* for error recovery in interactive/readfile modes */
char *my_fmri = NULL;
FILE *debugfile = stderr;
static GetLine *gl = NULL;	/* for interactive mode */

/*
 * Print errno and exit if cmdline or readfile, reset state if interactive
 * The error string *what should be dgettext()'d before calling bail().
 */
void
bail(char *what)
{
	if (errno != 0)
		warn(what);
	else
		warnx(dgettext(TEXT_DOMAIN, "Error: %s"), what);
	if (readfile) {
		return;
	}
	if (interactive && !readfile)
		longjmp(env, 2);
	EXIT_FATAL(NULL);
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
		warnx(dgettext(TEXT_DOMAIN,
		    "ERROR on line %u:\n%s\n"), lineno,  msgbuf);
	else
		warnx(dgettext(TEXT_DOMAIN, "ERROR: %s\n"), msgbuf);

	if (interactive && !readfile)
		longjmp(env, 1);

	EXIT_FATAL(NULL);
}

/*
 * bytecnt2str() wrapper. Zeroes out the input buffer and if the number
 * of bytes to be converted is more than 1K, it will produce readable string
 * in parentheses, store it in the original buffer and return the pointer to it.
 * Maximum length of the returned string is 14 characters (not including
 * the terminating zero).
 */
char *
bytecnt2out(uint64_t num, char *buf, size_t bufsiz, int flags)
{
	char *str;

	(void) memset(buf, '\0', bufsiz);

	if (num > 1024) {
		/* Return empty string in case of out-of-memory. */
		if ((str = malloc(bufsiz)) == NULL)
			return (buf);

		(void) bytecnt2str(num, str, bufsiz);
		/* Detect overflow. */
		if (strlen(str) == 0) {
			free(str);
			return (buf);
		}

		/* Emit nothing in case of overflow. */
		if (snprintf(buf, bufsiz, "%s(%sB)%s",
		    flags & SPC_BEGIN ? " " : "", str,
		    flags & SPC_END ? " " : "") >= bufsiz)
			(void) memset(buf, '\0', bufsiz);

		free(str);
	}

	return (buf);
}

/*
 * Convert 64-bit number to human readable string. Useful mainly for the
 * byte lifetime counters. Returns pointer to the user supplied buffer.
 * Able to convert up to Exabytes. Maximum length of the string produced
 * is 9 characters (not counting the terminating zero).
 */
char *
bytecnt2str(uint64_t num, char *buf, size_t buflen)
{
	uint64_t n = num;
	char u;
	int index = 0;

	while (n >= 1024) {
		n /= 1024;
		index++;
	}

	/* The field has all units this function can represent. */
	u = " KMGTPE"[index];

	if (index == 0) {
		/* Less than 1K */
		if (snprintf(buf, buflen, "%llu ", num) >= buflen)
			(void) memset(buf, '\0', buflen);
	} else {
		/* Otherwise display 2 precision digits. */
		if (snprintf(buf, buflen, "%.2f %c",
		    (double)num / (1ULL << index * 10), u) >= buflen)
			(void) memset(buf, '\0', buflen);
	}

	return (buf);
}

/*
 * secs2str() wrapper. Zeroes out the input buffer and if the number of
 * seconds to be converted is more than minute, it will produce readable
 * string in parentheses, store it in the original buffer and return the
 * pointer to it.
 */
char *
secs2out(unsigned int secs, char *buf, int bufsiz, int flags)
{
	char *str;

	(void) memset(buf, '\0', bufsiz);

	if (secs > 60) {
		/* Return empty string in case of out-of-memory. */
		if ((str = malloc(bufsiz)) == NULL)
			return (buf);

		(void) secs2str(secs, str, bufsiz);
		/* Detect overflow. */
		if (strlen(str) == 0) {
			free(str);
			return (buf);
		}

		/* Emit nothing in case of overflow. */
		if (snprintf(buf, bufsiz, "%s(%s)%s",
		    flags & SPC_BEGIN ? " " : "", str,
		    flags & SPC_END ? " " : "") >= bufsiz)
			(void) memset(buf, '\0', bufsiz);

		free(str);
	}

	return (buf);
}

/*
 * Convert number of seconds to human readable string. Useful mainly for
 * the lifetime counters. Returns pointer to the user supplied buffer.
 * Able to convert up to days.
 */
char *
secs2str(unsigned int secs, char *buf, int bufsiz)
{
	double val = secs;
	char *unit = "second";

	if (val >= 24*60*60) {
		val /= 86400;
		unit = "day";
	} else if (val >= 60*60) {
		val /= 60*60;
		unit = "hour";
	} else if (val >= 60) {
		val /= 60;
		unit = "minute";
	}

	/* Emit nothing in case of overflow. */
	if (snprintf(buf, bufsiz, "%.2f %s%s", val, unit,
	    val >= 2 ? "s" : "") >= bufsiz)
		(void) memset(buf, '\0', bufsiz);

	return (buf);
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
dump_sockaddr(struct sockaddr *sa, uint8_t prefixlen, boolean_t addr_only,
    FILE *where, boolean_t ignore_nss)
{
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	char			*printable_addr, *protocol;
	uint8_t			*addrptr;
	/* Add 4 chars to hold '/nnn' for prefixes. */
	char			storage[INET6_ADDRSTRLEN + 4];
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
		printable_addr = dgettext(TEXT_DOMAIN, "Invalid IP address.");
	} else {
		char prefix[5];	/* "/nnn" with terminator. */

		(void) snprintf(prefix, sizeof (prefix), "/%d", prefixlen);
		printable_addr = storage;
		if (prefixlen != 0) {
			(void) strlcat(printable_addr, prefix,
			    sizeof (storage));
		}
	}
	if (addr_only) {
		if (fprintf(where, "%s", printable_addr) < 0)
			return (-1);
	} else {
		if (fprintf(where, dgettext(TEXT_DOMAIN,
		    "%s: port %d, %s"), protocol,
		    ntohs(port), printable_addr) < 0)
			return (-1);
		if (ignore_nss == B_FALSE) {
			/*
			 * Do AF_independent reverse hostname lookup here.
			 */
			if (unspec) {
				if (fprintf(where,
				    dgettext(TEXT_DOMAIN,
				    " <unspecified>")) < 0)
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
					    dgettext(TEXT_DOMAIN,
					    " <unknown>")) < 0)
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
 * Dump a key, any salt and bitlen.
 * The key is made up of a stream of bits. If the algorithm requires a salt
 * value, this will also be part of the dumped key. The last "saltbits" of the
 * key string, reading left to right will be the salt value. To make it easier
 * to see which bits make up the key, the salt value is enclosed in []'s.
 * This function can also be called when ipseckey(1m) -s is run, this "saves"
 * the SAs, including the key to a file. When this is the case, the []'s are
 * not printed.
 *
 * The implementation allows the kernel to be told about the length of the salt
 * in whole bytes only. If this changes, this function will need to be updated.
 */
int
dump_key(uint8_t *keyp, uint_t bitlen, uint_t saltbits, FILE *where,
    boolean_t separate_salt)
{
	int	numbytes, saltbytes;

	numbytes = SADB_1TO8(bitlen);
	saltbytes = SADB_1TO8(saltbits);
	numbytes += saltbytes;

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
		if (separate_salt && saltbytes != 0 &&
		    numbytes == saltbytes) {
			if (fprintf(where, "[") < 0)
				return (-1);
		}
	}

	if (separate_salt && saltbits != 0) {
		if (fprintf(where, "]/%u+%u", bitlen, saltbits) < 0)
			return (-1);
	} else {
		if (fprintf(where, "/%u", bitlen + saltbits) < 0)
			return (-1);
	}

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
		if (fprintf(where, dgettext(TEXT_DOMAIN,
		    "<unknown %u>"), alg_num) < 0)
			return (-1);
		return (0);
	}

	/*
	 * Special-case <none> for backward output compat.
	 * Assume that SADB_AALG_NONE == SADB_EALG_NONE.
	 */
	if (alg_num == SADB_AALG_NONE) {
		if (fputs(dgettext(TEXT_DOMAIN,
		    "<none>"), where) == EOF)
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
		if (fputs(dgettext(TEXT_DOMAIN, "prefix"), where) == EOF)
			rc_val = -1;
		break;
	case SADB_IDENTTYPE_FQDN:
		if (fputs(dgettext(TEXT_DOMAIN, "FQDN"), where) == EOF)
			rc_val = -1;
		break;
	case SADB_IDENTTYPE_USER_FQDN:
		if (fputs(dgettext(TEXT_DOMAIN,
		    "user-FQDN (mbox)"), where) == EOF)
			rc_val = -1;
		break;
	case SADB_X_IDENTTYPE_DN:
		if (fputs(dgettext(TEXT_DOMAIN, "ASN.1 DER Distinguished Name"),
		    where) == EOF)
			rc_val = -1;
		canprint = B_FALSE;
		break;
	case SADB_X_IDENTTYPE_GN:
		if (fputs(dgettext(TEXT_DOMAIN, "ASN.1 DER Generic Name"),
		    where) == EOF)
			rc_val = -1;
		canprint = B_FALSE;
		break;
	case SADB_X_IDENTTYPE_KEY_ID:
		if (fputs(dgettext(TEXT_DOMAIN, "Generic key id"),
		    where) == EOF)
			rc_val = -1;
		break;
	case SADB_X_IDENTTYPE_ADDR_RANGE:
		if (fputs(dgettext(TEXT_DOMAIN, "Address range"), where) == EOF)
			rc_val = -1;
		break;
	default:
		if (fprintf(where, dgettext(TEXT_DOMAIN,
		    "<unknown %u>"), idtype) < 0)
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
				if (*ibuf == COMMENT_CHAR || *ibuf == '\n') {
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
 * init interactive mode if needed and not yet initialized
 */
static void
init_interactive(FILE *infile, CplMatchFn *match_fn)
{
	if (infile == stdin) {
		if (gl == NULL) {
			if ((gl = new_GetLine(MAX_LINE_LEN,
			    MAX_CMD_HIST)) == NULL)
				errx(1, dgettext(TEXT_DOMAIN,
				    "tecla initialization failed"));

			if (gl_customize_completion(gl, NULL,
			    match_fn) != 0) {
				(void) del_GetLine(gl);
				errx(1, dgettext(TEXT_DOMAIN,
				    "tab completion failed to initialize"));
			}

			/*
			 * In interactive mode we only want to terminate
			 * when explicitly requested (e.g. by a command).
			 */
			(void) sigset(SIGINT, SIG_IGN);
		}
	} else {
		readfile = B_TRUE;
	}
}

/*
 * free tecla data structure
 */
static void
fini_interactive(void)
{
	if (gl != NULL)
		(void) del_GetLine(gl);
}

/*
 * Get single input line, wrapping around interactive and non-interactive
 * mode.
 */
static char *
do_getstr(FILE *infile, char *prompt, char *ibuf, size_t ibuf_size)
{
	char	*line;

	if (infile != stdin)
		return (fgets(ibuf, ibuf_size, infile));

	/*
	 * If the user hits ^C then we want to catch it and
	 * start over.  If the user hits EOF then we want to
	 * bail out.
	 */
once_again:
	line = gl_get_line(gl, prompt, NULL, -1);
	if (gl_return_status(gl) == GLR_SIGNAL) {
		gl_abandon_line(gl);
		goto once_again;
	} else if (gl_return_status(gl) == GLR_ERROR) {
		gl_abandon_line(gl);
		errx(1, dgettext(TEXT_DOMAIN, "Error reading terminal: %s\n"),
		    gl_error_message(gl, NULL, 0));
	} else {
		if (line != NULL) {
			if (strlcpy(ibuf, line, ibuf_size) >= ibuf_size)
				warnx(dgettext(TEXT_DOMAIN,
				    "Line too long (max=%d chars)"),
				    ibuf_size);
			line = ibuf;
		}
	}

	return (line);
}

/*
 * Enter a mode where commands are read from a file.  Treat stdin special.
 */
void
do_interactive(FILE *infile, char *configfile, char *promptstring,
    char *my_fmri, parse_cmdln_fn parseit, CplMatchFn *match_fn)
{
	char		ibuf[IBUF_SIZE], holder[IBUF_SIZE];
	char		*volatile hptr, **thisargv, *ebuf;
	int		thisargc;
	volatile boolean_t	continue_in_progress = B_FALSE;
	char		*s;

	(void) setjmp(env);

	ebuf = NULL;
	interactive = B_TRUE;
	bzero(ibuf, IBUF_SIZE);

	/* panics for us */
	init_interactive(infile, match_fn);

	while ((s = do_getstr(infile, promptstring, ibuf, IBUF_SIZE)) != NULL) {
		if (readfile)
			lineno++;
		thisargc = 0;
		thisargv = NULL;

		/*
		 * Check byte IBUF_SIZE - 2, because byte IBUF_SIZE - 1 will
		 * be null-terminated because of fgets().
		 */
		if (ibuf[IBUF_SIZE - 2] != '\0') {
			if (infile == stdin) {
				/* do_getstr() issued a warning already */
				bzero(ibuf, IBUF_SIZE);
				continue;
			} else {
				ipsecutil_exit(SERVICE_FATAL, my_fmri,
				    debugfile, dgettext(TEXT_DOMAIN,
				    "Line %d too big."), lineno);
			}
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
				ipsecutil_exit(SERVICE_FATAL, my_fmri,
				    debugfile, dgettext(TEXT_DOMAIN,
				    "Command buffer overrun."));
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

		/*
		 * Just in case the command fails keep a copy of the
		 * command buffer for diagnostic output.
		 */
		if (readfile) {
			/*
			 * The error buffer needs to be big enough to
			 * hold the longest command string, plus
			 * some extra text, see below.
			 */
			ebuf = calloc((IBUF_SIZE * 2), sizeof (char));
			if (ebuf == NULL) {
				ipsecutil_exit(SERVICE_FATAL, my_fmri,
				    debugfile, dgettext(TEXT_DOMAIN,
				    "Memory allocation error."));
			} else {
				(void) snprintf(ebuf, (IBUF_SIZE * 2),
				    dgettext(TEXT_DOMAIN,
				    "Config file entry near line %u "
				    "caused error(s) or warnings:\n\n%s\n\n"),
				    lineno, ibuf);
			}
		}

		switch (create_argv(ibuf, &thisargc, &thisargv)) {
		case TOO_MANY_TOKENS:
			ipsecutil_exit(SERVICE_BADCONF, my_fmri, debugfile,
			    dgettext(TEXT_DOMAIN, "Too many input tokens."));
			break;
		case MEMORY_ALLOCATION:
			ipsecutil_exit(SERVICE_BADCONF, my_fmri, debugfile,
			    dgettext(TEXT_DOMAIN, "Memory allocation error."));
			break;
		case COMMENT_LINE:
			/* Comment line. */
			free(ebuf);
			break;
		default:
			if (thisargc != 0) {
				lines_parsed++;
				/* ebuf consumed */
				parseit(thisargc, thisargv, ebuf, readfile);
			} else {
				free(ebuf);
			}
			free(thisargv);
			if (infile == stdin) {
				(void) printf("%s", promptstring);
				(void) fflush(stdout);
			}
			break;
		}
		bzero(ibuf, IBUF_SIZE);
	}

	/*
	 * The following code is ipseckey specific. This should never be
	 * used by ikeadm which also calls this function because ikeadm
	 * only runs interactively. If this ever changes this code block
	 * sould be revisited.
	 */
	if (readfile) {
		if (lines_parsed != 0 && lines_added == 0) {
			ipsecutil_exit(SERVICE_BADCONF, my_fmri, debugfile,
			    dgettext(TEXT_DOMAIN, "Configuration file did not "
			    "contain any valid SAs"));
		}

		/*
		 * There were errors. Putting the service in maintenance mode.
		 * When svc.startd(1M) allows services to degrade themselves,
		 * this should be revisited.
		 *
		 * If this function was called from a program running as a
		 * smf_method(5), print a warning message. Don't spew out the
		 * errors as these will end up in the smf(5) log file which is
		 * publically readable, the errors may contain sensitive
		 * information.
		 */
		if ((lines_added < lines_parsed) && (configfile != NULL)) {
			if (my_fmri != NULL) {
				ipsecutil_exit(SERVICE_BADCONF, my_fmri,
				    debugfile, dgettext(TEXT_DOMAIN,
				    "The configuration file contained %d "
				    "errors.\n"
				    "Manually check the configuration with:\n"
				    "ipseckey -c %s\n"
				    "Use svcadm(1M) to clear maintenance "
				    "condition when errors are resolved.\n"),
				    lines_parsed - lines_added, configfile);
			} else {
				EXIT_BADCONFIG(NULL);
			}
		} else {
			if (my_fmri != NULL)
				ipsecutil_exit(SERVICE_EXIT_OK, my_fmri,
				    debugfile, dgettext(TEXT_DOMAIN,
				    "%d actions successfully processed."),
				    lines_added);
		}
	} else {
		/* no newline upon Ctrl-D */
		if (s != NULL)
			(void) putchar('\n');
		(void) fflush(stdout);
	}

	fini_interactive();

	EXIT_OK(NULL);
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
	{ D_LABEL,	"label" },
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
	char	linebuf[IBUF_SIZE];
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

		/* Skip blank lines, which often come near EOF. */
		if (strlen(linebuf) == 0)
			continue;

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
 *
 * Because this is possibly publically exported, do not change its name,
 * but this is for all intents and purposes an IKEv1/in.iked function.
 */
char *
kmc_lookup_by_cookie(int cookie)
{
	FILE		*map;
	static char	linebuf[IBUF_SIZE];
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
		return (dgettext(TEXT_DOMAIN, "no error"));
	case SPD_DIAGNOSTIC_UNKNOWN_EXT:
		return (dgettext(TEXT_DOMAIN, "unknown extension"));
	case SPD_DIAGNOSTIC_BAD_EXTLEN:
		return (dgettext(TEXT_DOMAIN, "bad extension length"));
	case SPD_DIAGNOSTIC_NO_RULE_EXT:
		return (dgettext(TEXT_DOMAIN, "no rule extension"));
	case SPD_DIAGNOSTIC_BAD_ADDR_LEN:
		return (dgettext(TEXT_DOMAIN, "bad address len"));
	case SPD_DIAGNOSTIC_MIXED_AF:
		return (dgettext(TEXT_DOMAIN, "mixed address family"));
	case SPD_DIAGNOSTIC_ADD_NO_MEM:
		return (dgettext(TEXT_DOMAIN, "add: no memory"));
	case SPD_DIAGNOSTIC_ADD_WRONG_ACT_COUNT:
		return (dgettext(TEXT_DOMAIN, "add: wrong action count"));
	case SPD_DIAGNOSTIC_ADD_BAD_TYPE:
		return (dgettext(TEXT_DOMAIN, "add: bad type"));
	case SPD_DIAGNOSTIC_ADD_BAD_FLAGS:
		return (dgettext(TEXT_DOMAIN, "add: bad flags"));
	case SPD_DIAGNOSTIC_ADD_INCON_FLAGS:
		return (dgettext(TEXT_DOMAIN, "add: inconsistent flags"));
	case SPD_DIAGNOSTIC_MALFORMED_LCLPORT:
		return (dgettext(TEXT_DOMAIN, "malformed local port"));
	case SPD_DIAGNOSTIC_DUPLICATE_LCLPORT:
		return (dgettext(TEXT_DOMAIN, "duplicate local port"));
	case SPD_DIAGNOSTIC_MALFORMED_REMPORT:
		return (dgettext(TEXT_DOMAIN, "malformed remote port"));
	case SPD_DIAGNOSTIC_DUPLICATE_REMPORT:
		return (dgettext(TEXT_DOMAIN, "duplicate remote port"));
	case SPD_DIAGNOSTIC_MALFORMED_PROTO:
		return (dgettext(TEXT_DOMAIN, "malformed proto"));
	case SPD_DIAGNOSTIC_DUPLICATE_PROTO:
		return (dgettext(TEXT_DOMAIN, "duplicate proto"));
	case SPD_DIAGNOSTIC_MALFORMED_LCLADDR:
		return (dgettext(TEXT_DOMAIN, "malformed local address"));
	case SPD_DIAGNOSTIC_DUPLICATE_LCLADDR:
		return (dgettext(TEXT_DOMAIN, "duplicate local address"));
	case SPD_DIAGNOSTIC_MALFORMED_REMADDR:
		return (dgettext(TEXT_DOMAIN, "malformed remote address"));
	case SPD_DIAGNOSTIC_DUPLICATE_REMADDR:
		return (dgettext(TEXT_DOMAIN, "duplicate remote address"));
	case SPD_DIAGNOSTIC_MALFORMED_ACTION:
		return (dgettext(TEXT_DOMAIN, "malformed action"));
	case SPD_DIAGNOSTIC_DUPLICATE_ACTION:
		return (dgettext(TEXT_DOMAIN, "duplicate action"));
	case SPD_DIAGNOSTIC_MALFORMED_RULE:
		return (dgettext(TEXT_DOMAIN, "malformed rule"));
	case SPD_DIAGNOSTIC_DUPLICATE_RULE:
		return (dgettext(TEXT_DOMAIN, "duplicate rule"));
	case SPD_DIAGNOSTIC_MALFORMED_RULESET:
		return (dgettext(TEXT_DOMAIN, "malformed ruleset"));
	case SPD_DIAGNOSTIC_DUPLICATE_RULESET:
		return (dgettext(TEXT_DOMAIN, "duplicate ruleset"));
	case SPD_DIAGNOSTIC_INVALID_RULE_INDEX:
		return (dgettext(TEXT_DOMAIN, "invalid rule index"));
	case SPD_DIAGNOSTIC_BAD_SPDID:
		return (dgettext(TEXT_DOMAIN, "bad spdid"));
	case SPD_DIAGNOSTIC_BAD_MSG_TYPE:
		return (dgettext(TEXT_DOMAIN, "bad message type"));
	case SPD_DIAGNOSTIC_UNSUPP_AH_ALG:
		return (dgettext(TEXT_DOMAIN, "unsupported AH algorithm"));
	case SPD_DIAGNOSTIC_UNSUPP_ESP_ENCR_ALG:
		return (dgettext(TEXT_DOMAIN,
		    "unsupported ESP encryption algorithm"));
	case SPD_DIAGNOSTIC_UNSUPP_ESP_AUTH_ALG:
		return (dgettext(TEXT_DOMAIN,
		    "unsupported ESP authentication algorithm"));
	case SPD_DIAGNOSTIC_UNSUPP_AH_KEYSIZE:
		return (dgettext(TEXT_DOMAIN, "unsupported AH key size"));
	case SPD_DIAGNOSTIC_UNSUPP_ESP_ENCR_KEYSIZE:
		return (dgettext(TEXT_DOMAIN,
		    "unsupported ESP encryption key size"));
	case SPD_DIAGNOSTIC_UNSUPP_ESP_AUTH_KEYSIZE:
		return (dgettext(TEXT_DOMAIN,
		    "unsupported ESP authentication key size"));
	case SPD_DIAGNOSTIC_NO_ACTION_EXT:
		return (dgettext(TEXT_DOMAIN, "No ACTION extension"));
	case SPD_DIAGNOSTIC_ALG_ID_RANGE:
		return (dgettext(TEXT_DOMAIN, "invalid algorithm identifer"));
	case SPD_DIAGNOSTIC_ALG_NUM_KEY_SIZES:
		return (dgettext(TEXT_DOMAIN,
		    "number of key sizes inconsistent"));
	case SPD_DIAGNOSTIC_ALG_NUM_BLOCK_SIZES:
		return (dgettext(TEXT_DOMAIN,
		    "number of block sizes inconsistent"));
	case SPD_DIAGNOSTIC_ALG_MECH_NAME_LEN:
		return (dgettext(TEXT_DOMAIN, "invalid mechanism name length"));
	case SPD_DIAGNOSTIC_NOT_GLOBAL_OP:
		return (dgettext(TEXT_DOMAIN,
		    "operation not applicable to all policies"));
	case SPD_DIAGNOSTIC_NO_TUNNEL_SELECTORS:
		return (dgettext(TEXT_DOMAIN,
		    "using selectors on a transport-mode tunnel"));
	default:
		return (dgettext(TEXT_DOMAIN, "unknown diagnostic"));
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
	case SADB_X_DIAGNOSTIC_NONE:
		return (dgettext(TEXT_DOMAIN, "No diagnostic"));
	case SADB_X_DIAGNOSTIC_UNKNOWN_MSG:
		return (dgettext(TEXT_DOMAIN, "Unknown message type"));
	case SADB_X_DIAGNOSTIC_UNKNOWN_EXT:
		return (dgettext(TEXT_DOMAIN, "Unknown extension type"));
	case SADB_X_DIAGNOSTIC_BAD_EXTLEN:
		return (dgettext(TEXT_DOMAIN, "Bad extension length"));
	case SADB_X_DIAGNOSTIC_UNKNOWN_SATYPE:
		return (dgettext(TEXT_DOMAIN,
		    "Unknown Security Association type"));
	case SADB_X_DIAGNOSTIC_SATYPE_NEEDED:
		return (dgettext(TEXT_DOMAIN,
		    "Specific Security Association type needed"));
	case SADB_X_DIAGNOSTIC_NO_SADBS:
		return (dgettext(TEXT_DOMAIN,
		    "No Security Association Databases present"));
	case SADB_X_DIAGNOSTIC_NO_EXT:
		return (dgettext(TEXT_DOMAIN,
		    "No extensions needed for message"));
	case SADB_X_DIAGNOSTIC_BAD_SRC_AF:
		return (dgettext(TEXT_DOMAIN, "Bad source address family"));
	case SADB_X_DIAGNOSTIC_BAD_DST_AF:
		return (dgettext(TEXT_DOMAIN,
		    "Bad destination address family"));
	case SADB_X_DIAGNOSTIC_BAD_PROXY_AF:
		return (dgettext(TEXT_DOMAIN,
		    "Bad inner-source address family"));
	case SADB_X_DIAGNOSTIC_AF_MISMATCH:
		return (dgettext(TEXT_DOMAIN,
		    "Source/destination address family mismatch"));
	case SADB_X_DIAGNOSTIC_BAD_SRC:
		return (dgettext(TEXT_DOMAIN, "Bad source address value"));
	case SADB_X_DIAGNOSTIC_BAD_DST:
		return (dgettext(TEXT_DOMAIN, "Bad destination address value"));
	case SADB_X_DIAGNOSTIC_ALLOC_HSERR:
		return (dgettext(TEXT_DOMAIN,
		    "Soft allocations limit more than hard limit"));
	case SADB_X_DIAGNOSTIC_BYTES_HSERR:
		return (dgettext(TEXT_DOMAIN,
		    "Soft bytes limit more than hard limit"));
	case SADB_X_DIAGNOSTIC_ADDTIME_HSERR:
		return (dgettext(TEXT_DOMAIN, "Soft add expiration time later "
		    "than hard expiration time"));
	case SADB_X_DIAGNOSTIC_USETIME_HSERR:
		return (dgettext(TEXT_DOMAIN, "Soft use expiration time later "
		    "than hard expiration time"));
	case SADB_X_DIAGNOSTIC_MISSING_SRC:
		return (dgettext(TEXT_DOMAIN, "Missing source address"));
	case SADB_X_DIAGNOSTIC_MISSING_DST:
		return (dgettext(TEXT_DOMAIN, "Missing destination address"));
	case SADB_X_DIAGNOSTIC_MISSING_SA:
		return (dgettext(TEXT_DOMAIN, "Missing SA extension"));
	case SADB_X_DIAGNOSTIC_MISSING_EKEY:
		return (dgettext(TEXT_DOMAIN, "Missing encryption key"));
	case SADB_X_DIAGNOSTIC_MISSING_AKEY:
		return (dgettext(TEXT_DOMAIN, "Missing authentication key"));
	case SADB_X_DIAGNOSTIC_MISSING_RANGE:
		return (dgettext(TEXT_DOMAIN, "Missing SPI range"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_SRC:
		return (dgettext(TEXT_DOMAIN, "Duplicate source address"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_DST:
		return (dgettext(TEXT_DOMAIN, "Duplicate destination address"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_SA:
		return (dgettext(TEXT_DOMAIN, "Duplicate SA extension"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_EKEY:
		return (dgettext(TEXT_DOMAIN, "Duplicate encryption key"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_AKEY:
		return (dgettext(TEXT_DOMAIN, "Duplicate authentication key"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_RANGE:
		return (dgettext(TEXT_DOMAIN, "Duplicate SPI range"));
	case SADB_X_DIAGNOSTIC_MALFORMED_SRC:
		return (dgettext(TEXT_DOMAIN, "Malformed source address"));
	case SADB_X_DIAGNOSTIC_MALFORMED_DST:
		return (dgettext(TEXT_DOMAIN, "Malformed destination address"));
	case SADB_X_DIAGNOSTIC_MALFORMED_SA:
		return (dgettext(TEXT_DOMAIN, "Malformed SA extension"));
	case SADB_X_DIAGNOSTIC_MALFORMED_EKEY:
		return (dgettext(TEXT_DOMAIN, "Malformed encryption key"));
	case SADB_X_DIAGNOSTIC_MALFORMED_AKEY:
		return (dgettext(TEXT_DOMAIN, "Malformed authentication key"));
	case SADB_X_DIAGNOSTIC_MALFORMED_RANGE:
		return (dgettext(TEXT_DOMAIN, "Malformed SPI range"));
	case SADB_X_DIAGNOSTIC_AKEY_PRESENT:
		return (dgettext(TEXT_DOMAIN, "Authentication key not needed"));
	case SADB_X_DIAGNOSTIC_EKEY_PRESENT:
		return (dgettext(TEXT_DOMAIN, "Encryption key not needed"));
	case SADB_X_DIAGNOSTIC_PROP_PRESENT:
		return (dgettext(TEXT_DOMAIN, "Proposal extension not needed"));
	case SADB_X_DIAGNOSTIC_SUPP_PRESENT:
		return (dgettext(TEXT_DOMAIN,
		    "Supported algorithms extension not needed"));
	case SADB_X_DIAGNOSTIC_BAD_AALG:
		return (dgettext(TEXT_DOMAIN,
		    "Unsupported authentication algorithm"));
	case SADB_X_DIAGNOSTIC_BAD_EALG:
		return (dgettext(TEXT_DOMAIN,
		    "Unsupported encryption algorithm"));
	case SADB_X_DIAGNOSTIC_BAD_SAFLAGS:
		return (dgettext(TEXT_DOMAIN, "Invalid SA flags"));
	case SADB_X_DIAGNOSTIC_BAD_SASTATE:
		return (dgettext(TEXT_DOMAIN, "Invalid SA state"));
	case SADB_X_DIAGNOSTIC_BAD_AKEYBITS:
		return (dgettext(TEXT_DOMAIN,
		    "Bad number of authentication bits"));
	case SADB_X_DIAGNOSTIC_BAD_EKEYBITS:
		return (dgettext(TEXT_DOMAIN,
		    "Bad number of encryption bits"));
	case SADB_X_DIAGNOSTIC_ENCR_NOTSUPP:
		return (dgettext(TEXT_DOMAIN,
		    "Encryption not supported for this SA type"));
	case SADB_X_DIAGNOSTIC_WEAK_EKEY:
		return (dgettext(TEXT_DOMAIN, "Weak encryption key"));
	case SADB_X_DIAGNOSTIC_WEAK_AKEY:
		return (dgettext(TEXT_DOMAIN, "Weak authentication key"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_KMP:
		return (dgettext(TEXT_DOMAIN,
		    "Duplicate key management protocol"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_KMC:
		return (dgettext(TEXT_DOMAIN,
		    "Duplicate key management cookie"));
	case SADB_X_DIAGNOSTIC_MISSING_NATT_LOC:
		return (dgettext(TEXT_DOMAIN, "Missing NAT-T local address"));
	case SADB_X_DIAGNOSTIC_MISSING_NATT_REM:
		return (dgettext(TEXT_DOMAIN, "Missing NAT-T remote address"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_NATT_LOC:
		return (dgettext(TEXT_DOMAIN, "Duplicate NAT-T local address"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_NATT_REM:
		return (dgettext(TEXT_DOMAIN,
		    "Duplicate NAT-T remote address"));
	case SADB_X_DIAGNOSTIC_MALFORMED_NATT_LOC:
		return (dgettext(TEXT_DOMAIN, "Malformed NAT-T local address"));
	case SADB_X_DIAGNOSTIC_MALFORMED_NATT_REM:
		return (dgettext(TEXT_DOMAIN,
		    "Malformed NAT-T remote address"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_NATT_PORTS:
		return (dgettext(TEXT_DOMAIN, "Duplicate NAT-T ports"));
	case SADB_X_DIAGNOSTIC_MISSING_INNER_SRC:
		return (dgettext(TEXT_DOMAIN, "Missing inner source address"));
	case SADB_X_DIAGNOSTIC_MISSING_INNER_DST:
		return (dgettext(TEXT_DOMAIN,
		    "Missing inner destination address"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_INNER_SRC:
		return (dgettext(TEXT_DOMAIN,
		    "Duplicate inner source address"));
	case SADB_X_DIAGNOSTIC_DUPLICATE_INNER_DST:
		return (dgettext(TEXT_DOMAIN,
		    "Duplicate inner destination address"));
	case SADB_X_DIAGNOSTIC_MALFORMED_INNER_SRC:
		return (dgettext(TEXT_DOMAIN,
		    "Malformed inner source address"));
	case SADB_X_DIAGNOSTIC_MALFORMED_INNER_DST:
		return (dgettext(TEXT_DOMAIN,
		    "Malformed inner destination address"));
	case SADB_X_DIAGNOSTIC_PREFIX_INNER_SRC:
		return (dgettext(TEXT_DOMAIN,
		    "Invalid inner-source prefix length "));
	case SADB_X_DIAGNOSTIC_PREFIX_INNER_DST:
		return (dgettext(TEXT_DOMAIN,
		    "Invalid inner-destination prefix length"));
	case SADB_X_DIAGNOSTIC_BAD_INNER_DST_AF:
		return (dgettext(TEXT_DOMAIN,
		    "Bad inner-destination address family"));
	case SADB_X_DIAGNOSTIC_INNER_AF_MISMATCH:
		return (dgettext(TEXT_DOMAIN,
		    "Inner source/destination address family mismatch"));
	case SADB_X_DIAGNOSTIC_BAD_NATT_REM_AF:
		return (dgettext(TEXT_DOMAIN,
		    "Bad NAT-T remote address family"));
	case SADB_X_DIAGNOSTIC_BAD_NATT_LOC_AF:
		return (dgettext(TEXT_DOMAIN,
		    "Bad NAT-T local address family"));
	case SADB_X_DIAGNOSTIC_PROTO_MISMATCH:
		return (dgettext(TEXT_DOMAIN,
		    "Source/desination protocol mismatch"));
	case SADB_X_DIAGNOSTIC_INNER_PROTO_MISMATCH:
		return (dgettext(TEXT_DOMAIN,
		    "Inner source/desination protocol mismatch"));
	case SADB_X_DIAGNOSTIC_DUAL_PORT_SETS:
		return (dgettext(TEXT_DOMAIN,
		    "Both inner ports and outer ports are set"));
	case SADB_X_DIAGNOSTIC_PAIR_INAPPROPRIATE:
		return (dgettext(TEXT_DOMAIN,
		    "Pairing failed, target SA unsuitable for pairing"));
	case SADB_X_DIAGNOSTIC_PAIR_ADD_MISMATCH:
		return (dgettext(TEXT_DOMAIN,
		    "Source/destination address differs from pair SA"));
	case SADB_X_DIAGNOSTIC_PAIR_ALREADY:
		return (dgettext(TEXT_DOMAIN,
		    "Already paired with another security association"));
	case SADB_X_DIAGNOSTIC_PAIR_SA_NOTFOUND:
		return (dgettext(TEXT_DOMAIN,
		    "Command failed, pair security association not found"));
	case SADB_X_DIAGNOSTIC_BAD_SA_DIRECTION:
		return (dgettext(TEXT_DOMAIN,
		    "Inappropriate SA direction"));
	case SADB_X_DIAGNOSTIC_SA_NOTFOUND:
		return (dgettext(TEXT_DOMAIN,
		    "Security association not found"));
	case SADB_X_DIAGNOSTIC_SA_EXPIRED:
		return (dgettext(TEXT_DOMAIN,
		    "Security association is not valid"));
	case SADB_X_DIAGNOSTIC_BAD_CTX:
		return (dgettext(TEXT_DOMAIN,
		    "Algorithm invalid or not supported by Crypto Framework"));
	case SADB_X_DIAGNOSTIC_INVALID_REPLAY:
		return (dgettext(TEXT_DOMAIN,
		    "Invalid Replay counter"));
	case SADB_X_DIAGNOSTIC_MISSING_LIFETIME:
		return (dgettext(TEXT_DOMAIN,
		    "Inappropriate lifetimes"));
	default:
		return (dgettext(TEXT_DOMAIN, "Unknown diagnostic code"));
	}
}

/*
 * Convert an IPv6 mask to a prefix len.  I assume all IPv6 masks are
 * contiguous, so I stop at the first zero bit!
 */
int
in_masktoprefix(uint8_t *mask, boolean_t is_v4mapped)
{
	int rc = 0;
	uint8_t last;
	int limit = IPV6_ABITS;

	if (is_v4mapped) {
		mask += ((IPV6_ABITS - IP_ABITS)/8);
		limit = IP_ABITS;
	}

	while (*mask == 0xff) {
		rc += 8;
		if (rc == limit)
			return (limit);
		mask++;
	}

	last = *mask;
	while (last != 0) {
		rc++;
		last = (last << 1) & 0xff;
	}

	return (rc);
}

/*
 * Expand the diagnostic code into a message.
 */
void
print_diagnostic(FILE *file, uint16_t diagnostic)
{
	/* Use two spaces so above strings can fit on the line. */
	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    "  Diagnostic code %u:  %s.\n"),
	    diagnostic, keysock_diag(diagnostic));
}

/*
 * Prints the base PF_KEY message.
 */
void
print_sadb_msg(FILE *file, struct sadb_msg *samsg, time_t wallclock,
    boolean_t vflag)
{
	if (wallclock != 0)
		printsatime(file, wallclock, dgettext(TEXT_DOMAIN,
		    "%sTimestamp: %s\n"), "", NULL,
		    vflag);

	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    "Base message (version %u) type "),
	    samsg->sadb_msg_version);
	switch (samsg->sadb_msg_type) {
	case SADB_RESERVED:
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "RESERVED (warning: set to 0)"));
		break;
	case SADB_GETSPI:
		(void) fprintf(file, "GETSPI");
		break;
	case SADB_UPDATE:
		(void) fprintf(file, "UPDATE");
		break;
	case SADB_X_UPDATEPAIR:
		(void) fprintf(file, "UPDATE PAIR");
		break;
	case SADB_ADD:
		(void) fprintf(file, "ADD");
		break;
	case SADB_DELETE:
		(void) fprintf(file, "DELETE");
		break;
	case SADB_X_DELPAIR:
		(void) fprintf(file, "DELETE PAIR");
		break;
	case SADB_GET:
		(void) fprintf(file, "GET");
		break;
	case SADB_ACQUIRE:
		(void) fprintf(file, "ACQUIRE");
		break;
	case SADB_REGISTER:
		(void) fprintf(file, "REGISTER");
		break;
	case SADB_EXPIRE:
		(void) fprintf(file, "EXPIRE");
		break;
	case SADB_FLUSH:
		(void) fprintf(file, "FLUSH");
		break;
	case SADB_DUMP:
		(void) fprintf(file, "DUMP");
		break;
	case SADB_X_PROMISC:
		(void) fprintf(file, "X_PROMISC");
		break;
	case SADB_X_INVERSE_ACQUIRE:
		(void) fprintf(file, "X_INVERSE_ACQUIRE");
		break;
	default:
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "Unknown (%u)"), samsg->sadb_msg_type);
		break;
	}
	(void) fprintf(file, dgettext(TEXT_DOMAIN, ", SA type "));

	switch (samsg->sadb_msg_satype) {
	case SADB_SATYPE_UNSPEC:
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "<unspecified/all>"));
		break;
	case SADB_SATYPE_AH:
		(void) fprintf(file, "AH");
		break;
	case SADB_SATYPE_ESP:
		(void) fprintf(file, "ESP");
		break;
	case SADB_SATYPE_RSVP:
		(void) fprintf(file, "RSVP");
		break;
	case SADB_SATYPE_OSPFV2:
		(void) fprintf(file, "OSPFv2");
		break;
	case SADB_SATYPE_RIPV2:
		(void) fprintf(file, "RIPv2");
		break;
	case SADB_SATYPE_MIP:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "Mobile IP"));
		break;
	default:
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "<unknown %u>"), samsg->sadb_msg_satype);
		break;
	}

	(void) fprintf(file, ".\n");

	if (samsg->sadb_msg_errno != 0) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "Error %s from PF_KEY.\n"),
		    strerror(samsg->sadb_msg_errno));
		print_diagnostic(file, samsg->sadb_x_msg_diagnostic);
	}

	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    "Message length %u bytes, seq=%u, pid=%u.\n"),
	    SADB_64TO8(samsg->sadb_msg_len), samsg->sadb_msg_seq,
	    samsg->sadb_msg_pid);
}

/*
 * Print the SA extension for PF_KEY.
 */
void
print_sa(FILE *file, char *prefix, struct sadb_sa *assoc)
{
	if (assoc->sadb_sa_len != SADB_8TO64(sizeof (*assoc))) {
		warnxfp(EFD(file), dgettext(TEXT_DOMAIN,
		    "WARNING: SA info extension length (%u) is bad."),
		    SADB_64TO8(assoc->sadb_sa_len));
	}

	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    "%sSADB_ASSOC spi=0x%x, replay window size=%u, state="),
	    prefix, ntohl(assoc->sadb_sa_spi), assoc->sadb_sa_replay);
	switch (assoc->sadb_sa_state) {
	case SADB_SASTATE_LARVAL:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "LARVAL"));
		break;
	case SADB_SASTATE_MATURE:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "MATURE"));
		break;
	case SADB_SASTATE_DYING:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "DYING"));
		break;
	case SADB_SASTATE_DEAD:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "DEAD"));
		break;
	case SADB_X_SASTATE_ACTIVE_ELSEWHERE:
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "ACTIVE_ELSEWHERE"));
		break;
	case SADB_X_SASTATE_IDLE:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "IDLE"));
		break;
	default:
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "<unknown %u>"), assoc->sadb_sa_state);
	}

	if (assoc->sadb_sa_auth != SADB_AALG_NONE) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "\n%sAuthentication algorithm = "),
		    prefix);
		(void) dump_aalg(assoc->sadb_sa_auth, file);
	}

	if (assoc->sadb_sa_encrypt != SADB_EALG_NONE) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "\n%sEncryption algorithm = "), prefix);
		(void) dump_ealg(assoc->sadb_sa_encrypt, file);
	}

	(void) fprintf(file, dgettext(TEXT_DOMAIN, "\n%sflags=0x%x < "), prefix,
	    assoc->sadb_sa_flags);
	if (assoc->sadb_sa_flags & SADB_SAFLAGS_PFS)
		(void) fprintf(file, "PFS ");
	if (assoc->sadb_sa_flags & SADB_SAFLAGS_NOREPLAY)
		(void) fprintf(file, "NOREPLAY ");

	/* BEGIN Solaris-specific flags. */
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_USED)
		(void) fprintf(file, "X_USED ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_PAIRED)
		(void) fprintf(file, "X_PAIRED ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_OUTBOUND)
		(void) fprintf(file, "X_OUTBOUND ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_INBOUND)
		(void) fprintf(file, "X_INBOUND ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_UNIQUE)
		(void) fprintf(file, "X_UNIQUE ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_AALG1)
		(void) fprintf(file, "X_AALG1 ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_AALG2)
		(void) fprintf(file, "X_AALG2 ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_EALG1)
		(void) fprintf(file, "X_EALG1 ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_EALG2)
		(void) fprintf(file, "X_EALG2 ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_NATT_LOC)
		(void) fprintf(file, "X_NATT_LOC ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_NATT_REM)
		(void) fprintf(file, "X_NATT_REM ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_TUNNEL)
		(void) fprintf(file, "X_TUNNEL ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_NATTED)
		(void) fprintf(file, "X_NATTED ");
	/* END Solaris-specific flags. */

	(void) fprintf(file, ">\n");
}

void
printsatime(FILE *file, int64_t lt, const char *msg, const char *pfx,
    const char *pfx2, boolean_t vflag)
{
	char tbuf[TBUF_SIZE]; /* For strftime() call. */
	const char *tp = tbuf;
	time_t t = lt;
	struct tm res;

	if (t != lt) {
		if (lt > 0)
			t = LONG_MAX;
		else
			t = LONG_MIN;
	}

	if (strftime(tbuf, TBUF_SIZE, NULL, localtime_r(&t, &res)) == 0)
		tp = dgettext(TEXT_DOMAIN, "<time conversion failed>");
	(void) fprintf(file, msg, pfx, tp);
	if (vflag && (pfx2 != NULL))
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s\t(raw time value %" PRIu64 ")\n"), pfx2, lt);
}

/*
 * Print the SA lifetime information.  (An SADB_EXT_LIFETIME_* extension.)
 */
void
print_lifetimes(FILE *file, time_t wallclock, struct sadb_lifetime *current,
    struct sadb_lifetime *hard, struct sadb_lifetime *soft,
    struct sadb_lifetime *idle, boolean_t vflag)
{
	int64_t scratch;
	char *soft_prefix = dgettext(TEXT_DOMAIN, "SLT: ");
	char *hard_prefix = dgettext(TEXT_DOMAIN, "HLT: ");
	char *current_prefix = dgettext(TEXT_DOMAIN, "CLT: ");
	char *idle_prefix = dgettext(TEXT_DOMAIN, "ILT: ");
	char byte_str[BYTE_STR_SIZE]; /* byte lifetime string representation */
	char secs_str[SECS_STR_SIZE]; /* buffer for seconds representation */

	if (current != NULL &&
	    current->sadb_lifetime_len != SADB_8TO64(sizeof (*current))) {
		warnxfp(EFD(file), dgettext(TEXT_DOMAIN,
		    "WARNING: CURRENT lifetime extension length (%u) is bad."),
		    SADB_64TO8(current->sadb_lifetime_len));
	}

	if (hard != NULL &&
	    hard->sadb_lifetime_len != SADB_8TO64(sizeof (*hard))) {
		warnxfp(EFD(file), dgettext(TEXT_DOMAIN,
		    "WARNING: HARD lifetime extension length (%u) is bad."),
		    SADB_64TO8(hard->sadb_lifetime_len));
	}

	if (soft != NULL &&
	    soft->sadb_lifetime_len != SADB_8TO64(sizeof (*soft))) {
		warnxfp(EFD(file), dgettext(TEXT_DOMAIN,
		    "WARNING: SOFT lifetime extension length (%u) is bad."),
		    SADB_64TO8(soft->sadb_lifetime_len));
	}

	if (idle != NULL &&
	    idle->sadb_lifetime_len != SADB_8TO64(sizeof (*idle))) {
		warnxfp(EFD(file), dgettext(TEXT_DOMAIN,
		    "WARNING: IDLE lifetime extension length (%u) is bad."),
		    SADB_64TO8(idle->sadb_lifetime_len));
	}

	(void) fprintf(file, " LT: Lifetime information\n");
	if (current != NULL) {
		/* Express values as current values. */
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%sCurrent lifetime information:\n"),
		    current_prefix);
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s%" PRIu64 " bytes %sprotected, %u allocations "
		    "used.\n"), current_prefix,
		    current->sadb_lifetime_bytes,
		    bytecnt2out(current->sadb_lifetime_bytes, byte_str,
		    sizeof (byte_str), SPC_END),
		    current->sadb_lifetime_allocations);
		printsatime(file, current->sadb_lifetime_addtime,
		    dgettext(TEXT_DOMAIN, "%sSA added at time: %s\n"),
		    current_prefix, current_prefix, vflag);
		if (current->sadb_lifetime_usetime != 0) {
			printsatime(file, current->sadb_lifetime_usetime,
			    dgettext(TEXT_DOMAIN,
			    "%sSA first used at time %s\n"),
			    current_prefix, current_prefix, vflag);
		}
		printsatime(file, wallclock, dgettext(TEXT_DOMAIN,
		    "%sTime now is %s\n"), current_prefix, current_prefix,
		    vflag);
	}

	if (soft != NULL) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%sSoft lifetime information:\n"),
		    soft_prefix);
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s%" PRIu64 " bytes %sof lifetime, %u allocations.\n"),
		    soft_prefix,
		    soft->sadb_lifetime_bytes,
		    bytecnt2out(soft->sadb_lifetime_bytes, byte_str,
		    sizeof (byte_str), SPC_END),
		    soft->sadb_lifetime_allocations);
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s%" PRIu64 " seconds %sof post-add lifetime.\n"),
		    soft_prefix, soft->sadb_lifetime_addtime,
		    secs2out(soft->sadb_lifetime_addtime, secs_str,
		    sizeof (secs_str), SPC_END));
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s%" PRIu64 " seconds %sof post-use lifetime.\n"),
		    soft_prefix, soft->sadb_lifetime_usetime,
		    secs2out(soft->sadb_lifetime_usetime, secs_str,
		    sizeof (secs_str), SPC_END));
		/* If possible, express values as time remaining. */
		if (current != NULL) {
			if (soft->sadb_lifetime_bytes != 0)
				(void) fprintf(file, dgettext(TEXT_DOMAIN, "%s"
				    "%" PRIu64 " bytes %smore can be "
				    "protected.\n"), soft_prefix,
				    (soft->sadb_lifetime_bytes >
				    current->sadb_lifetime_bytes) ?
				    soft->sadb_lifetime_bytes -
				    current->sadb_lifetime_bytes : 0,
				    (soft->sadb_lifetime_bytes >
				    current->sadb_lifetime_bytes) ?
				    bytecnt2out(soft->sadb_lifetime_bytes -
				    current->sadb_lifetime_bytes, byte_str,
				    sizeof (byte_str), SPC_END) : "");
			if (soft->sadb_lifetime_addtime != 0 ||
			    (soft->sadb_lifetime_usetime != 0 &&
			    current->sadb_lifetime_usetime != 0)) {
				int64_t adddelta, usedelta;

				if (soft->sadb_lifetime_addtime != 0) {
					adddelta =
					    current->sadb_lifetime_addtime +
					    soft->sadb_lifetime_addtime -
					    wallclock;
				} else {
					adddelta = TIME_MAX;
				}

				if (soft->sadb_lifetime_usetime != 0 &&
				    current->sadb_lifetime_usetime != 0) {
					usedelta =
					    current->sadb_lifetime_usetime +
					    soft->sadb_lifetime_usetime -
					    wallclock;
				} else {
					usedelta = TIME_MAX;
				}
				(void) fprintf(file, "%s", soft_prefix);
				scratch = MIN(adddelta, usedelta);
				if (scratch >= 0) {
					(void) fprintf(file,
					    dgettext(TEXT_DOMAIN,
					    "Soft expiration occurs in %"
					    PRId64 " seconds%s\n"), scratch,
					    secs2out(scratch, secs_str,
					    sizeof (secs_str), SPC_BEGIN));
				} else {
					(void) fprintf(file,
					    dgettext(TEXT_DOMAIN,
					    "Soft expiration occurred\n"));
				}
				scratch += wallclock;
				printsatime(file, scratch, dgettext(TEXT_DOMAIN,
				    "%sTime of expiration: %s.\n"),
				    soft_prefix, soft_prefix, vflag);
			}
		}
	}

	if (hard != NULL) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%sHard lifetime information:\n"), hard_prefix);
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s%" PRIu64 " bytes %sof lifetime, %u allocations.\n"),
		    hard_prefix,
		    hard->sadb_lifetime_bytes,
		    bytecnt2out(hard->sadb_lifetime_bytes, byte_str,
		    sizeof (byte_str), SPC_END),
		    hard->sadb_lifetime_allocations);
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s%" PRIu64 " seconds %sof post-add lifetime.\n"),
		    hard_prefix, hard->sadb_lifetime_addtime,
		    secs2out(hard->sadb_lifetime_addtime, secs_str,
		    sizeof (secs_str), SPC_END));
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s%" PRIu64 " seconds %sof post-use lifetime.\n"),
		    hard_prefix, hard->sadb_lifetime_usetime,
		    secs2out(hard->sadb_lifetime_usetime, secs_str,
		    sizeof (secs_str), SPC_END));
		/* If possible, express values as time remaining. */
		if (current != NULL) {
			if (hard->sadb_lifetime_bytes != 0)
				(void) fprintf(file, dgettext(TEXT_DOMAIN, "%s"
				    "%" PRIu64 " bytes %smore can be "
				    "protected.\n"), hard_prefix,
				    (hard->sadb_lifetime_bytes >
				    current->sadb_lifetime_bytes) ?
				    hard->sadb_lifetime_bytes -
				    current->sadb_lifetime_bytes : 0,
				    (hard->sadb_lifetime_bytes >
				    current->sadb_lifetime_bytes) ?
				    bytecnt2out(hard->sadb_lifetime_bytes -
				    current->sadb_lifetime_bytes, byte_str,
				    sizeof (byte_str), SPC_END) : "");
			if (hard->sadb_lifetime_addtime != 0 ||
			    (hard->sadb_lifetime_usetime != 0 &&
			    current->sadb_lifetime_usetime != 0)) {
				int64_t adddelta, usedelta;

				if (hard->sadb_lifetime_addtime != 0) {
					adddelta =
					    current->sadb_lifetime_addtime +
					    hard->sadb_lifetime_addtime -
					    wallclock;
				} else {
					adddelta = TIME_MAX;
				}

				if (hard->sadb_lifetime_usetime != 0 &&
				    current->sadb_lifetime_usetime != 0) {
					usedelta =
					    current->sadb_lifetime_usetime +
					    hard->sadb_lifetime_usetime -
					    wallclock;
				} else {
					usedelta = TIME_MAX;
				}
				(void) fprintf(file, "%s", hard_prefix);
				scratch = MIN(adddelta, usedelta);
				if (scratch >= 0) {
					(void) fprintf(file,
					    dgettext(TEXT_DOMAIN,
					    "Hard expiration occurs in %"
					    PRId64 " seconds%s\n"), scratch,
					    secs2out(scratch, secs_str,
					    sizeof (secs_str), SPC_BEGIN));
				} else {
					(void) fprintf(file,
					    dgettext(TEXT_DOMAIN,
					    "Hard expiration occurred\n"));
				}
				scratch += wallclock;
				printsatime(file, scratch, dgettext(TEXT_DOMAIN,
				    "%sTime of expiration: %s.\n"),
				    hard_prefix, hard_prefix, vflag);
			}
		}
	}
	if (idle != NULL) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%sIdle lifetime information:\n"), idle_prefix);
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s%" PRIu64 " seconds %sof post-add lifetime.\n"),
		    idle_prefix, idle->sadb_lifetime_addtime,
		    secs2out(idle->sadb_lifetime_addtime, secs_str,
		    sizeof (secs_str), SPC_END));
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s%" PRIu64 " seconds %sof post-use lifetime.\n"),
		    idle_prefix, idle->sadb_lifetime_usetime,
		    secs2out(idle->sadb_lifetime_usetime, secs_str,
		    sizeof (secs_str), SPC_END));
	}
}

/*
 * Print an SADB_EXT_ADDRESS_* extension.
 */
void
print_address(FILE *file, char *prefix, struct sadb_address *addr,
    boolean_t ignore_nss)
{
	struct protoent *pe;

	(void) fprintf(file, "%s", prefix);
	switch (addr->sadb_address_exttype) {
	case SADB_EXT_ADDRESS_SRC:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "Source address "));
		break;
	case SADB_X_EXT_ADDRESS_INNER_SRC:
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "Inner source address "));
		break;
	case SADB_EXT_ADDRESS_DST:
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "Destination address "));
		break;
	case SADB_X_EXT_ADDRESS_INNER_DST:
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "Inner destination address "));
		break;
	case SADB_X_EXT_ADDRESS_NATT_LOC:
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "NAT-T local address "));
		break;
	case SADB_X_EXT_ADDRESS_NATT_REM:
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "NAT-T remote address "));
		break;
	}

	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    "(proto=%d"), addr->sadb_address_proto);
	if (ignore_nss == B_FALSE) {
		if (addr->sadb_address_proto == 0) {
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "/<unspecified>"));
		} else if ((pe = getprotobynumber(addr->sadb_address_proto))
		    != NULL) {
			(void) fprintf(file, "/%s", pe->p_name);
		} else {
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "/<unknown>"));
		}
	}
	(void) fprintf(file, dgettext(TEXT_DOMAIN, ")\n%s"), prefix);
	(void) dump_sockaddr((struct sockaddr *)(addr + 1),
	    addr->sadb_address_prefixlen, B_FALSE, file, ignore_nss);
}

/*
 * Print an SADB_EXT_KEY extension.
 */
void
print_key(FILE *file, char *prefix, struct sadb_key *key)
{
	(void) fprintf(file, "%s", prefix);

	switch (key->sadb_key_exttype) {
	case SADB_EXT_KEY_AUTH:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "Authentication"));
		break;
	case SADB_EXT_KEY_ENCRYPT:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "Encryption"));
		break;
	}

	(void) fprintf(file, dgettext(TEXT_DOMAIN, " key.\n%s"), prefix);
	(void) dump_key((uint8_t *)(key + 1), key->sadb_key_bits,
	    key->sadb_key_reserved, file, B_TRUE);
	(void) fprintf(file, "\n");
}

/*
 * Print an SADB_EXT_IDENTITY_* extension.
 */
void
print_ident(FILE *file, char *prefix, struct sadb_ident *id)
{
	boolean_t canprint = B_TRUE;

	(void) fprintf(file, "%s", prefix);
	switch (id->sadb_ident_exttype) {
	case SADB_EXT_IDENTITY_SRC:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "Source"));
		break;
	case SADB_EXT_IDENTITY_DST:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "Destination"));
		break;
	}

	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    " identity, uid=%d, type "), id->sadb_ident_id);
	canprint = dump_sadb_idtype(id->sadb_ident_type, file, NULL);
	(void) fprintf(file, "\n%s", prefix);
	if (canprint) {
		(void) fprintf(file, "%s\n", (char *)(id + 1));
	} else {
		print_asn1_name(file, (const unsigned char *)(id + 1),
		    SADB_64TO8(id->sadb_ident_len) - sizeof (sadb_ident_t));
	}
}

/*
 * Convert sadb_sens extension into binary security label.
 */

#include <tsol/label.h>
#include <sys/tsol/tndb.h>
#include <sys/tsol/label_macro.h>

void
ipsec_convert_sens_to_bslabel(const struct sadb_sens *sens, bslabel_t *sl)
{
	uint64_t *bitmap = (uint64_t *)(sens + 1);
	int bitmap_len = SADB_64TO8(sens->sadb_sens_sens_len);

	bsllow(sl);
	LCLASS_SET((_bslabel_impl_t *)sl, sens->sadb_sens_sens_level);
	bcopy(bitmap, &((_bslabel_impl_t *)sl)->compartments,
	    bitmap_len);
}

void
ipsec_convert_bslabel_to_string(bslabel_t *sl, char **plabel)
{
	if (label_to_str(sl, plabel, M_LABEL, DEF_NAMES) != 0) {
		*plabel = strdup(dgettext(TEXT_DOMAIN,
		    "** Label conversion failed **"));
	}
}

void
ipsec_convert_bslabel_to_hex(bslabel_t *sl, char **plabel)
{
	if (label_to_str(sl, plabel, M_INTERNAL, DEF_NAMES) != 0) {
		*plabel = strdup(dgettext(TEXT_DOMAIN,
		    "** Label conversion failed **"));
	}
}

int
ipsec_convert_sl_to_sens(int doi, bslabel_t *sl, sadb_sens_t *sens)
{
	uint8_t *bitmap;
	int sens_len = sizeof (sadb_sens_t) + _C_LEN * 4;


	if (sens == NULL)
		return (sens_len);


	(void) memset(sens, 0, sens_len);

	sens->sadb_sens_exttype = SADB_EXT_SENSITIVITY;
	sens->sadb_sens_len = SADB_8TO64(sens_len);
	sens->sadb_sens_dpd = doi;

	sens->sadb_sens_sens_level = LCLASS(sl);
	sens->sadb_sens_integ_level = 0;
	sens->sadb_sens_sens_len = _C_LEN >> 1;
	sens->sadb_sens_integ_len = 0;

	sens->sadb_x_sens_flags = 0;

	bitmap = (uint8_t *)(sens + 1);
	bcopy(&(((_bslabel_impl_t *)sl)->compartments), bitmap, _C_LEN * 4);

	return (sens_len);
}


/*
 * Print an SADB_SENSITIVITY extension.
 */
void
print_sens(FILE *file, char *prefix, const struct sadb_sens *sens,
    boolean_t ignore_nss)
{
	char *plabel;
	char *hlabel;
	uint64_t *bitmap = (uint64_t *)(sens + 1);
	bslabel_t sl;
	int i;
	int sens_len = sens->sadb_sens_sens_len;
	int integ_len = sens->sadb_sens_integ_len;
	boolean_t inner = (sens->sadb_sens_exttype == SADB_EXT_SENSITIVITY);
	const char *sensname = inner ?
	    dgettext(TEXT_DOMAIN, "Plaintext Sensitivity") :
	    dgettext(TEXT_DOMAIN, "Ciphertext Sensitivity");

	ipsec_convert_sens_to_bslabel(sens, &sl);

	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    "%s%s DPD %d, sens level=%d, integ level=%d, flags=%x\n"),
	    prefix, sensname, sens->sadb_sens_dpd, sens->sadb_sens_sens_level,
	    sens->sadb_sens_integ_level, sens->sadb_x_sens_flags);

	ipsec_convert_bslabel_to_hex(&sl, &hlabel);

	if (ignore_nss) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s %s Label: %s\n"), prefix, sensname, hlabel);

		for (i = 0; i < sens_len; i++, bitmap++)
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "%s %s BM extended word %d 0x%" PRIx64 "\n"),
			    prefix, sensname, i, *bitmap);

	} else {
		ipsec_convert_bslabel_to_string(&sl, &plabel);

		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s %s Label: %s (%s)\n"),
		    prefix, sensname, plabel, hlabel);
		free(plabel);

	}
	free(hlabel);

	bitmap = (uint64_t *)(sens + 1 + sens_len);

	for (i = 0; i < integ_len; i++, bitmap++)
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s Integrity BM extended word %d 0x%" PRIx64 "\n"),
		    prefix, i, *bitmap);
}

/*
 * Print an SADB_EXT_PROPOSAL extension.
 */
void
print_prop(FILE *file, char *prefix, struct sadb_prop *prop)
{
	struct sadb_comb *combs;
	int i, numcombs;

	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    "%sProposal, replay counter = %u.\n"), prefix,
	    prop->sadb_prop_replay);

	numcombs = prop->sadb_prop_len - SADB_8TO64(sizeof (*prop));
	numcombs /= SADB_8TO64(sizeof (*combs));

	combs = (struct sadb_comb *)(prop + 1);

	for (i = 0; i < numcombs; i++) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s Combination #%u "), prefix, i + 1);
		if (combs[i].sadb_comb_auth != SADB_AALG_NONE) {
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "Authentication = "));
			(void) dump_aalg(combs[i].sadb_comb_auth, file);
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "  minbits=%u, maxbits=%u.\n%s "),
			    combs[i].sadb_comb_auth_minbits,
			    combs[i].sadb_comb_auth_maxbits, prefix);
		}

		if (combs[i].sadb_comb_encrypt != SADB_EALG_NONE) {
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "Encryption = "));
			(void) dump_ealg(combs[i].sadb_comb_encrypt, file);
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "  minbits=%u, maxbits=%u.\n%s "),
			    combs[i].sadb_comb_encrypt_minbits,
			    combs[i].sadb_comb_encrypt_maxbits, prefix);
		}

		(void) fprintf(file, dgettext(TEXT_DOMAIN, "HARD: "));
		if (combs[i].sadb_comb_hard_allocations)
			(void) fprintf(file, dgettext(TEXT_DOMAIN, "alloc=%u "),
			    combs[i].sadb_comb_hard_allocations);
		if (combs[i].sadb_comb_hard_bytes)
			(void) fprintf(file, dgettext(TEXT_DOMAIN, "bytes=%"
			    PRIu64 " "), combs[i].sadb_comb_hard_bytes);
		if (combs[i].sadb_comb_hard_addtime)
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "post-add secs=%" PRIu64 " "),
			    combs[i].sadb_comb_hard_addtime);
		if (combs[i].sadb_comb_hard_usetime)
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "post-use secs=%" PRIu64 ""),
			    combs[i].sadb_comb_hard_usetime);

		(void) fprintf(file, dgettext(TEXT_DOMAIN, "\n%s SOFT: "),
		    prefix);
		if (combs[i].sadb_comb_soft_allocations)
			(void) fprintf(file, dgettext(TEXT_DOMAIN, "alloc=%u "),
			    combs[i].sadb_comb_soft_allocations);
		if (combs[i].sadb_comb_soft_bytes)
			(void) fprintf(file, dgettext(TEXT_DOMAIN, "bytes=%"
			    PRIu64 " "), combs[i].sadb_comb_soft_bytes);
		if (combs[i].sadb_comb_soft_addtime)
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "post-add secs=%" PRIu64 " "),
			    combs[i].sadb_comb_soft_addtime);
		if (combs[i].sadb_comb_soft_usetime)
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "post-use secs=%" PRIu64 ""),
			    combs[i].sadb_comb_soft_usetime);
		(void) fprintf(file, "\n");
	}
}

/*
 * Print an extended proposal (SADB_X_EXT_EPROP).
 */
void
print_eprop(FILE *file, char *prefix, struct sadb_prop *eprop)
{
	uint64_t *sofar;
	struct sadb_x_ecomb *ecomb;
	struct sadb_x_algdesc *algdesc;
	int i, j;

	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    "%sExtended Proposal, replay counter = %u, "), prefix,
	    eprop->sadb_prop_replay);
	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    "number of combinations = %u.\n"), eprop->sadb_x_prop_numecombs);

	sofar = (uint64_t *)(eprop + 1);
	ecomb = (struct sadb_x_ecomb *)sofar;

	for (i = 0; i < eprop->sadb_x_prop_numecombs; ) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%s Extended combination #%u:\n"), prefix, ++i);

		(void) fprintf(file, dgettext(TEXT_DOMAIN, "%s HARD: "),
		    prefix);
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "alloc=%u, "),
		    ecomb->sadb_x_ecomb_hard_allocations);
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "bytes=%" PRIu64
		    ", "), ecomb->sadb_x_ecomb_hard_bytes);
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "post-add secs=%"
		    PRIu64 ", "), ecomb->sadb_x_ecomb_hard_addtime);
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "post-use secs=%"
		    PRIu64 "\n"), ecomb->sadb_x_ecomb_hard_usetime);

		(void) fprintf(file, dgettext(TEXT_DOMAIN, "%s SOFT: "),
		    prefix);
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "alloc=%u, "),
		    ecomb->sadb_x_ecomb_soft_allocations);
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "bytes=%" PRIu64 ", "), ecomb->sadb_x_ecomb_soft_bytes);
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "post-add secs=%" PRIu64 ", "),
		    ecomb->sadb_x_ecomb_soft_addtime);
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "post-use secs=%"
		    PRIu64 "\n"), ecomb->sadb_x_ecomb_soft_usetime);

		sofar = (uint64_t *)(ecomb + 1);
		algdesc = (struct sadb_x_algdesc *)sofar;

		for (j = 0; j < ecomb->sadb_x_ecomb_numalgs; ) {
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "%s Alg #%u "), prefix, ++j);
			switch (algdesc->sadb_x_algdesc_satype) {
			case SADB_SATYPE_ESP:
				(void) fprintf(file, dgettext(TEXT_DOMAIN,
				    "for ESP "));
				break;
			case SADB_SATYPE_AH:
				(void) fprintf(file, dgettext(TEXT_DOMAIN,
				    "for AH "));
				break;
			default:
				(void) fprintf(file, dgettext(TEXT_DOMAIN,
				    "for satype=%d "),
				    algdesc->sadb_x_algdesc_satype);
			}
			switch (algdesc->sadb_x_algdesc_algtype) {
			case SADB_X_ALGTYPE_CRYPT:
				(void) fprintf(file, dgettext(TEXT_DOMAIN,
				    "Encryption = "));
				(void) dump_ealg(algdesc->sadb_x_algdesc_alg,
				    file);
				break;
			case SADB_X_ALGTYPE_AUTH:
				(void) fprintf(file, dgettext(TEXT_DOMAIN,
				    "Authentication = "));
				(void) dump_aalg(algdesc->sadb_x_algdesc_alg,
				    file);
				break;
			default:
				(void) fprintf(file, dgettext(TEXT_DOMAIN,
				    "algtype(%d) = alg(%d)"),
				    algdesc->sadb_x_algdesc_algtype,
				    algdesc->sadb_x_algdesc_alg);
				break;
			}

			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "  minbits=%u, maxbits=%u, saltbits=%u\n"),
			    algdesc->sadb_x_algdesc_minbits,
			    algdesc->sadb_x_algdesc_maxbits,
			    algdesc->sadb_x_algdesc_reserved);

			sofar = (uint64_t *)(++algdesc);
		}
		ecomb = (struct sadb_x_ecomb *)sofar;
	}
}

/*
 * Print an SADB_EXT_SUPPORTED extension.
 */
void
print_supp(FILE *file, char *prefix, struct sadb_supported *supp)
{
	struct sadb_alg *algs;
	int i, numalgs;

	(void) fprintf(file, dgettext(TEXT_DOMAIN, "%sSupported "), prefix);
	switch (supp->sadb_supported_exttype) {
	case SADB_EXT_SUPPORTED_AUTH:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "authentication"));
		break;
	case SADB_EXT_SUPPORTED_ENCRYPT:
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "encryption"));
		break;
	}
	(void) fprintf(file, dgettext(TEXT_DOMAIN, " algorithms.\n"));

	algs = (struct sadb_alg *)(supp + 1);
	numalgs = supp->sadb_supported_len - SADB_8TO64(sizeof (*supp));
	numalgs /= SADB_8TO64(sizeof (*algs));
	for (i = 0; i < numalgs; i++) {
		uint16_t exttype = supp->sadb_supported_exttype;

		(void) fprintf(file, "%s", prefix);
		switch (exttype) {
		case SADB_EXT_SUPPORTED_AUTH:
			(void) dump_aalg(algs[i].sadb_alg_id, file);
			break;
		case SADB_EXT_SUPPORTED_ENCRYPT:
			(void) dump_ealg(algs[i].sadb_alg_id, file);
			break;
		}
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    " minbits=%u, maxbits=%u, ivlen=%u, saltbits=%u"),
		    algs[i].sadb_alg_minbits, algs[i].sadb_alg_maxbits,
		    algs[i].sadb_alg_ivlen, algs[i].sadb_x_alg_saltbits);
		if (exttype == SADB_EXT_SUPPORTED_ENCRYPT)
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    ", increment=%u"), algs[i].sadb_x_alg_increment);
		(void) fprintf(file, dgettext(TEXT_DOMAIN, ".\n"));
	}
}

/*
 * Print an SADB_EXT_SPIRANGE extension.
 */
void
print_spirange(FILE *file, char *prefix, struct sadb_spirange *range)
{
	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    "%sSPI Range, min=0x%x, max=0x%x\n"), prefix,
	    htonl(range->sadb_spirange_min),
	    htonl(range->sadb_spirange_max));
}

/*
 * Print an SADB_X_EXT_KM_COOKIE extension.
 */

void
print_kmc(FILE *file, char *prefix, struct sadb_x_kmc *kmc)
{
	char *cookie_label;

	switch (kmc->sadb_x_kmc_proto) {
	case SADB_X_KMP_IKE:
		cookie_label = kmc_lookup_by_cookie(kmc->sadb_x_kmc_cookie);
		if (cookie_label == NULL)
			cookie_label =
			    dgettext(TEXT_DOMAIN, "<Label not found.>");
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "%sProtocol %u, cookie=\"%s\" (%u)\n"), prefix,
		    kmc->sadb_x_kmc_proto, cookie_label,
		    kmc->sadb_x_kmc_cookie);
		return;
	case SADB_X_KMP_MANUAL:
		cookie_label = dgettext(TEXT_DOMAIN, "Manual SA with cookie");
		break;
	/* case SADB_X_KMP_IKEV2: */
	default:
		cookie_label =
		    dgettext(TEXT_DOMAIN, "<unknown KM protocol>");
		break;
	}

	/* XXX KEBE ASKS... htonll() on generic kmc_cookie? */
	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    "%sProtocol %u, cookie=\"%s\" (0x%"PRIx64"/%"PRIu64")\n"),
	    prefix, kmc->sadb_x_kmc_proto, cookie_label,
	    kmc->sadb_x_kmc_cookie64, kmc->sadb_x_kmc_cookie64);
}

/*
 * Print an SADB_X_EXT_REPLAY_CTR extension.
 */

void
print_replay(FILE *file, char *prefix, sadb_x_replay_ctr_t *repl)
{
	(void) fprintf(file, dgettext(TEXT_DOMAIN,
	    "%sReplay Value "), prefix);
	if ((repl->sadb_x_rc_replay32 == 0) &&
	    (repl->sadb_x_rc_replay64 == 0)) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN,
		    "<Value not found.>"));
	}
	/*
	 * We currently do not support a 64-bit replay value.
	 * RFC 4301 will require one, however, and we have a field
	 * in place when 4301 is built.
	 */
	(void) fprintf(file, "% " PRIu64 "\n",
	    ((repl->sadb_x_rc_replay32 == 0) ?
	    repl->sadb_x_rc_replay64 : repl->sadb_x_rc_replay32));
}
/*
 * Print an SADB_X_EXT_PAIR extension.
 */
static void
print_pair(FILE *file, char *prefix, struct sadb_x_pair *pair)
{
	(void) fprintf(file, dgettext(TEXT_DOMAIN, "%sPaired with spi=0x%x\n"),
	    prefix, ntohl(pair->sadb_x_pair_spi));
}

/*
 * Take a PF_KEY message pointed to buffer and print it.  Useful for DUMP
 * and GET.
 */
void
print_samsg(FILE *file, uint64_t *buffer, boolean_t want_timestamp,
    boolean_t vflag, boolean_t ignore_nss)
{
	uint64_t *current;
	struct sadb_msg *samsg = (struct sadb_msg *)buffer;
	struct sadb_ext *ext;
	struct sadb_lifetime *currentlt = NULL, *hardlt = NULL, *softlt = NULL;
	struct sadb_lifetime *idlelt = NULL;
	int i;
	time_t wallclock;

	(void) time(&wallclock);

	print_sadb_msg(file, samsg, want_timestamp ? wallclock : 0, vflag);
	current = (uint64_t *)(samsg + 1);
	while (current - buffer < samsg->sadb_msg_len) {
		int lenbytes;

		ext = (struct sadb_ext *)current;
		lenbytes = SADB_64TO8(ext->sadb_ext_len);
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
			print_sa(file, dgettext(TEXT_DOMAIN,
			    "SA: "), (struct sadb_sa *)current);
			break;
		/*
		 * Pluck out lifetimes and print them at the end.  This is
		 * to show relative lifetimes.
		 */
		case SADB_EXT_LIFETIME_CURRENT:
			currentlt = (struct sadb_lifetime *)current;
			break;
		case SADB_EXT_LIFETIME_HARD:
			hardlt = (struct sadb_lifetime *)current;
			break;
		case SADB_EXT_LIFETIME_SOFT:
			softlt = (struct sadb_lifetime *)current;
			break;
		case SADB_X_EXT_LIFETIME_IDLE:
			idlelt = (struct sadb_lifetime *)current;
			break;

		case SADB_EXT_ADDRESS_SRC:
			print_address(file, dgettext(TEXT_DOMAIN, "SRC: "),
			    (struct sadb_address *)current, ignore_nss);
			break;
		case SADB_X_EXT_ADDRESS_INNER_SRC:
			print_address(file, dgettext(TEXT_DOMAIN, "INS: "),
			    (struct sadb_address *)current, ignore_nss);
			break;
		case SADB_EXT_ADDRESS_DST:
			print_address(file, dgettext(TEXT_DOMAIN, "DST: "),
			    (struct sadb_address *)current, ignore_nss);
			break;
		case SADB_X_EXT_ADDRESS_INNER_DST:
			print_address(file, dgettext(TEXT_DOMAIN, "IND: "),
			    (struct sadb_address *)current, ignore_nss);
			break;
		case SADB_EXT_KEY_AUTH:
			print_key(file, dgettext(TEXT_DOMAIN,
			    "AKY: "), (struct sadb_key *)current);
			break;
		case SADB_EXT_KEY_ENCRYPT:
			print_key(file, dgettext(TEXT_DOMAIN,
			    "EKY: "), (struct sadb_key *)current);
			break;
		case SADB_EXT_IDENTITY_SRC:
			print_ident(file, dgettext(TEXT_DOMAIN, "SID: "),
			    (struct sadb_ident *)current);
			break;
		case SADB_EXT_IDENTITY_DST:
			print_ident(file, dgettext(TEXT_DOMAIN, "DID: "),
			    (struct sadb_ident *)current);
			break;
		case SADB_EXT_SENSITIVITY:
			print_sens(file, dgettext(TEXT_DOMAIN, "SNS: "),
			    (struct sadb_sens *)current, ignore_nss);
			break;
		case SADB_EXT_PROPOSAL:
			print_prop(file, dgettext(TEXT_DOMAIN, "PRP: "),
			    (struct sadb_prop *)current);
			break;
		case SADB_EXT_SUPPORTED_AUTH:
			print_supp(file, dgettext(TEXT_DOMAIN, "SUA: "),
			    (struct sadb_supported *)current);
			break;
		case SADB_EXT_SUPPORTED_ENCRYPT:
			print_supp(file, dgettext(TEXT_DOMAIN, "SUE: "),
			    (struct sadb_supported *)current);
			break;
		case SADB_EXT_SPIRANGE:
			print_spirange(file, dgettext(TEXT_DOMAIN, "SPR: "),
			    (struct sadb_spirange *)current);
			break;
		case SADB_X_EXT_EPROP:
			print_eprop(file, dgettext(TEXT_DOMAIN, "EPR: "),
			    (struct sadb_prop *)current);
			break;
		case SADB_X_EXT_KM_COOKIE:
			print_kmc(file, dgettext(TEXT_DOMAIN, "KMC: "),
			    (struct sadb_x_kmc *)current);
			break;
		case SADB_X_EXT_ADDRESS_NATT_REM:
			print_address(file, dgettext(TEXT_DOMAIN, "NRM: "),
			    (struct sadb_address *)current, ignore_nss);
			break;
		case SADB_X_EXT_ADDRESS_NATT_LOC:
			print_address(file, dgettext(TEXT_DOMAIN, "NLC: "),
			    (struct sadb_address *)current, ignore_nss);
			break;
		case SADB_X_EXT_PAIR:
			print_pair(file, dgettext(TEXT_DOMAIN, "OTH: "),
			    (struct sadb_x_pair *)current);
			break;
		case SADB_X_EXT_OUTER_SENS:
			print_sens(file, dgettext(TEXT_DOMAIN, "OSN: "),
			    (struct sadb_sens *)current, ignore_nss);
			break;
		case SADB_X_EXT_REPLAY_VALUE:
			(void) print_replay(file, dgettext(TEXT_DOMAIN,
			    "RPL: "), (sadb_x_replay_ctr_t *)current);
			break;
		default:
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "UNK: Unknown ext. %d, len %d.\n"),
			    ext->sadb_ext_type, lenbytes);
			for (i = 0; i < ext->sadb_ext_len; i++)
				(void) fprintf(file, dgettext(TEXT_DOMAIN,
				    "UNK: 0x%" PRIx64 "\n"),
				    ((uint64_t *)ext)[i]);
			break;
		}
		current += (lenbytes == 0) ?
		    SADB_8TO64(sizeof (struct sadb_ext)) : ext->sadb_ext_len;
	}
	/*
	 * Print lifetimes NOW.
	 */
	if (currentlt != NULL || hardlt != NULL || softlt != NULL ||
	    idlelt != NULL)
		print_lifetimes(file, wallclock, currentlt, hardlt,
		    softlt, idlelt, vflag);

	if (current - buffer != samsg->sadb_msg_len) {
		warnxfp(EFD(file), dgettext(TEXT_DOMAIN,
		    "WARNING: insufficient buffer space or corrupt message."));
	}

	(void) fflush(file);	/* Make sure our message is out there. */
}

/*
 * save_XXX functions are used when "saving" the SA tables to either a
 * file or standard output.  They use the dump_XXX functions where needed,
 * but mostly they use the rparseXXX functions.
 */

/*
 * Print save information for a lifetime extension.
 *
 * NOTE : It saves the lifetime in absolute terms.  For example, if you
 * had a hard_usetime of 60 seconds, you'll save it as 60 seconds, even though
 * there may have been 59 seconds burned off the clock.
 */
boolean_t
save_lifetime(struct sadb_lifetime *lifetime, FILE *ofile)
{
	char *prefix;

	switch (lifetime->sadb_lifetime_exttype) {
	case SADB_EXT_LIFETIME_HARD:
		prefix = "hard";
		break;
	case SADB_EXT_LIFETIME_SOFT:
		prefix = "soft";
		break;
	case SADB_X_EXT_LIFETIME_IDLE:
		prefix = "idle";
		break;
	}

	if (putc('\t', ofile) == EOF)
		return (B_FALSE);

	if (lifetime->sadb_lifetime_allocations != 0 && fprintf(ofile,
	    "%s_alloc %u ", prefix, lifetime->sadb_lifetime_allocations) < 0)
		return (B_FALSE);

	if (lifetime->sadb_lifetime_bytes != 0 && fprintf(ofile,
	    "%s_bytes %" PRIu64 " ", prefix, lifetime->sadb_lifetime_bytes) < 0)
		return (B_FALSE);

	if (lifetime->sadb_lifetime_addtime != 0 && fprintf(ofile,
	    "%s_addtime %" PRIu64 " ", prefix,
	    lifetime->sadb_lifetime_addtime) < 0)
		return (B_FALSE);

	if (lifetime->sadb_lifetime_usetime != 0 && fprintf(ofile,
	    "%s_usetime %" PRIu64 " ", prefix,
	    lifetime->sadb_lifetime_usetime) < 0)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Print save information for an address extension.
 */
boolean_t
save_address(struct sadb_address *addr, FILE *ofile)
{
	char *printable_addr, buf[INET6_ADDRSTRLEN];
	const char *prefix, *pprefix;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(addr + 1);
	struct sockaddr_in *sin = (struct sockaddr_in *)sin6;
	int af = sin->sin_family;

	/*
	 * Address-family reality check.
	 */
	if (af != AF_INET6 && af != AF_INET)
		return (B_FALSE);

	switch (addr->sadb_address_exttype) {
	case SADB_EXT_ADDRESS_SRC:
		prefix = "src";
		pprefix = "sport";
		break;
	case SADB_X_EXT_ADDRESS_INNER_SRC:
		prefix = "isrc";
		pprefix = "isport";
		break;
	case SADB_EXT_ADDRESS_DST:
		prefix = "dst";
		pprefix = "dport";
		break;
	case SADB_X_EXT_ADDRESS_INNER_DST:
		prefix = "idst";
		pprefix = "idport";
		break;
	case SADB_X_EXT_ADDRESS_NATT_LOC:
		prefix = "nat_loc ";
		pprefix = "nat_lport";
		break;
	case SADB_X_EXT_ADDRESS_NATT_REM:
		prefix = "nat_rem ";
		pprefix = "nat_rport";
		break;
	}

	if (fprintf(ofile, "    %s ", prefix) < 0)
		return (B_FALSE);

	/*
	 * Do not do address-to-name translation, given that we live in
	 * an age of names that explode into many addresses.
	 */
	printable_addr = (char *)inet_ntop(af,
	    (af == AF_INET) ? (char *)&sin->sin_addr : (char *)&sin6->sin6_addr,
	    buf, sizeof (buf));
	if (printable_addr == NULL)
		printable_addr = "Invalid IP address.";
	if (fprintf(ofile, "%s", printable_addr) < 0)
		return (B_FALSE);
	if (addr->sadb_address_prefixlen != 0 &&
	    !((addr->sadb_address_prefixlen == 32 && af == AF_INET) ||
	    (addr->sadb_address_prefixlen == 128 && af == AF_INET6))) {
		if (fprintf(ofile, "/%d", addr->sadb_address_prefixlen) < 0)
			return (B_FALSE);
	}

	/*
	 * The port is in the same position for struct sockaddr_in and
	 * struct sockaddr_in6.  We exploit that property here.
	 */
	if ((pprefix != NULL) && (sin->sin_port != 0))
		(void) fprintf(ofile, " %s %d", pprefix, ntohs(sin->sin_port));

	return (B_TRUE);
}

/*
 * Print save information for a key extension. Returns whether writing
 * to the specified output file was successful or not.
 */
boolean_t
save_key(struct sadb_key *key, FILE *ofile)
{
	char *prefix;

	if (putc('\t', ofile) == EOF)
		return (B_FALSE);

	prefix = (key->sadb_key_exttype == SADB_EXT_KEY_AUTH) ? "auth" : "encr";

	if (fprintf(ofile, "%skey ", prefix) < 0)
		return (B_FALSE);

	if (dump_key((uint8_t *)(key + 1), key->sadb_key_bits,
	    key->sadb_key_reserved, ofile, B_FALSE) == -1)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Print save information for an identity extension.
 */
boolean_t
save_ident(struct sadb_ident *ident, FILE *ofile)
{
	char *prefix;

	if (putc('\t', ofile) == EOF)
		return (B_FALSE);

	prefix = (ident->sadb_ident_exttype == SADB_EXT_IDENTITY_SRC) ? "src" :
	    "dst";

	if (fprintf(ofile, "%sidtype %s ", prefix,
	    rparseidtype(ident->sadb_ident_type)) < 0)
		return (B_FALSE);

	if (ident->sadb_ident_type == SADB_X_IDENTTYPE_DN ||
	    ident->sadb_ident_type == SADB_X_IDENTTYPE_GN) {
		if (fprintf(ofile, dgettext(TEXT_DOMAIN,
		    "<can-not-print>")) < 0)
			return (B_FALSE);
	} else {
		if (fprintf(ofile, "%s", (char *)(ident + 1)) < 0)
			return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
save_sens(struct sadb_sens *sens, FILE *ofile)
{
	char *prefix;
	char *hlabel;
	bslabel_t sl;

	if (putc('\t', ofile) == EOF)
		return (B_FALSE);

	if (sens->sadb_sens_exttype == SADB_EXT_SENSITIVITY)
		prefix = "label";
	else if ((sens->sadb_x_sens_flags & SADB_X_SENS_IMPLICIT) == 0)
		prefix = "outer-label";
	else
		prefix = "implicit-label";

	ipsec_convert_sens_to_bslabel(sens, &sl);
	ipsec_convert_bslabel_to_hex(&sl, &hlabel);

	if (fprintf(ofile, "%s %s ", prefix, hlabel) < 0) {
		free(hlabel);
		return (B_FALSE);
	}
	free(hlabel);

	return (B_TRUE);
}

/*
 * "Save" a security association to an output file.
 *
 * NOTE the lack of calls to dgettext() because I'm outputting parseable stuff.
 * ALSO NOTE that if you change keywords (see parsecmd()), you'll have to
 * change them here as well.
 */
void
save_assoc(uint64_t *buffer, FILE *ofile)
{
	int terrno;
	boolean_t seen_proto = B_FALSE, seen_iproto = B_FALSE;
	uint64_t *current;
	struct sadb_address *addr;
	struct sadb_x_replay_ctr *repl;
	struct sadb_msg *samsg = (struct sadb_msg *)buffer;
	struct sadb_ext *ext;

#define	tidyup() \
	terrno = errno; (void) fclose(ofile); errno = terrno; \
	interactive = B_FALSE

#define	savenl() if (fputs(" \\\n", ofile) == EOF) \
	{ bail(dgettext(TEXT_DOMAIN, "savenl")); }

	if (fputs("# begin assoc\n", ofile) == EOF)
		bail(dgettext(TEXT_DOMAIN,
		    "save_assoc: Opening comment of SA"));
	if (fprintf(ofile, "add %s ", rparsesatype(samsg->sadb_msg_satype)) < 0)
		bail(dgettext(TEXT_DOMAIN, "save_assoc: First line of SA"));
	savenl();

	current = (uint64_t *)(samsg + 1);
	while (current - buffer < samsg->sadb_msg_len) {
		struct sadb_sa *assoc;

		ext = (struct sadb_ext *)current;
		addr = (struct sadb_address *)ext;  /* Just in case... */
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
			assoc = (struct sadb_sa *)ext;
			if (assoc->sadb_sa_state != SADB_SASTATE_MATURE) {
				if (fprintf(ofile, "# WARNING: SA was dying "
				    "or dead.\n") < 0) {
					tidyup();
					bail(dgettext(TEXT_DOMAIN,
					    "save_assoc: fprintf not mature"));
				}
			}
			if (fprintf(ofile, "    spi 0x%x ",
			    ntohl(assoc->sadb_sa_spi)) < 0) {
				tidyup();
				bail(dgettext(TEXT_DOMAIN,
				    "save_assoc: fprintf spi"));
			}
			if (assoc->sadb_sa_encrypt != SADB_EALG_NONE) {
				if (fprintf(ofile, "encr_alg %s ",
				    rparsealg(assoc->sadb_sa_encrypt,
				    IPSEC_PROTO_ESP)) < 0) {
					tidyup();
					bail(dgettext(TEXT_DOMAIN,
					    "save_assoc: fprintf encrypt"));
				}
			}
			if (assoc->sadb_sa_auth != SADB_AALG_NONE) {
				if (fprintf(ofile, "auth_alg %s ",
				    rparsealg(assoc->sadb_sa_auth,
				    IPSEC_PROTO_AH)) < 0) {
					tidyup();
					bail(dgettext(TEXT_DOMAIN,
					    "save_assoc: fprintf auth"));
				}
			}
			if (fprintf(ofile, "replay %d ",
			    assoc->sadb_sa_replay) < 0) {
				tidyup();
				bail(dgettext(TEXT_DOMAIN,
				    "save_assoc: fprintf replay"));
			}
			if (assoc->sadb_sa_flags & (SADB_X_SAFLAGS_NATT_LOC |
			    SADB_X_SAFLAGS_NATT_REM)) {
				if (fprintf(ofile, "encap udp") < 0) {
					tidyup();
					bail(dgettext(TEXT_DOMAIN,
					    "save_assoc: fprintf encap"));
				}
			}
			savenl();
			break;
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
		case SADB_X_EXT_LIFETIME_IDLE:
			if (!save_lifetime((struct sadb_lifetime *)ext,
			    ofile)) {
				tidyup();
				bail(dgettext(TEXT_DOMAIN, "save_lifetime"));
			}
			savenl();
			break;
		case SADB_X_EXT_ADDRESS_INNER_SRC:
		case SADB_X_EXT_ADDRESS_INNER_DST:
			if (!seen_iproto && addr->sadb_address_proto) {
				(void) fprintf(ofile, "    iproto %d",
				    addr->sadb_address_proto);
				savenl();
				seen_iproto = B_TRUE;
			}
			goto skip_srcdst;  /* Hack to avoid cases below... */
			/* FALLTHRU */
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
			if (!seen_proto && addr->sadb_address_proto) {
				(void) fprintf(ofile, "    proto %d",
				    addr->sadb_address_proto);
				savenl();
				seen_proto = B_TRUE;
			}
			/* FALLTHRU */
		case SADB_X_EXT_ADDRESS_NATT_REM:
		case SADB_X_EXT_ADDRESS_NATT_LOC:
skip_srcdst:
			if (!save_address(addr, ofile)) {
				tidyup();
				bail(dgettext(TEXT_DOMAIN, "save_address"));
			}
			savenl();
			break;
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
			if (!save_key((struct sadb_key *)ext, ofile)) {
				tidyup();
				bail(dgettext(TEXT_DOMAIN, "save_address"));
			}
			savenl();
			break;
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
			if (!save_ident((struct sadb_ident *)ext, ofile)) {
				tidyup();
				bail(dgettext(TEXT_DOMAIN, "save_address"));
			}
			savenl();
			break;
		case SADB_X_EXT_REPLAY_VALUE:
			repl = (sadb_x_replay_ctr_t *)ext;
			if ((repl->sadb_x_rc_replay32 == 0) &&
			    (repl->sadb_x_rc_replay64 == 0)) {
				tidyup();
				bail(dgettext(TEXT_DOMAIN, "Replay Value"));
			}
			if (fprintf(ofile, "replay_value %" PRIu64 "",
			    (repl->sadb_x_rc_replay32 == 0 ?
			    repl->sadb_x_rc_replay64 :
			    repl->sadb_x_rc_replay32)) < 0) {
				tidyup();
				bail(dgettext(TEXT_DOMAIN,
				    "save_assoc: fprintf replay value"));
			}
			savenl();
			break;
		case SADB_EXT_SENSITIVITY:
		case SADB_X_EXT_OUTER_SENS:
			if (!save_sens((struct sadb_sens *)ext, ofile)) {
				tidyup();
				bail(dgettext(TEXT_DOMAIN, "save_sens"));
			}
			savenl();
			break;
		default:
			/* Skip over irrelevant extensions. */
			break;
		}
		current += ext->sadb_ext_len;
	}

	if (fputs(dgettext(TEXT_DOMAIN, "\n# end assoc\n\n"), ofile) == EOF) {
		tidyup();
		bail(dgettext(TEXT_DOMAIN, "save_assoc: last fputs"));
	}
}

/*
 * Open the output file for the "save" command.
 */
FILE *
opensavefile(char *filename)
{
	int fd;
	FILE *retval;
	struct stat buf;

	/*
	 * If the user specifies "-" or doesn't give a filename, then
	 * dump to stdout.  Make sure to document the dangers of files
	 * that are NFS, directing your output to strange places, etc.
	 */
	if (filename == NULL || strcmp("-", filename) == 0)
		return (stdout);

	/*
	 * open the file with the create bits set.  Since I check for
	 * real UID == root in main(), I won't worry about the ownership
	 * problem.
	 */
	fd = open(filename, O_WRONLY | O_EXCL | O_CREAT | O_TRUNC, S_IRUSR);
	if (fd == -1) {
		if (errno != EEXIST)
			bail_msg("%s %s: %s", filename, dgettext(TEXT_DOMAIN,
			    "open error"),
			    strerror(errno));
		fd = open(filename, O_WRONLY | O_TRUNC, 0);
		if (fd == -1)
			bail_msg("%s %s: %s", filename, dgettext(TEXT_DOMAIN,
			    "open error"), strerror(errno));
		if (fstat(fd, &buf) == -1) {
			(void) close(fd);
			bail_msg("%s fstat: %s", filename, strerror(errno));
		}
		if (S_ISREG(buf.st_mode) &&
		    ((buf.st_mode & S_IAMB) != S_IRUSR)) {
			warnx(dgettext(TEXT_DOMAIN,
			    "WARNING: Save file already exists with "
			    "permission %o."), buf.st_mode & S_IAMB);
			warnx(dgettext(TEXT_DOMAIN,
			    "Normal users may be able to read IPsec "
			    "keying material."));
		}
	}

	/* Okay, we have an FD.  Assign it to a stdio FILE pointer. */
	retval = fdopen(fd, "w");
	if (retval == NULL) {
		(void) close(fd);
		bail_msg("%s %s: %s", filename, dgettext(TEXT_DOMAIN,
		    "fdopen error"), strerror(errno));
	}
	return (retval);
}

const char *
do_inet_ntop(const void *addr, char *cp, size_t size)
{
	boolean_t isv4;
	struct in6_addr *inaddr6 = (struct in6_addr *)addr;
	struct in_addr inaddr;

	if ((isv4 = IN6_IS_ADDR_V4MAPPED(inaddr6)) == B_TRUE) {
		IN6_V4MAPPED_TO_INADDR(inaddr6, &inaddr);
	}

	return (inet_ntop(isv4 ? AF_INET : AF_INET6,
	    isv4 ? (void *)&inaddr : inaddr6, cp, size));
}

char numprint[NBUF_SIZE];

/*
 * Parse and reverse parse a specific SA type (AH, ESP, etc.).
 */
static struct typetable {
	char *type;
	int token;
} type_table[] = {
	{"all", SADB_SATYPE_UNSPEC},
	{"ah",  SADB_SATYPE_AH},
	{"esp", SADB_SATYPE_ESP},
	/* PF_KEY NOTE:  More to come if net/pfkeyv2.h gets updated. */
	{NULL, 0}	/* Token value is irrelevant for this entry. */
};

char *
rparsesatype(int type)
{
	struct typetable *tt = type_table;

	while (tt->type != NULL && type != tt->token)
		tt++;

	if (tt->type == NULL) {
		(void) snprintf(numprint, NBUF_SIZE, "%d", type);
	} else {
		return (tt->type);
	}

	return (numprint);
}


/*
 * Return a string containing the name of the specified numerical algorithm
 * identifier.
 */
char *
rparsealg(uint8_t alg, int proto_num)
{
	static struct ipsecalgent *holder = NULL; /* we're single-threaded */

	if (holder != NULL)
		freeipsecalgent(holder);

	holder = getipsecalgbynum(alg, proto_num, NULL);
	if (holder == NULL) {
		(void) snprintf(numprint, NBUF_SIZE, "%d", alg);
		return (numprint);
	}

	return (*(holder->a_names));
}

/*
 * Parse and reverse parse out a source/destination ID type.
 */
static struct idtypes {
	char *idtype;
	uint8_t retval;
} idtypes[] = {
	{"prefix",	SADB_IDENTTYPE_PREFIX},
	{"fqdn",	SADB_IDENTTYPE_FQDN},
	{"domain",	SADB_IDENTTYPE_FQDN},
	{"domainname",	SADB_IDENTTYPE_FQDN},
	{"user_fqdn",	SADB_IDENTTYPE_USER_FQDN},
	{"mailbox",	SADB_IDENTTYPE_USER_FQDN},
	{"der_dn",	SADB_X_IDENTTYPE_DN},
	{"der_gn",	SADB_X_IDENTTYPE_GN},
	{NULL,		0}
};

char *
rparseidtype(uint16_t type)
{
	struct idtypes *idp;

	for (idp = idtypes; idp->idtype != NULL; idp++) {
		if (type == idp->retval)
			return (idp->idtype);
	}

	(void) snprintf(numprint, NBUF_SIZE, "%d", type);
	return (numprint);
}

/*
 * This is a general purpose exit function, calling functions can specify an
 * error type. If the command calling this function was started by smf(5) the
 * error type could be used as a hint to the restarter. In the future this
 * function could be used to do something more intelligent with a process that
 * encounters an error. If exit() is called with an error code other than those
 * defined by smf(5), the program will just get restarted. Unless restarting
 * is likely to resolve the error condition, its probably sensible to just
 * log the error and keep running.
 *
 * The SERVICE_* exit_types mean nothing if the command was run from the
 * command line, just exit(). There are two special cases:
 *
 * SERVICE_DEGRADE - Not implemented in smf(5), one day it could hint that
 *                   the service is not running as well is it could. For
 *                   now, don't do anything, just record the error.
 * DEBUG_FATAL - Something happened, if the command was being run in debug
 *               mode, exit() as you really want to know something happened,
 *               otherwise just keep running. This is ignored when running
 *               under smf(5).
 *
 * The function will handle an optional variable args error message, this
 * will be written to the error stream, typically a log file or stderr.
 */
void
ipsecutil_exit(exit_type_t type, char *fmri, FILE *fp, const char *fmt, ...)
{
	int exit_status;
	va_list args;

	if (fp == NULL)
		fp = stderr;
	if (fmt != NULL) {
		va_start(args, fmt);
		vwarnxfp(fp, fmt, args);
		va_end(args);
	}

	if (fmri == NULL) {
		/* Command being run directly from a shell. */
		switch (type) {
		case SERVICE_EXIT_OK:
			exit_status = 0;
			break;
		case SERVICE_DEGRADE:
			return;
		case SERVICE_BADPERM:
		case SERVICE_BADCONF:
		case SERVICE_MAINTAIN:
		case SERVICE_DISABLE:
		case SERVICE_FATAL:
		case SERVICE_RESTART:
		case DEBUG_FATAL:
			warnxfp(fp, "Fatal error - exiting.");
			exit_status = 1;
			break;
		}
	} else {
		/* Command being run as a smf(5) method. */
		switch (type) {
		case SERVICE_EXIT_OK:
			exit_status = SMF_EXIT_OK;
			break;
		case SERVICE_DEGRADE: /* Not implemented yet. */
		case DEBUG_FATAL:
			/* Keep running, don't exit(). */
			return;
		case SERVICE_BADPERM:
			warnxfp(fp, dgettext(TEXT_DOMAIN,
			    "Permission error with %s."), fmri);
			exit_status = SMF_EXIT_ERR_PERM;
			break;
		case SERVICE_BADCONF:
			warnxfp(fp, dgettext(TEXT_DOMAIN,
			    "Bad configuration of service %s."), fmri);
			exit_status = SMF_EXIT_ERR_FATAL;
			break;
		case SERVICE_MAINTAIN:
			warnxfp(fp, dgettext(TEXT_DOMAIN,
			    "Service %s needs maintenance."), fmri);
			exit_status = SMF_EXIT_ERR_FATAL;
			break;
		case SERVICE_DISABLE:
			exit_status = SMF_EXIT_ERR_FATAL;
			break;
		case SERVICE_FATAL:
			warnxfp(fp, dgettext(TEXT_DOMAIN,
			    "Service %s fatal error."), fmri);
			exit_status = SMF_EXIT_ERR_FATAL;
			break;
		case SERVICE_RESTART:
			exit_status = 1;
			break;
		}
	}
	(void) fflush(fp);
	(void) fclose(fp);
	exit(exit_status);
}
