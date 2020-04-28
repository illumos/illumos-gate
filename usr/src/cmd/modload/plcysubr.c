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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Device policy specific subroutines.  We cannot merge them with
 * drvsubr.c because of static linking requirements.
 */

/*
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <priv.h>
#include <string.h>
#include <libgen.h>
#include <libintl.h>
#include <errno.h>
#include <alloca.h>
#include <sys/modctl.h>
#include <sys/devpolicy.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "addrem.h"
#include "errmsg.h"
#include "plcysubr.h"

size_t devplcysys_sz;
const priv_impl_info_t *privimplinfo;

/*
 * New token types should be parsed in parse_plcy_entry.
 */
#define	PSET	0

typedef struct token {
	const char	*token;
	int		type;
	ptrdiff_t	off;
} token_t;

static token_t toktab[] = {
	{ DEVPLCY_TKN_RDP, PSET /* offsetof(devplcysys_t, dps_rdp) */ },
	{ DEVPLCY_TKN_WRP, PSET /* offsetof(devplcysys_t, dps_wrp) */ },
};

#define	RDPOL	0
#define	WRPOL	1

#define	NTOK	(sizeof (toktab)/sizeof (token_t))

/*
 * Compute the size of the datastructures needed.
 */
void
devplcy_init(void)
{
	if ((privimplinfo = getprivimplinfo()) == NULL) {
		(void) fprintf(stderr, gettext(ERR_PRIVIMPL));
		exit(1);
	}

	devplcysys_sz = DEVPLCYSYS_SZ(privimplinfo);

	toktab[RDPOL].off =
	    (char *)DEVPLCYSYS_RDP((devplcysys_t *)0, privimplinfo) - (char *)0;
	toktab[WRPOL].off =
	    (char *)DEVPLCYSYS_WRP((devplcysys_t *)0, privimplinfo) - (char *)0;
}

/*
 * Read a configuration file line and return a static buffer pointing to it.
 * It returns a static struct fileentry which has several fields:
 *	- rawbuf, which includes the lines including empty lines and comments
 *	leading up to the file and the entry as found in the file
 *	- orgentry, pointer in rawbuf to the start of the entry proper.
 *	- entry, a pre-parsed entry, escaped newlines removed.
 *	- startline, the line number of the first line in the file
 */
fileentry_t *
fgetline(FILE *fp)
{
	static size_t sz = BUFSIZ;
	static struct fileentry fe;
	static int linecnt = 1;

	char *buf = fe.rawbuf;
	ptrdiff_t off;
	char *p;
	int c, lastc, i;

	if (buf == NULL) {
		fe.rawbuf = buf = malloc(sz);
		if (buf == NULL)
			return (NULL);
	}
	if (fe.entry != NULL) {
		free(fe.entry);
		fe.orgentry = fe.entry = NULL;
	}

	i = 0;
	off = -1;
	c = '\n';

	while (lastc = c, (c = getc(fp)) != EOF) {
		buf[i++] = c;

		if (i == sz) {
			sz *= 2;
			fe.rawbuf = buf = realloc(buf, sz);
			if (buf == NULL)
				return (NULL);
		}

		if (c == '\n') {
			linecnt++;
			/* Newline, escaped or not yet processing an entry */
			if (off == -1 || lastc == '\\')
				continue;
		} else if (lastc == '\n' && off == -1) {
			/* Start of more comments */
			if (c == '#')
				continue;
			/* Found start of entry */
			off = i - 1;
			fe.startline = linecnt;
			continue;
		} else
			continue;

		buf[i] = '\0';
		fe.orgentry = buf + off;
		p = fe.entry = strdup(fe.orgentry);

		if (p == NULL)
			return (NULL);

		/* Remove <backslash><newline> */
		if ((p = strchr(p, '\\')) != NULL) {
			for (off = 0; (p[-off] = p[0]) != '\0'; p++)
				if (p[0] == '\\' && p[1] == '\n') {
					off += 2;
					p++;
				}
		}
		return (&fe);
	}
	if (lastc != '\n' || off != -1)
		return (NULL);
	buf[i] = '\0';
	linecnt = 1;
	return (&fe);
}

/*
 * Parse minor number ranges:
 *	(minor) or (lowminor-highminor)
 * Return 0 for success, -1 for failure.
 */
int
parse_minor_range(const char *range, minor_t *lo, minor_t *hi, char *type)
{
	unsigned long tmp;
	char *p;

	if (*range++ != '(')
		return (-1);

	errno = 0;
	tmp = strtoul(range, &p, 0);
	if (tmp > L_MAXMIN32 || (tmp == 0 && errno != 0) ||
	    (*p != '-' && *p != ')'))
		return (-1);
	*lo = tmp;
	if (*p == '-') {
		errno = 0;
		tmp = strtoul(p + 1, &p, 0);
		if (tmp > L_MAXMIN32 || (tmp == 0 && errno != 0) || *p != ')')
			return (-1);
	}
	*hi = tmp;
	if (*lo > *hi)
		return (-1);

	switch (p[1]) {
	case '\0':
		*type = '\0';
		break;
	case 'c':
	case 'C':
		*type = 'c';
		break;
	case 'b':
	case 'B':
		*type = 'b';
		break;
	default:
		return (-1);
	}
	return (0);
}

static void
put_minor_range(FILE *fp, fileentry_t *old, const char *devn, const char *tail,
    minor_t lo, minor_t hi, char type)
{
	/* Preserve preceeding comments */
	if (old != NULL && old->rawbuf != old->orgentry)
		(void) fwrite(old->rawbuf, 1, old->orgentry - old->rawbuf, fp);

	if (type == '\0') {
		put_minor_range(fp, NULL, devn, tail, lo, hi, 'b');
		put_minor_range(fp, NULL, devn, tail, lo, hi, 'c');
	} else if (lo == hi) {
		(void) fprintf(fp, "%s:(%d)%c%s", devn, (int)lo, type, tail);
	} else {
		(void) fprintf(fp, "%s:(%d-%d)%c%s", devn, (int)lo, (int)hi,
		    type, tail);
	}
}

static int
delete_one_entry(const char *filename, const char *entry)
{
	char tfile[MAXPATHLEN];
	char ofile[MAXPATHLEN];
	char *nfile;
	FILE *old, *new;
	fileentry_t *fep;
	struct stat buf;
	int newfd;
	char *mpart;
	boolean_t delall;
	boolean_t delrange;
	minor_t rlo, rhi;
	char rtype;

	mpart = strchr(entry, ':');
	if (mpart == NULL) {
		delall = B_TRUE;
		delrange = B_FALSE;
	} else {
		delall = B_FALSE;
		mpart++;
		if (*mpart == '(') {
			if (parse_minor_range(mpart, &rlo, &rhi, &rtype) != 0)
				return (-1);
			delrange = B_TRUE;
		} else {
			delrange = B_FALSE;
		}
	}

	if (strlen(filename) + sizeof (XEND)  > sizeof (tfile))
		return (-1);

	old = fopen(filename, "r");

	if (old == NULL)
		return (-1);

	(void) snprintf(tfile, sizeof (tfile), "%s%s", filename, XEND);
	(void) snprintf(ofile, sizeof (ofile), "%s%s", filename, ".old");

	nfile = mktemp(tfile);

	new = fopen(nfile, "w");
	if (new == NULL) {
		(void) fclose(old);
		return (ERROR);
	}

	newfd = fileno(new);

	/* Copy permissions, ownership */
	if (fstat(fileno(old), &buf) == 0) {
		(void) fchown(newfd, buf.st_uid, buf.st_gid);
		(void) fchmod(newfd, buf.st_mode);
	} else {
		(void) fchown(newfd, 0, 3);	/* root:sys */
		(void) fchmod(newfd, 0644);
	}

	while ((fep = fgetline(old))) {
		char *tok;
		char *min;
		char *tail;
		char tc;
		int len;

		/* Trailing comments */
		if (fep->entry == NULL) {
			(void) fputs(fep->rawbuf, new);
			break;
		}

		tok = fep->entry;
		while (*tok && isspace(*tok))
			tok++;

		if (*tok == '\0') {
			(void) fputs(fep->rawbuf, new);
			break;
		}

		/* Make sure we can recover the remainder incl. whitespace */
		tail = strpbrk(tok, "\t\n ");
		if (tail == NULL)
			tail = tok + strlen(tok);
		tc = *tail;
		*tail = '\0';

		if (delall || delrange) {
			min = strchr(tok, ':');
			if (min)
				*min++ = '\0';
		}

		len = strlen(tok);
		if (delrange) {
			minor_t lo, hi;
			char type;

			/*
			 * Delete or shrink overlapping ranges.
			 */
			if (strncmp(entry, tok, len) == 0 &&
			    entry[len] == ':' &&
			    min != NULL &&
			    parse_minor_range(min, &lo, &hi, &type) == 0 &&
			    (type == rtype || rtype == '\0') &&
			    lo <= rhi && hi >= rlo) {
				minor_t newlo, newhi;

				/* Complete overlap, then drop it. */
				if (lo >= rlo && hi <= rhi)
					continue;

				/* Partial overlap, shrink range */
				if (lo < rlo)
					newhi = rlo - 1;
				else
					newhi = hi;
				if (hi > rhi)
					newlo = rhi + 1;
				else
					newlo = lo;

				/* restore NULed character */
				*tail = tc;

				/* Split range? */
				if (newlo > newhi) {
					/*
					 * We have two ranges:
					 * lo ... newhi (== rlo - 1)
					 * newlo (== rhi + 1) .. hi
					 */
					put_minor_range(new, fep, tok, tail,
					    lo, newhi, type);
					put_minor_range(new, NULL, tok, tail,
					    newlo, hi, type);
				} else {
					put_minor_range(new, fep, tok, tail,
					    newlo, newhi, type);
				}
				continue;
			}
		} else if (strcmp(entry, tok) == 0 ||
		    (strncmp(entry, tok, len) == 0 &&
		    entry[len] == ':' &&
		    entry[len+1] == '*' &&
		    entry[len+2] == '\0')) {
			/*
			 * Delete exact match.
			 */
			continue;
		}

		/* Copy unaffected entry. */
		(void) fputs(fep->rawbuf, new);
	}
	(void) fclose(old);
	(void) fflush(new);
	(void) fsync(newfd);
	if (ferror(new) == 0 && fclose(new) == 0 && fep != NULL) {
		if (rename(filename, ofile) != 0) {
			perror(NULL);
			(void) fprintf(stderr, gettext(ERR_UPDATE), ofile);
			(void) unlink(ofile);
			(void) unlink(nfile);
			return (ERROR);
		} else if (rename(nfile, filename) != 0) {
			perror(NULL);
			(void) fprintf(stderr, gettext(ERR_UPDATE), ofile);
			(void) rename(ofile, filename);
			(void) unlink(nfile);
			return (ERROR);
		}
		(void) unlink(ofile);
	} else
		(void) unlink(nfile);
	return (0);
}


int
delete_plcy_entry(const char *filename, const char *entry)
{
	char *p, *single;
	char *copy;
	int ret = 0;

	copy = strdup(entry);
	if (copy == NULL)
		return (ERROR);

	for (single = strtok_r(copy, " \t\n", &p);
	    single != NULL;
	    single = strtok_r(NULL, " \t\n", &p)) {
		if ((ret = delete_one_entry(filename, single)) != 0) {
			free(copy);
			return (ret);
		}
	}
	free(copy);
	return (0);
}

/*
 * Analyze the device policy token; new tokens should be added to
 * toktab; new token types should be coded here.
 */
int
parse_plcy_token(char *token, devplcysys_t *dp)
{
	char *val = strchr(token, '=');
	const char *perr;
	int i;
	priv_set_t *pset;

	if (val == NULL) {
		(void) fprintf(stderr, gettext(ERR_NO_EQUALS), token);
		return (1);
	}
	*val++ = '\0';

	for (i = 0; i < NTOK; i++) {
		if (strcmp(token, toktab[i].token) == 0) {
			/* standard pointer computation for tokens */
			void *item = (char *)dp + toktab[i].off;

			switch (toktab[i].type) {
			case PSET:
				pset = priv_str_to_set(val, ",", &perr);
				if (pset == NULL) {
					if (perr == NULL) {
						(void) fprintf(stderr,
						    gettext(ERR_NO_MEM));
					} else {
						(void) fprintf(stderr,
						    gettext(ERR_BAD_PRIVS),
						    perr - val, val, perr);
					}
					return (1);
				}
				priv_copyset(pset, item);
				priv_freeset(pset);
				break;
			default:
				(void) fprintf(stderr,
				    "Internal Error: bad token type: %d\n",
				    toktab[i].type);
				return (1);
			}
			/* Standard cleanup & return for good tokens */
			val[-1] = '=';
			return (0);
		}
	}
	(void) fprintf(stderr, gettext(ERR_BAD_TOKEN), token);
	return (1);
}

static int
add2str(char **dstp, const char *str, size_t *sz)
{
	char *p = *dstp;
	size_t len = strlen(p) + strlen(str) + 1;

	if (len > *sz) {
		*sz *= 2;
		if (*sz < len)
			*sz = len;
		*dstp = p = realloc(p, *sz);
		if (p == NULL) {
			(void) fprintf(stderr, gettext(ERR_NO_MEM));
			return (-1);
		}
	}
	(void) strcat(p, str);
	return (0);
}

/*
 * Verify that the policy entry is valid and return the canonical entry.
 */
char *
check_plcy_entry(char *entry, const char *driver, boolean_t todel)
{
	char *res;
	devplcysys_t *ds;
	char *tok;
	size_t sz = strlen(entry) * 2 + strlen(driver) + 3;
	boolean_t tokseen = B_FALSE;

	devplcy_init();

	res = malloc(sz);
	ds = alloca(devplcysys_sz);

	if (res == NULL || ds == NULL) {
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		free(res);
		return (NULL);
	}

	*res = '\0';

	while ((tok = strtok(entry, " \t\n")) != NULL) {
		entry = NULL;

		/* It's not a token */
		if (strchr(tok, '=') == NULL) {
			if (strchr(tok, ':') != NULL) {
				(void) fprintf(stderr, gettext(ERR_BAD_MINOR));
				free(res);
				return (NULL);
			}
			if (*res != '\0' && add2str(&res, "\n", &sz) != 0)
				return (NULL);

			if (*tok == '(') {
				char type;
				if (parse_minor_range(tok, &ds->dps_lomin,
				    &ds->dps_himin, &type) != 0 ||
				    (!todel && type == '\0')) {
					(void) fprintf(stderr,
					    gettext(ERR_BAD_MINOR));
					free(res);
					return (NULL);
				}
			} else {
				char *tmp = strchr(tok, '*');

				if (tmp != NULL &&
				    strchr(tmp + 1, '*') != NULL) {
					(void) fprintf(stderr,
					    gettext(ERR_BAD_MINOR));
					free(res);
				}
			}

			if (add2str(&res, driver, &sz) != 0)
				return (NULL);
			if (add2str(&res, ":", &sz) != 0)
				return (NULL);
			if (add2str(&res, tok, &sz) != 0)
				return (NULL);
			tokseen = B_FALSE;
		} else {
			if (*res == '\0') {
				if (add2str(&res, driver, &sz) != 0)
					return (NULL);
				if (add2str(&res, ":*", &sz) != 0)
					return (NULL);
			}
			if (parse_plcy_token(tok, ds) != 0) {
				free(res);
				return (NULL);
			}

			if (add2str(&res, "\t", &sz) != 0)
				return (NULL);
			if (add2str(&res, tok, &sz) != 0)
				return (NULL);
			tokseen = B_TRUE;
		}
	}
	if ((todel && tokseen) || *res == '\0' || (!todel && !tokseen)) {
		(void) fprintf(stderr, gettext(ERR_INVALID_PLCY));
		free(res);
		return (NULL);
	}
	if (!todel)
		if (add2str(&res, "\n", &sz) != 0)
			return (NULL);
	return (res);
}

int
update_device_policy(const char *filename, const char *entry, boolean_t repl)
{
	FILE *fp;

	if (repl) {
		char *dup, *tok, *s1;

		dup = strdup(entry);
		if (dup == NULL) {
			(void) fprintf(stderr, gettext(ERR_NO_MEM));
			return (ERROR);
		}

		/*
		 * Split the entry in lines; then get the first token
		 * of each line.
		 */
		for (tok = strtok_r(dup, "\n", &s1); tok != NULL;
		    tok = strtok_r(NULL, "\n", &s1)) {

			tok = strtok(tok, " \n\t");

			if (delete_one_entry(filename, tok) != 0) {
				free(dup);
				return (ERROR);
			}
		}

		free(dup);
	}

	fp = fopen(filename, "a");
	if (fp == NULL)
		return (ERROR);

	(void) fputs(entry, fp);

	if (fflush(fp) != 0 || fsync(fileno(fp)) != 0 || fclose(fp) != 0)
		return (ERROR);

	return (NOERR);
}


/*
 * We need to allocate the privileges now or the privilege set
 * parsing code will not allow them.
 */
int
check_priv_entry(const char *privlist, boolean_t add)
{
	char *l = strdup(privlist);
	char *pr;

	if (l == NULL) {
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		return (ERROR);
	}

	while ((pr = strtok_r(l, ",", &l)) != NULL) {
		/* Privilege already exists */
		if (priv_getbyname(pr) != -1)
			continue;

		if (add && modctl(MODALLOCPRIV, pr) != 0) {
			(void) fprintf(stderr, gettext(ERR_BAD_PRIV), pr,
			    strerror(errno));
			return (ERROR);
		}
	}
	return (NOERR);
}
