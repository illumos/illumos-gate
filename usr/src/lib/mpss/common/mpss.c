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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/auxv.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <procfs.h>
#include <libintl.h>
#include <locale.h>

extern int	gmatch(const char *s, const char *p);

#pragma init(__mpssmain)

static const char *mpssident = "mpss.so.1";

/* environment variables */

#define	ENV_MPSSCFGFILE		"MPSSCFGFILE"
#define	ENV_MPSSSTACK		"MPSSSTACK"
#define	ENV_MPSSHEAP		"MPSSHEAP"
#define	ENV_MPSSERRFILE		"MPSSERRFILE"

#define	MPSSHEAP	0
#define	MPSSSTACK	1

/* config file */

#define	DEF_MPSSCFGFILE		"/etc/mpss.conf"
#define	MAXLINELEN	MAXPATHLEN + 64
#define	CFGDELIMITER	':'
#define	ARGDELIMITER	' '

/*
 * avoid malloc which causes certain applications to crash
 */
static char		lbuf[MAXLINELEN];
static char		pbuf[MAXPATHLEN];

#ifdef MPSSDEBUG
#define	ENV_MPSSDEBUG	"MPSSDEBUG"
#define	MPSSPRINT(x, y)	if (mpssdebug & x) (void) fprintf y;

static int		mpssdebug;
#else
#define	MPSSPRINT(x, y)
#endif

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

/*PRINTFLIKE2*/
static void
mpsserr(FILE *fp, char *fmt, ...)
{
	va_list		ap;
	va_start(ap, fmt);
	if (fp)
		(void) vfprintf(fp, fmt, ap);
	else
		vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);
}

/*
 * Return the pointer to the fully-resolved path name of the process's
 * executable file obtained from the AT_SUN_EXECNAME aux vector entry.
 */
static const char *
mygetexecname(void)
{
	const char	*execname = NULL;
	static auxv_t	auxb;

	/*
	 * The first time through, read the initial aux vector that was
	 * passed to the process at exec(2).  Only do this once.
	 */
	int fd = open("/proc/self/auxv", O_RDONLY);

	if (fd >= 0) {
		while (read(fd, &auxb, sizeof (auxv_t)) == sizeof (auxv_t)) {
			if (auxb.a_type == AT_SUN_EXECNAME) {
				execname = auxb.a_un.a_ptr;
				break;
			}
		}
		(void) close(fd);
	}
	return (execname);
}

static size_t
atosz(char *szstr)
{
	size_t		sz;
	char		*endptr, c;

	sz = strtoll(szstr, &endptr, 0);

	while (c = *endptr++) {
		switch (c) {
		case 't':
		case 'T':
			sz *= 1024;
		/*FALLTHRU*/
		case 'g':
		case 'G':
			sz *= 1024;
		/*FALLTHRU*/
		case 'm':
		case 'M':
			sz *= 1024;
		/*FALLTHRU*/
		case 'k':
		case 'K':
			sz *= 1024;
		default:
			break;
		}
	}
	return (sz);

}

#define	PGSZELEM	(8 * sizeof (void *))
static size_t		pgsz[PGSZELEM];
static int		nelem;

static int
pgszok(size_t sz)
{
	int		i;

	if (sz == 0)
		return (1);

	for (i = 0; i < nelem; i++) {
		if (sz == pgsz[i])
			break;
	}

	return (i < nelem);
}

static void
pgszinit()
{
	nelem = getpagesizes(NULL, 0);

	if (!nelem)
		return;

	if (nelem > PGSZELEM)
		nelem = PGSZELEM;

	(void) getpagesizes(pgsz, nelem);
#ifdef MPSSDEBUG
	pgsz[nelem] = 0x800000;
	nelem++;
#endif
}


static int
pgszset(size_t sz, uint_t flags)
{
	struct memcntl_mha	mpss;
	int		rc;

	mpss.mha_cmd = (flags == MPSSHEAP) ?
	    MHA_MAPSIZE_BSSBRK: MHA_MAPSIZE_STACK;
	mpss.mha_pagesize = sz;
	mpss.mha_flags = 0;
	rc = memcntl(NULL, 0, MC_HAT_ADVISE, (caddr_t)&mpss, 0, 0);

	return (rc);
}

/*
 * check if exec name matches cfgname found in mpss cfg file.
 */
static int
fnmatch(const char *execname, char *cfgname, char *cwd)
{
	const char	*ename;
	int		rc;

	/* cfgname should not have a '/' unless it begins with one */
	if (cfgname[0] == '/') {
		/*
		 * if execname does not begin with a '/', prepend the
		 * current directory.
		 */
		if (execname[0] != '/') {
			ename = (const char *)strcat(cwd, execname);
		} else
			ename = execname;
	} else {	/* simple cfg name */
		if (ename = strrchr(execname, '/'))
			/* execname is a path name - get the base name */
			ename++;
		else
			ename = execname;
	}
	rc = gmatch(ename, cfgname);
	MPSSPRINT(2, (stderr, "gmatch: %s %s %s %d\n",
	    cfgname, ename, execname, rc));

	return (rc);
}

/*
 * Check if string matches any of exec arguments.
 */
static int
argmatch(char *str, FILE *errfp)
{
	int fd;
	psinfo_t pi;
	int rc = 0;
	int arg;
	char **argv;

	fd = open("/proc/self/psinfo", O_RDONLY);

	if (fd >= 0) {
		if (read(fd, &pi, sizeof (pi)) == sizeof (pi)) {
			argv = (char **)pi.pr_argv;
			argv++;
			MPSSPRINT(2, (stderr, "argmatch: %s ", str));
			for (arg = 1; arg < pi.pr_argc; arg++, argv++) {
				if (rc = gmatch(*argv, str)) {
					MPSSPRINT(2, (stderr, "%s ", *argv));
					break;
				}
			}
			MPSSPRINT(2, (stderr, "%d\n", rc));
		} else {
			mpsserr(errfp, dgettext(TEXT_DOMAIN,
			    "%s: /proc/self/psinfo read failed [%s]\n"),
			    mpssident, strerror(errno));
		}
		(void) close(fd);
	} else {
		mpsserr(errfp, dgettext(TEXT_DOMAIN,
		    "%s: /proc/self/psinfo open failed [%s]\n"),
		    mpssident, strerror(errno));
	}
	return (rc);
}

static int
empty(char *str)
{
	char	c;

	while ((c = *str) == '\n' || c == ' ' || c == '\t')
		str++;
	return (*str == '\0');
}

void
__mpssmain()
{
	static size_t	heapsz = (size_t)-1, stacksz = (size_t)-1, sz;
	char		*cfgfile, *errfile;
	const char	*execname;
	char		*cwd;
	int		cwdlen;
	FILE		*fp = NULL, *errfp = NULL;
	char		*tok, *tokheap = NULL, *tokstack = NULL, *tokarg;
	char		*str, *envheap, *envstack;
	int		lineno = 0;
	char		*locale;

	/*
	 * If a private error file is indicated then set the locale
	 * for error messages for the duration of this routine.
	 * Error messages destined for syslog should not be translated
	 * and thus come from the default C locale.
	 */
	if ((errfile = getenv(ENV_MPSSERRFILE)) != NULL) {
		errfp = fopen(errfile, "aF");
		if (errfp) {
			locale = setlocale(LC_MESSAGES, "");
		} else {
			mpsserr(NULL, dgettext(TEXT_DOMAIN,
			    "%s: cannot open error file: %s [%s]\n"),
			    mpssident, errfile, strerror(errno));
		}
	}

#ifdef MPSSDEBUG
	if (str = getenv(ENV_MPSSDEBUG))
		mpssdebug = atosz(str);
#endif

	pgszinit();

	if (envstack = getenv(ENV_MPSSSTACK)) {
		sz = atosz(envstack);
		if (pgszok(sz))
			stacksz = sz;
		else
			mpsserr(errfp, dgettext(TEXT_DOMAIN,
			    "%s: invalid stack page size specified:"
			    " MPSSSTACK=%s\n"),
			    mpssident, envstack);
	}

	if (envheap = getenv(ENV_MPSSHEAP)) {
		sz = atosz(envheap);
		if (pgszok(sz))
			heapsz = sz;
		else
			mpsserr(errfp, dgettext(TEXT_DOMAIN,
			    "%s: invalid heap page size specified:"
			    " MPSSHEAP=%s\n"),
			    mpssident, envheap);
	}

	/*
	 * Open specified cfg file or default one.
	 */
	if (cfgfile = getenv(ENV_MPSSCFGFILE)) {
		fp = fopen(cfgfile, "rF");
		if (!fp) {
			mpsserr(errfp, dgettext(TEXT_DOMAIN,
			    "%s: cannot open configuration file: %s [%s]\n"),
			    mpssident, cfgfile, strerror(errno));
		}
	} else {
		cfgfile = DEF_MPSSCFGFILE;
		fp = fopen(cfgfile, "rF");
	}

	execname = mygetexecname();

	if (fp) {

		cwd = getcwd(pbuf, MAXPATHLEN);
		if (!cwd)
			return;

		cwd = strcat(cwd, "/");
		cwdlen = strlen(cwd);

		while (fgets(lbuf, MAXLINELEN, fp)) {
			lineno++;
			if (empty(lbuf))
				continue;
			/*
			 * Make sure line wasn't truncated.
			 */
			if (strlen(lbuf) >= MAXLINELEN - 1) {
				mpsserr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: invalid entry, "
				    "line too long - cfgfile:"
				    " %s, line: %d\n"),
				    mpssident, cfgfile, lineno);
				continue;
			}
			/*
			 * parse right to left in case delimiter is
			 * in name.
			 */
			if (!(tokstack = strrchr(lbuf, CFGDELIMITER))) {
				mpsserr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: no delimiters specified - cfgfile:"
				    " %s, line: %d\n"),
				    mpssident, cfgfile, lineno);
				continue;
			}
			/* found delimiter in lbuf */
			*tokstack++ = '\0';
			/* remove for error message */
			if (str = strrchr(tokstack, '\n'))
				*str = '\0';
			if (!(tokheap = strrchr(lbuf, CFGDELIMITER))) {
				mpsserr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: invalid entry, "
				    "missing delimiter - cfgfile: %s,"
				    " line: %d\n"),
				    mpssident, cfgfile, lineno);
				continue;
			}
			*tokheap++ = '\0';

			/* exec-args is optional */
			if (tokarg = strrchr(lbuf, ARGDELIMITER)) {
				*tokarg++ = '\0';
			}

			tok = lbuf;

			if (!fnmatch(execname, tok, cwd)) {
				tokheap = tokstack = tokarg = NULL;
				cwd[cwdlen] = '\0';
				continue;
			}

			if (tokarg &&
			    !empty(tokarg) &&
			    !argmatch(tokarg, errfp)) {
				tokheap = tokstack = tokarg = NULL;
				cwd[cwdlen] = '\0';
				continue;
			}

			/* heap token */
			if (empty(tokheap)) {
				/* empty cfg entry */
				heapsz = (size_t)-1;
			} else {
				sz = atosz(tokheap);
				if (pgszok(sz))
					heapsz = sz;
				else {
					mpsserr(errfp, dgettext(TEXT_DOMAIN,
					    "%s: invalid heap page size"
					    " specified (%s) for %s - "
					    "cfgfile: %s, line: %d\n"),
					    mpssident, tokheap,
					    execname, cfgfile,
					    lineno);
					heapsz = (size_t)-1;
				}
			}

			/* stack token */
			if (empty(tokstack)) {
				stacksz = (size_t)-1;
				break;
			} else {
				sz = atosz(tokstack);
				if (pgszok(sz))
					stacksz = sz;
				else {
					mpsserr(errfp, dgettext(TEXT_DOMAIN,
					    "%s: invalid stack page size"
					    " specified (%s) for %s - "
					    "cfgfile: %s, line: %d\n"),
					    mpssident, tokstack,
					    execname, cfgfile, lineno);
					stacksz = (size_t)-1;
				}
			}
			break;
		}
		(void) fclose(fp);
	}

	if ((heapsz != (size_t)-1) && (pgszset(heapsz, MPSSHEAP) < 0))
		mpsserr(errfp, dgettext(TEXT_DOMAIN,
		    "%s: memcntl() failed [%s]: heap page size (%s)"
		    " for %s not set\n"),
		    mpssident, strerror(errno), (tokheap) ? tokheap : envheap,
		    execname);
	if ((stacksz != (size_t)-1) && (pgszset(stacksz, MPSSSTACK) < 0))
		mpsserr(errfp, dgettext(TEXT_DOMAIN,
		    "%s: memcntl() failed [%s]: stack page size (%s)"
		    " for %s not set\n"),
		    mpssident, strerror(errno), (tokstack) ? tokstack: envstack,
		    execname);

	if (errfp) {
		(void) fclose(errfp);
		(void) setlocale(LC_MESSAGES, locale);
	} else {
		/* close log file: no-op if nothing logged to syslog */
		closelog();
	}
}
