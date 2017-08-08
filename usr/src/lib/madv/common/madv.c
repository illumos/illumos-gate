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

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/shm.h>
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
#include <dlfcn.h>
#include <assert.h>
#include <libintl.h>
#include <locale.h>

extern int	gmatch(const char *s, const char *p);

#pragma init(__madvmain)

static FILE *errfp = NULL;
static const char *madvident = "madv.so.1";
static int pagesize;
static int advice_all = -1;
static int advice_heap = -1;
static int advice_shm = -1;
static int advice_ism = -1;
static int advice_dism = -1;
static int advice_map = -1;
static int advice_mapshared = -1;
static int advice_mapprivate = -1;
static int advice_mapanon = -1;

/* environment variables */

#define	ENV_MADV		"MADV"
#define	ENV_MADVCFGFILE		"MADVCFGFILE"
#define	ENV_MADVERRFILE		"MADVERRFILE"

/* config file */

#define	DEF_MADVCFGFILE		"/etc/madv.conf"
#define	MAXLINELEN	MAXPATHLEN + 64
#define	CFGDELIMITER	':'
#define	ARGDELIMITER	' '

/*
 * avoid malloc which causes certain applications to crash
 */
static char		lbuf[MAXLINELEN];
static char		pbuf[MAXPATHLEN];

#ifdef MADVDEBUG
#define	ENV_MADVDEBUG	"MADVDEBUG"
#define	MADVPRINT(x, y)	if (madvdebug & x) (void) fprintf y;

static int madvdebug = 0;
#else
#define	MADVPRINT(x, y)
#endif

/*
 * advice options
 */
static char *legal_optstr[] = {
	"madv",
	"heap",
	"shm",
	"ism",
	"dism",
	"map",
	"mapshared",
	"mapprivate",
	"mapanon",
	NULL
};

enum optenum {
	OPT_MADV,
	OPT_HEAP,
	OPT_SHM,
	OPT_ISM,
	OPT_DISM,
	OPT_MAP,
	OPT_MAPSHARED,
	OPT_MAPPRIVATE,
	OPT_MAPANON
};

/*
 * Advice values
 * These need to correspond to the order of the MADV_ flags in mman.h
 * since the position infers the value for the flag.
 */
static char *legal_madvice[] = {
	"normal",
	"random",
	"sequential",
	"willneed_NOT_SUPPORTED!",
	"dontneed_NOT_SUPPORTED!",
	"free_NOT_SUPPORTED!",
	"access_default",
	"access_lwp",
	"access_many",
	NULL
};

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

/*PRINTFLIKE2*/
static void
madverr(FILE *fp, char *fmt, ...)
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

/*
 * Return the process's current brk base and size.
 */
static int
mygetbrk(uintptr_t *base, size_t *size)
{
	int fd;
	pstatus_t ps;
	int rc;

	fd = open("/proc/self/status", O_RDONLY);

	if (fd >= 0) {
		if (read(fd, &ps, sizeof (ps)) == sizeof (ps)) {
			*base = ps.pr_brkbase;
			*size = ps.pr_brksize;
			rc = 0;
		} else {
			rc = errno;
		}
		(void) close(fd);
	} else {
		rc = errno;
	}
	return (rc);
}

/*
 * Check if exec name matches cfgname found in madv cfg file.
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
	MADVPRINT(2, (stderr, "gmatch: %s %s %s %d\n",
	    cfgname, ename, execname, rc));

	return (rc);
}

/*
 * Check if string matches any of exec arguments.
 */
static int
argmatch(char *str)
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
			MADVPRINT(2, (stderr, "argmatch: %s ", str));
			for (arg = 1; arg < pi.pr_argc; arg++, argv++) {
				if (rc = gmatch(*argv, str)) {
					MADVPRINT(2, (stderr, "%s ", *argv));
					break;
				}
			}
			MADVPRINT(2, (stderr, "%d\n", rc));
		} else {
			madverr(errfp, dgettext(TEXT_DOMAIN,
			    "%s: /proc/self/psinfo read failed [%s]\n"),
			    madvident, strerror(errno));
		}
		(void) close(fd);
	} else {
		madverr(errfp, dgettext(TEXT_DOMAIN,
		    "%s: /proc/self/psinfo open failed [%s]\n"),
		    madvident, strerror(errno));
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

static int
strtoadv(char *advstr)
{
	char *dummy, *locstr = advstr;

	return (getsubopt(&locstr, legal_madvice, &dummy));
}

static void
advice_opts(char *optstr, const char *execname, char *cfgfile, int lineno)
{
	char *value;
	int opt;
	int advice = 0;

	while (*optstr != '\0') {
		opt = getsubopt(&optstr, legal_optstr, &value);
		if (opt < 0) {
			madverr(errfp, dgettext(TEXT_DOMAIN,
			    "%s: invalid advice option (%s)"
			    " for %s - cfgfile: %s, line: %d\n"),
			    madvident, value, execname, cfgfile, lineno);
			break;
		} else if (!value) {
			madverr(errfp, dgettext(TEXT_DOMAIN,
			    "%s: option missing advice"
			    " for %s - cfgfile: %s, line: %d\n"),
			    madvident, execname, cfgfile, lineno);
			break;
		}
		advice = strtoadv(value);
		if (advice < 0) {
			madverr(errfp, dgettext(TEXT_DOMAIN,
			    "%s: invalid advice specified (%s)"
			    " for %s - cfgfile: %s, line: %d\n"),
			    madvident, value, execname, cfgfile, lineno);
			break;
		}
		switch (opt) {
		case OPT_MADV:
			advice_all = advice;
			break;
		case OPT_HEAP:
			if (advice_heap < 0) {
				advice_heap = advice;
			} else {
				madverr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: duplicate advice specified "
				    "(%s) for %s - cfgfile: %s, line: %d\n"),
				    madvident, value, execname, cfgfile,
				    lineno);
			}
			break;
		case OPT_SHM:
			if (advice_shm < 0) {
				advice_shm = advice;
			} else {
				madverr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: duplicate advice specified "
				    "(%s) for %s - cfgfile: %s, line: %d\n"),
				    madvident, value, execname, cfgfile,
				    lineno);
			}
			break;
		case OPT_ISM:
			if (advice_ism < 0) {
				advice_ism = advice;
			} else {
				madverr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: duplicate advice specified "
				    "(%s) for %s - cfgfile: %s, line: %d\n"),
				    madvident, value, execname, cfgfile,
				    lineno);
			}
			break;
		case OPT_DISM:
			if (advice_dism < 0) {
				advice_dism = advice;
			} else {
				madverr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: duplicate advice specified "
				    "(%s) for %s - cfgfile: %s, line: %d\n"),
				    madvident, value, execname, cfgfile,
				    lineno);
			}
			break;
		case OPT_MAP:
			if (advice_map < 0) {
				advice_map = advice;
			} else {
				madverr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: duplicate advice specified "
				    "(%s) for %s - cfgfile: %s, line: %d\n"),
				    madvident, value, execname, cfgfile,
				    lineno);
			}
			break;
		case OPT_MAPSHARED:
			if (advice_mapshared < 0) {
				advice_mapshared = advice;
			} else {
				madverr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: duplicate advice specified "
				    "(%s) for %s - cfgfile: %s, line: %d\n"),
				    madvident, value, execname, cfgfile,
				    lineno);
			}
			break;
		case OPT_MAPPRIVATE:
			if (advice_mapprivate < 0) {
				advice_mapprivate = advice;
			} else {
				madverr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: duplicate advice specified "
				    "(%s) for %s - cfgfile: %s, line: %d\n"),
				    madvident, value, execname, cfgfile,
				    lineno);
			}
			break;
		case OPT_MAPANON:
			if (advice_mapanon < 0) {
				advice_mapanon = advice;
			} else {
				madverr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: duplicate advice specified "
				    "(%s) for %s - cfgfile: %s, line: %d\n"),
				    madvident, value, execname, cfgfile,
				    lineno);
			}
			break;
		default:
			madverr(errfp, dgettext(TEXT_DOMAIN,
			    "%s: invalid advice option (%s)"
			    " for %s - cfgfile: %s, line: %d\n"),
			    madvident, value, execname, cfgfile, lineno);
			break;
		}
	}
}

static void
__madvmain()
{
	char		*cfgfile, *errfile;
	FILE		*fp = NULL;
	const char	*execname;
	char		*cwd;
	int		cwdlen;
	char		*tok, *tokadv, *tokarg;
	char		*str, *envadv;
	int		lineno = 0;
	int		advice;
	uintptr_t	brkbase, brkend;
	size_t		brksize;
	int		rc;
	char		*locale;

	/*
	 * If a private error file is indicated then set the locale
	 * for error messages for the duration of this routine.
	 * Error messages destined for syslog should not be translated
	 * and thus come from the default C locale.
	 */
	if ((errfile = getenv(ENV_MADVERRFILE)) != NULL) {
		errfp = fopen(errfile, "aF");
		if (errfp) {
			locale = setlocale(LC_MESSAGES, "");
		} else {
			madverr(NULL, dgettext(TEXT_DOMAIN,
			    "%s: cannot open error file: %s [%s]\n"),
			    madvident, errfile, strerror(errno));
		}
	}

#ifdef MADVDEBUG
	if (str = getenv(ENV_MADVDEBUG))
		madvdebug = atoi(str);
#endif

	if (envadv = getenv(ENV_MADV)) {
		if ((advice = strtoadv(envadv)) >= 0)
			advice_all = advice;
		else
			madverr(errfp, dgettext(TEXT_DOMAIN,
			    "%s: invalid advice specified: MADV=%s\n"),
			    madvident, envadv);
	}

	/*
	 * Open specified cfg file or default one.
	 */
	if (cfgfile = getenv(ENV_MADVCFGFILE)) {
		fp = fopen(cfgfile, "rF");
		if (!fp) {
			madverr(errfp, dgettext(TEXT_DOMAIN,
			    "%s: cannot open configuration file: %s [%s]\n"),
			    madvident, cfgfile, strerror(errno));
		}
	} else {
		cfgfile = DEF_MADVCFGFILE;
		fp = fopen(cfgfile, "rF");
	}

	if (fp) {
		execname = mygetexecname();

		cwd = getcwd(pbuf, MAXPATHLEN);
		if (!cwd)
			return;

		cwd = strcat(cwd, "/");
		cwdlen = strlen(cwd);

		while (fgets(lbuf, MAXLINELEN, fp)) {
			lineno++;

			/*
			 * Make sure line wasn't truncated.
			 */
			if (strlen(lbuf) >= MAXLINELEN - 1) {
				madverr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: invalid entry, "
				    "line too long - cfgfile:"
				    " %s, line: %d\n"),
				    madvident, cfgfile, lineno);
				continue;
			}

			if (empty(lbuf))
				continue;

			/*
			 * Get advice options.
			 * Parse right to left in case delimiter is in name.
			 */
			if (!(tokadv = strrchr(lbuf, CFGDELIMITER))) {
				madverr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: no delimiter specified - cfgfile:"
				    " %s, line: %d\n"),
				    madvident, cfgfile, lineno);
				continue;
			}
			*tokadv++ = '\0';

			/*
			 * Remove newline from end of advice options.
			 */
			if (str = strrchr(tokadv, '\n'))
				*str = '\0';

			/*
			 * Get optional argument string.
			 */
			if (tokarg = strrchr(lbuf, ARGDELIMITER)) {
				*tokarg++ = '\0';
			}

			/*
			 * Compare exec name.
			 */
			tok = lbuf;
			if (!fnmatch(execname, tok, cwd)) {
				tokadv = tokarg = NULL;
				cwd[cwdlen] = '\0';
				continue;
			}

			/*
			 * Compare arguments if argument string specified.
			 */
			if (tokarg &&
			    !empty(tokarg) &&
			    !argmatch(tokarg)) {
				tokadv = tokarg = NULL;
				cwd[cwdlen] = '\0';
				continue;
			}

			/*
			 * Parse advice options.
			 * If empty, any advice from ENV_MADV is reset.
			 */
			if (empty(tokadv)) {
				advice_all = -1;
			} else {
				advice_opts(tokadv, execname, cfgfile, lineno);
			}
			break;
		}
		(void) fclose(fp);
	}

	/*
	 * Pagesize needed for proper aligning by brk interpose.
	 */
	pagesize = sysconf(_SC_PAGESIZE);

	/*
	 * Apply global advice if set.
	 * Specific options in the cfgfile take precedence.
	 */
	if (advice_all >= 0) {
		if (advice_heap < 0)
			advice_heap = advice_all;
		if (advice_shm < 0)
			advice_shm = advice_all;
		if (advice_map < 0)
			advice_map = advice_all;
	}

	MADVPRINT(2, (stderr, "advice_all %d\n", advice_all));
	MADVPRINT(2, (stderr, "advice_heap %d\n", advice_heap));
	MADVPRINT(2, (stderr, "advice_shm %d\n", advice_shm));
	MADVPRINT(2, (stderr, "advice_ism %d\n", advice_ism));
	MADVPRINT(2, (stderr, "advice_dism %d\n", advice_dism));
	MADVPRINT(2, (stderr, "advice_map %d\n", advice_map));
	MADVPRINT(2, (stderr, "advice_mapshared %d\n", advice_mapshared));
	MADVPRINT(2, (stderr, "advice_mapprivate %d\n", advice_mapprivate));
	MADVPRINT(2, (stderr, "advice_mapanon %d\n", advice_mapanon));

	/*
	 * If heap advice is specified, apply it to the existing heap.
	 * As the heap grows the kernel applies the advice automatically
	 * to new portions of the heap.
	 */
	if (advice_heap >= 0) {
		if (rc = mygetbrk(&brkbase, &brksize)) {
			madverr(errfp, dgettext(TEXT_DOMAIN,
			    "%s: /proc/self/status read failed [%s]\n"),
			    madvident, strerror(rc));
		} else {
			MADVPRINT(4, (stderr, "brkbase 0x%x brksize 0x%x\n",
			    brkbase, brksize));
			/*
			 * Align start address for memcntl and apply advice
			 * on full pages of heap.  Create a page of heap if
			 * it does not already exist.
			 */
			brkend = roundup(brkbase+brksize, pagesize);
			brkbase = roundup(brkbase, pagesize);
			brksize = brkend - brkbase;
			if (brksize < pagesize) {
				if (sbrk(pagesize) == (void *)-1) {
					madverr(errfp, dgettext(TEXT_DOMAIN,
					    "%s: sbrk failed [%s]\n"),
					    madvident, strerror(errno));
					goto out;
				}
				brksize = pagesize;
			}
			MADVPRINT(1, (stderr, "heap advice: 0x%x 0x%x %d\n",
			    brkbase, brksize, advice_heap));
			if (memcntl((caddr_t)brkbase, brksize, MC_ADVISE,
			    (caddr_t)(intptr_t)advice_heap, 0, 0) < 0) {
				madverr(errfp, dgettext(TEXT_DOMAIN,
				    "%s: memcntl() failed [%s]: heap advice\n"),
				    madvident, strerror(errno));
			}
		}
	}
out:
	if (errfp) {
		(void) fclose(errfp);
		(void) setlocale(LC_MESSAGES, locale);
	} else {
		/* close log file: no-op if nothing logged to syslog */
		closelog();
	}

}

/*
 * shmat interpose
 */
void *
shmat(int shmid, const void *shmaddr, int shmflag)
{
	static caddr_t (*shmatfunc)() = NULL;
	void *result;
	int advice = -1;
	struct shmid_ds	mds;
#ifdef MADVDEBUG
	int rc;
#endif

	if (!shmatfunc) {
		shmatfunc = (caddr_t (*)()) dlsym(RTLD_NEXT, "shmat");
		assert(shmatfunc);
	}

	result = shmatfunc(shmid, shmaddr, shmflag);

	/*
	 * Options ism, dism take precedence over option shm.
	 */
	if (advice_ism >= 0 && (shmflag & SHM_SHARE_MMU)) {
		advice = advice_ism;
	} else if (advice_dism >= 0 && (shmflag & SHM_PAGEABLE)) {
		advice = advice_dism;
	} else if (advice_shm >= 0) {
		advice = advice_shm;
	}

	/*
	 * Apply advice if specified and shmat succeeded.
	 */
	if (advice >= 0 && result != (void *)-1) {
#ifdef MADVDEBUG
		/* First determine segment size */
		rc = shmctl(shmid, IPC_STAT, &mds);
		MADVPRINT(4, (stderr, "shmctl rc %d errno %d\n", rc, errno));
		rc = memcntl(result, mds.shm_segsz, MC_ADVISE,
		    (caddr_t)(intptr_t)advice, 0, 0);
		MADVPRINT(1, (stderr,
		    "shmat advice: 0x%x 0x%x %d, rc %d errno %d\n",
		    result, mds.shm_segsz, advice, rc, errno));
#else
		/* First determine segment size */
		(void) shmctl(shmid, IPC_STAT, &mds);
		(void) memcntl(result, mds.shm_segsz, MC_ADVISE,
		    (caddr_t)(intptr_t)advice, 0, 0);
#endif
	}

	return (result);
}

/*
 * mmap interpose
 */
caddr_t
mmap(caddr_t addr, size_t len, int prot, int flags, int fd, off_t pos)
{
	static caddr_t (*mmapfunc)() = NULL;
	caddr_t result;
	int advice = -1;

	if (!mmapfunc) {
		mmapfunc = (caddr_t (*)()) dlsym(RTLD_NEXT, "mmap");
		assert(mmapfunc);
	}

	result = mmapfunc(addr, len, prot, flags, fd, pos);

	/*
	 * Option mapanon has highest precedence while option map
	 * has lowest precedence.
	 */
	if (advice_mapanon >= 0 && (flags & MAP_ANON)) {
		advice = advice_mapanon;
	} else if (advice_mapshared >= 0 && (flags & MAP_SHARED)) {
		advice = advice_mapshared;
	} else if (advice_mapprivate >= 0 && (flags & MAP_PRIVATE)) {
		advice = advice_mapprivate;
	} else if (advice_map >= 0) {
		advice = advice_map;
	}

	/*
	 * Apply advice if specified and mmap succeeded.
	 */
	if (advice >= 0 && result != MAP_FAILED) {
#ifdef MADVDEBUG
		int rc;

		rc = memcntl(result, len, MC_ADVISE,
		    (caddr_t)(intptr_t)advice, 0, 0);
		MADVPRINT(1, (stderr,
		    "mmap advice: 0x%x 0x%x %d, rc %d errno %d\n",
		    result, len, advice, rc, errno));
#else
		(void) memcntl(result, len, MC_ADVISE,
		    (caddr_t)(intptr_t)advice, 0, 0);
#endif
	}

	return (result);
}

#if !defined(_LP64)
/*
 * mmap64 interpose
 */
caddr_t
mmap64(caddr_t addr, size_t len, int prot, int flags, int fd, off64_t pos)
{
	static caddr_t (*mmap64func)();
	caddr_t result;
	int advice = -1;

	if (!mmap64func) {
		mmap64func = (caddr_t (*)()) dlsym(RTLD_NEXT, "mmap64");
		assert(mmap64func);
	}

	result = mmap64func(addr, len, prot, flags, fd, pos);

	/*
	 * Option mapanon has highest precedence while option map
	 * has lowest precedence.
	 */
	if (advice_mapanon >= 0 && (flags & MAP_ANON)) {
		advice = advice_mapanon;
	} else if (advice_mapshared >= 0 && (flags & MAP_SHARED)) {
		advice = advice_mapshared;
	} else if (advice_mapprivate >= 0 && (flags & MAP_PRIVATE)) {
		advice = advice_mapprivate;
	} else if (advice_map >= 0) {
		advice = advice_map;
	}

	/*
	 * Apply advice if specified and mmap succeeded.
	 */
	if (advice >= 0 && result != MAP_FAILED) {
#ifdef MADVDEBUG
		int rc;

		rc = memcntl(result, len, MC_ADVISE, (caddr_t)advice, 0, 0);
		MADVPRINT(1, (stderr,
		    "mmap64 advice: 0x%x 0x%x %d, rc %d errno %d\n",
		    result, len, advice, rc, errno));
#else
		(void) memcntl(result, len, MC_ADVISE, (caddr_t)advice, 0, 0);
#endif
	}

	return (result);
}
#endif	/* !_LP64 */
