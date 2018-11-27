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

#include <sys/types.h>
#include <sys/systeminfo.h>

#include <limits.h>
#include <strings.h>
#include <stddef.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>

#include <fmdump.h>

/*
 * fmdump loadable scheme support
 *
 * This file provides a pared-down implementation of fmd's fmd_fmri.c and
 * fmd_scheme.c and must be kept in sync with the set of service routines
 * required by scheme plug-ins.  At some point if other utilities want to
 * use this we can refactor it into a more general library.  (Note: fmd
 * cannot use such a library because it has its own internal locking, etc.)
 * As schemes are needed, we dlopen() them and cache a list of them which we
 * can search later.  We also use the list as a negative cache: if we fail to
 * load a scheme, we add an entry with sch_dlp = NULL and sch_err recording
 * the errno to be returned to the caller.
 */

typedef struct fmd_scheme_ops {
	int (*sop_init)(void);
	void (*sop_fini)(void);
	ssize_t (*sop_nvl2str)(nvlist_t *, char *, size_t);
} fmd_scheme_ops_t;

typedef struct fmd_scheme_opd {
	const char *opd_name;		/* symbol name of scheme function */
	size_t opd_off;			/* offset within fmd_scheme_ops_t */
} fmd_scheme_opd_t;

typedef struct fmd_scheme {
	struct fmd_scheme *sch_next;    /* next scheme on list of schemes */
	char *sch_name;			/* name of this scheme (fmri prefix) */
	void *sch_dlp;			/* libdl(3DL) shared library handle */
	int sch_err;			/* if negative entry, errno to return */
	fmd_scheme_ops_t sch_ops;	/* scheme function pointers */
} fmd_scheme_t;

static fmd_scheme_t *sch_list;		/* list of cached schemes */

static long
fmd_scheme_notsup(void)
{
	errno = ENOTSUP;
	return (-1);
}

static void
fmd_scheme_vnop(void)
{
}

static int
fmd_scheme_nop(void)
{
	return (0);
}

/*
 * Default values for the scheme ops.  If a scheme function is not defined in
 * the module, then this operation is implemented using the default function.
 */
static const fmd_scheme_ops_t _fmd_scheme_default_ops = {
	(int (*)())fmd_scheme_nop,		/* sop_init */
	(void (*)())fmd_scheme_vnop,		/* sop_fini */
	(ssize_t (*)())fmd_scheme_notsup,	/* sop_nvl2str */
};

/*
 * Scheme ops descriptions.  These names and offsets are used by the function
 * fmd_scheme_rtld_init(), defined below, to load up a fmd_scheme_ops_t.
 */
static const fmd_scheme_opd_t _fmd_scheme_ops[] = {
	{ "fmd_fmri_init", offsetof(fmd_scheme_ops_t, sop_init) },
	{ "fmd_fmri_fini", offsetof(fmd_scheme_ops_t, sop_fini) },
	{ "fmd_fmri_nvl2str", offsetof(fmd_scheme_ops_t, sop_nvl2str) },
	{ NULL, 0 }
};

static fmd_scheme_t *
fmd_scheme_create(const char *name)
{
	fmd_scheme_t *sp;

	if ((sp = malloc(sizeof (fmd_scheme_t))) == NULL ||
	    (sp->sch_name = strdup(name)) == NULL) {
		free(sp);
		return (NULL);
	}

	sp->sch_next = sch_list;
	sp->sch_dlp = NULL;
	sp->sch_err = 0;
	sp->sch_ops = _fmd_scheme_default_ops;

	sch_list = sp;
	return (sp);
}

static int
fmd_scheme_rtld_init(fmd_scheme_t *sp)
{
	const fmd_scheme_opd_t *opd;
	void *p;

	for (opd = _fmd_scheme_ops; opd->opd_name != NULL; opd++) {
		if ((p = dlsym(sp->sch_dlp, opd->opd_name)) != NULL)
			*(void **)((uintptr_t)&sp->sch_ops + opd->opd_off) = p;
	}

	return (sp->sch_ops.sop_init());
}

static fmd_scheme_t *
fmd_scheme_lookup(const char *dir, const char *name)
{
	fmd_scheme_t *sp;
	char path[PATH_MAX];

	for (sp = sch_list; sp != NULL; sp = sp->sch_next) {
		if (strcmp(name, sp->sch_name) == 0)
			return (sp);
	}

	if ((sp = fmd_scheme_create(name)) == NULL)
		return (NULL); /* errno is set for us */

	(void) snprintf(path, sizeof (path), "%s%s/%s.so",
	    g_root ? g_root : "", dir, name);

	if (access(path, F_OK) != 0) {
		sp->sch_err = errno;
		return (sp);
	}

	if ((sp->sch_dlp = dlopen(path, RTLD_LOCAL | RTLD_NOW)) == NULL) {
		sp->sch_err = ELIBACC;
		return (sp);
	}

	if (fmd_scheme_rtld_init(sp) != 0) {
		sp->sch_err = errno;
		(void) dlclose(sp->sch_dlp);
		sp->sch_dlp = NULL;
	}

	return (sp);
}

char *
fmdump_nvl2str(nvlist_t *nvl)
{
	fmd_scheme_t *sp;
	char c, *name, *s = NULL;
	ssize_t len;

	if (nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &name) != 0) {
		fmdump_warn("fmri does not contain required '%s' nvpair\n",
		    FM_FMRI_SCHEME);
		return (NULL);
	}

	if ((sp = fmd_scheme_lookup("/usr/lib/fm/fmd/schemes", name)) == NULL ||
	    sp->sch_dlp == NULL || sp->sch_err != 0) {
		const char *msg =
		    sp->sch_err == ELIBACC ? dlerror() : strerror(sp->sch_err);

		fmdump_warn("cannot init '%s' scheme library to "
		    "format fmri: %s\n", name, msg ? msg : "unknown error");

		return (NULL);
	}

	if ((len = sp->sch_ops.sop_nvl2str(nvl, &c, sizeof (c))) == -1 ||
	    (s = malloc(len + 1)) == NULL ||
	    sp->sch_ops.sop_nvl2str(nvl, s, len + 1) == -1) {
		fmdump_warn("cannot format fmri using scheme '%s'", name);
		free(s);
		return (NULL);
	}

	return (s);
}


void *
fmd_fmri_alloc(size_t size)
{
	return (malloc(size));
}

void *
fmd_fmri_zalloc(size_t size)
{
	void *data;

	if ((data = malloc(size)) != NULL)
		bzero(data, size);

	return (data);
}

/*ARGSUSED*/
void
fmd_fmri_free(void *data, size_t size)
{
	free(data);
}

int
fmd_fmri_error(int err)
{
	errno = err;
	return (-1);
}

char *
fmd_fmri_strescape(const char *s)
{
	return (strdup(s));
}

char *
fmd_fmri_strdup(const char *s)
{
	return (strdup(s));
}

void
fmd_fmri_strfree(char *s)
{
	free(s);
}

const char *
fmd_fmri_get_rootdir(void)
{
	return (g_root ? g_root : "");
}

const char *
fmd_fmri_get_platform(void)
{
	static char platform[MAXNAMELEN];

	if (platform[0] == '\0')
		(void) sysinfo(SI_PLATFORM, platform, sizeof (platform));

	return (platform);
}

uint64_t
fmd_fmri_get_drgen(void)
{
	return (0);
}

int
fmd_fmri_set_errno(int err)
{
	errno = err;
	return (-1);
}

void
fmd_fmri_warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fmdump_vwarn(format, ap);
	va_end(ap);
}

struct topo_hdl *
fmd_fmri_topo_hold(int version)
{
	int err;

	if (version != TOPO_VERSION)
		return (NULL);

	if (g_thp == NULL) {
		if ((g_thp = topo_open(TOPO_VERSION, "/", &err)) == NULL) {
			(void) fprintf(stderr, "topo_open failed: %s\n",
			    topo_strerror(err));
			exit(1);
		}
	}

	return (g_thp);
}

/*ARGSUSED*/
void
fmd_fmri_topo_rele(struct topo_hdl *thp)
{
	/* nothing to do */
}
