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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2013 Joyent, Inc. All rights reserved.
 */

#include <sys/param.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <dlfcn.h>
#include <ctype.h>
#include <link.h>

#include <mdb/mdb_module.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb.h>

typedef struct mdb_modload_data {
	int mld_first;
	int mld_mode;
} mdb_modload_data_t;

#ifndef _KMDB
static int
mdb_module_load_targmod(const char *name, char *buf, size_t buflen,
    uintptr_t targaddr, uintptr_t targsize)
{
	int fd, ret;
	char *template = "/tmp/.mdb_mod_%s.pid%d.XXXXXX";

	(void) mdb_iob_snprintf(buf, buflen, template, name, getpid());
	fd = mkstemp(buf);
	if (fd == -1) {
		mdb_printf("failed to create temporary file "
		    "for dmod %s: %s\n", buf,
		    strerror(errno));
		return (-1);
	}
	ret = mdb_module_dumpfd(fd, targaddr, targsize);
	(void) close(fd);
	if (ret != 0)
		(void) unlink(buf);

	return (ret);
}

static int
mdb_module_load_fromtarg(const char *mname, char *pathbuf, size_t buflen)
{
	char buf[256], name[256];
	char *p;
	GElf_Sym sym;

	if (mdb.m_target == NULL)
		return (1);

	/*
	 * See mdb_module_load() for details about the symbol names we test for
	 * here.
	 */
	(void) strlcpy(name, mname, sizeof (name));
	if ((p = strrchr(name, '.')) != NULL && *++p != '\0') {
		if (strisnum(p) || strcmp(p, "so") == 0) {
			(void) mdb_iob_snprintf(buf, sizeof (buf),
			    "mdb_%s_start", name);
			if (mdb_lookup_by_name(buf, &sym) == 0)
				goto found;
		}

		while (strisnum(p) && (p = strrchr(name, '.')) != NULL) {
			*p = '\0'; /* strip trailing digits */
			(void) mdb_iob_snprintf(buf, sizeof (buf),
			    "mdb_%s_start", name);
			if (mdb_lookup_by_name(buf, &sym) == 0)
				goto found;
		}
	}

	(void) mdb_iob_snprintf(buf, sizeof (buf), "mdb_%s.so_start",
	    mname);
	if (mdb_lookup_by_name(buf, &sym) == 0)
		goto found;

	return (1);

found:
	return (mdb_module_load_targmod(mname, pathbuf, buflen,
	    sym.st_value, sym.st_size));
}

typedef struct mdb_autoload_arg {
	int			ma_found;
	mdb_modload_data_t 	*ma_mld;
} mdb_autoload_arg_t;

/*
 * A valid key that we care about will look like: mdb_<module>_start. The module
 * name will end up being everything inbetween.
 */
static int
mdb_module_autoload_cb(mdb_symbol_t *sym, void *arg)
{
	static const char *lead = "mdb_", *end = "_start";
	static int llen = 4, elen = 6;
	char *errstr;
	char buf[256], createbuf[256];
	int len = strlen(sym->sym_name);
	mdb_autoload_arg_t *map = arg;
	int ret;

	if (len < llen + elen + 1)
		return (0);

	if (strncmp(lead, sym->sym_name, strlen(lead)) != 0)
		return (0);

	if (strcmp(end, sym->sym_name + len - elen) != 0)
		return (0);

	(void) strlcpy(buf, sym->sym_name + llen, sizeof (buf));
	buf[len - llen - elen] = '\0';

	if (!mdb_module_validate_name(buf, (const char **)&errstr))
		return (0);

	ret = mdb_module_load_targmod(buf, createbuf, sizeof (createbuf),
	    sym->sym_sym->st_value, sym->sym_sym->st_size);
	if (ret != 0) {
		mdb_printf("failed to load module %s from target\n", buf);
		return (0);
	}
	ret = mdb_module_create(buf, createbuf, map->ma_mld->mld_mode, NULL);
	if (ret == 0) {
		map->ma_found++;
		if (mdb.m_term != NULL) {
			if (map->ma_mld->mld_first == TRUE) {
				mdb_iob_puts(mdb.m_out, "Loading modules: [");
				map->ma_mld->mld_first = FALSE;
			}
			mdb_iob_printf(mdb.m_out, " %s", buf);
			mdb_iob_flush(mdb.m_out);
		}
	}
	(void) unlink(createbuf);

	return (0);
}

static int
mdb_module_autoload_targ(const char *mname, mdb_modload_data_t *mlp)
{
	mdb_autoload_arg_t ma;
	ma.ma_found = 0;
	ma.ma_mld = mlp;
	mdb_symbol_iter(mname, MDB_SYMTAB,
	    MDB_BIND_ANY | MDB_TYPE_OBJECT, mdb_module_autoload_cb, &ma);
	return (ma.ma_found);
}
#endif /* _KMDB */

int
mdb_module_load(const char *name, int mode)
{
	const char *wformat = "no module '%s' could be found\n";
	const char *fullname = NULL;
	char buf[MAXPATHLEN], *p, *q;
	int i;

	ASSERT(!(mode & MDB_MOD_DEFER));

	if (strchr(name, '/') != NULL) {
		ASSERT(!(mode & MDB_MOD_BUILTIN));

		(void) mdb_iob_snprintf(buf, sizeof (buf), "%s",
		    strbasename(name));

		/*
		 * Remove any .so(.[0-9]+)? suffix
		 */
		while ((p = strrchr(buf, '.')) != NULL) {
			for (q = p + 1; isdigit(*q); q++)
				;

			if (*q == '\0') {
				/* found digits to remove */
				*p = '\0';
				continue;
			}

			if (strcmp(p, ".so") == 0) {
				*p = '\0';
				break;
			}

		}
		fullname = name;
		name = buf;
	}

	if (!mdb_module_validate_name(name, &wformat))
		goto err;

	if (fullname != NULL) {
		if (access(fullname, F_OK) != 0) {
			name = fullname; /* for warn() below */
			goto err;
		}
		return (mdb_module_create(name, fullname, mode, NULL));
	}

	/*
	 * If a simple name is specified, search of a symbol called
	 * mdb_<module>_start in the target itself. If that fails, search the
	 * module apth in order, and for each element look for the following
	 * files:
	 *
	 * 1. If the module name ends in ".so(.[0-9]+)?", search for the literal
	 *    name and then search for the name without the [0-9]+ suffix.
	 * 2. If the module name ends in ".so", search for the literal name.
	 * 3. Search for the module name with ".so" appended.
	 *
	 * Once a matching file is detected, we attempt to load that module
	 * and do not resume our search in the case of an error.
	 */

#ifndef	_KMDB
	/* Search the target */
	i = mdb_module_load_fromtarg(name, buf, sizeof (buf));
	if (i == -1)
		goto err;
	if (i == 0) {
		i = mdb_module_create(name, buf, mode, NULL);
		(void) unlink(buf);
		return (i);
	}
#endif	/* _KMDB */

	/* Start searching the module path */
	for (i = 0; mdb.m_lpath[i] != NULL; i++) {
		if ((p = strrchr(name, '.')) != NULL && *++p != '\0') {
			if (strisnum(p) || strcmp(p, "so") == 0) {
				(void) mdb_iob_snprintf(buf, sizeof (buf),
				    "%s/%s", mdb.m_lpath[i], name);
				mdb_dprintf(MDB_DBG_MODULE,
				    "checking for %s\n", buf);
				if (access(buf, F_OK) == 0) {
					return (mdb_module_create(name, buf,
					    mode, NULL));
				}
			}

			while (strisnum(p) && (p = strrchr(buf, '.')) != NULL) {
				*p = '\0'; /* strip trailing digits */
				mdb_dprintf(MDB_DBG_MODULE,
				    "checking for %s\n", buf);
				if (access(buf, F_OK) == 0) {
					return (mdb_module_create(name, buf,
					    mode, NULL));
				}
			}
		}

		(void) mdb_iob_snprintf(buf, sizeof (buf), "%s/%s.so",
		    mdb.m_lpath[i], name);

		mdb_dprintf(MDB_DBG_MODULE, "checking for %s\n", buf);

		if (access(buf, F_OK) == 0)
			return (mdb_module_create(name, buf, mode, NULL));
	}
err:
	if (!(mode & MDB_MOD_SILENT))
		warn(wformat, name);

	return (-1);
}

/*ARGSUSED*/
static int
module_load(void *fp, const mdb_map_t *map, const char *fullname)
{
	int ret = 0;
	mdb_modload_data_t *mld = fp;
	const char *name = strbasename(fullname);
#ifndef _KMDB
	(void) mdb_module_autoload_targ(name, mld);
#endif	/* ! _KMDB */

	if (mdb_module_load(name, mld->mld_mode) == 0 && mdb.m_term != NULL) {
		if (mld->mld_first == TRUE) {
			mdb_iob_puts(mdb.m_out, "Loading modules: [");
			mld->mld_first = FALSE;
		}
		mdb_iob_printf(mdb.m_out, " %s", name);
		mdb_iob_flush(mdb.m_out);
	}

	if (strstr(fullname, "/libc/") != NULL) {
		/*
		 * A bit of a kludge:  because we manage alternately capable
		 * libc instances by mounting the appropriately capable
		 * instance over /lib/libc.so.1, we may find that our object
		 * list does not contain libc.so.1, but rather one of its
		 * hwcap variants.  Unfortunately, there is not a way of
		 * getting from this shared object to the object that it is
		 * effectively interposing on -- which means that without
		 * special processing, we will not load any libc.so dmod.  So
		 * if we see that we have a shared object coming out of the
		 * "libc" directory, we assume that we have a "libc-like"
		 * object, and explicitly load the "libc.so" dmod.
		 */
		return (module_load(fp, map, "libc.so.1"));
	}

	return (0);
}

void
mdb_module_load_all(int mode)
{
	uint_t oflag = mdb_iob_getflags(mdb.m_out) & MDB_IOB_PGENABLE;
	mdb_modload_data_t mld;

	mld.mld_first = TRUE;
	mld.mld_mode = mode | MDB_MOD_LOCAL | MDB_MOD_SILENT;

	mdb_iob_clrflags(mdb.m_out, oflag);

	(void) mdb_tgt_object_iter(mdb.m_target, module_load, &mld);

	if (mdb.m_term != NULL && mld.mld_first == FALSE)
		mdb_iob_puts(mdb.m_out, " ]\n");

	mdb_iob_setflags(mdb.m_out, oflag);
}

/*ARGSUSED*/
int
mdb_module_unload(const char *name, int mode)
{
	ASSERT((mode & ~MDB_MOD_SILENT) == 0);

	return (mdb_module_unload_common(name));
}
