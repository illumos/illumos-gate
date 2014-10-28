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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_demangle.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

#include <demangle.h>
#include <strings.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>

#ifdef _LP64
static const char LIB_DEMANGLE[] = "/usr/lib/64/libdemangle.so.1";
#else
static const char LIB_DEMANGLE[] = "/usr/lib/libdemangle.so.1";
#endif

mdb_demangler_t *
mdb_dem_load(const char *path)
{
	mdb_demangler_t *dmp;
	void *hdl, *func;

	if (access(path, F_OK) == -1)
		return (NULL);

	if ((hdl = dlmopen(LM_ID_BASE, path, RTLD_LAZY | RTLD_LOCAL)) == NULL) {
		(void) set_errno(EMDB_RTLD);
		return (NULL);
	}

	if ((func = dlsym(hdl, "cplus_demangle")) == NULL) {
		(void) dlclose(hdl);
		(void) set_errno(EMDB_NODEM);
		return (NULL);
	}

	dmp = mdb_alloc(sizeof (mdb_demangler_t), UM_SLEEP);
	(void) strncpy(dmp->dm_pathname, path, MAXPATHLEN);
	dmp->dm_pathname[MAXPATHLEN - 1] = '\0';
	dmp->dm_handle = hdl;
	dmp->dm_convert = (int (*)())func;
	dmp->dm_len = MDB_SYM_NAMLEN * 2;
	dmp->dm_buf = mdb_alloc(dmp->dm_len, UM_SLEEP);
	dmp->dm_flags = MDB_DM_SCOPE;

	return (dmp);
}

void
mdb_dem_unload(mdb_demangler_t *dmp)
{
	(void) dlclose(dmp->dm_handle);
	mdb_free(dmp->dm_buf, dmp->dm_len);
	mdb_free(dmp, sizeof (mdb_demangler_t));
}

static const char *
mdb_dem_filter(mdb_demangler_t *dmp, const char *name)
{
	static const char s_pref[] = "static ";
	static const char c_suff[] = " const";
	static const char v_suff[] = " volatile";

	/*
	 * We process dm_dem, which skips the prefix in dm_buf (if any)
	 */
	size_t len = strlen(dmp->dm_dem);
	char *end = dmp->dm_dem + len;
	size_t resid;

	/*
	 * If static, const, and volatile qualifiers should not be displayed,
	 * rip all of them out of dmp->dm_dem.
	 */
	if (!(dmp->dm_flags & MDB_DM_QUAL)) {
		if (strncmp(dmp->dm_dem, s_pref, sizeof (s_pref) - 1) == 0) {
			bcopy(dmp->dm_dem + sizeof (s_pref) - 1, dmp->dm_dem,
			    len - (sizeof (s_pref) - 1) + 1);
			end -= sizeof (s_pref) - 1;
			len -= sizeof (s_pref) - 1;
		}

		for (;;) {
			if (len > sizeof (c_suff) - 1 &&
			    strcmp(end - (sizeof (c_suff) - 1), c_suff) == 0) {
				end -= sizeof (c_suff) - 1;
				len -= sizeof (c_suff) - 1;
				*end = '\0';
				continue;
			}
			if (len > sizeof (v_suff) - 1 &&
			    strcmp(end - (sizeof (v_suff) - 1), v_suff) == 0) {
				end -= sizeof (v_suff) - 1;
				len -= sizeof (v_suff) - 1;
				*end = '\0';
				continue;
			}
			break;
		}
	}

	/*
	 * If function arguments should not be displayed, remove everything
	 * between the outermost set of parentheses in dmp->dm_dem.
	 */
	if (!(dmp->dm_flags & MDB_DM_FUNCARG)) {
		char *lp = strchr(dmp->dm_dem, '(');
		char *rp = strrchr(dmp->dm_dem, ')');

		if (lp != NULL && rp != NULL)
			bcopy(rp + 1, lp, strlen(rp) + 1);
	}

	/*
	 * If function scope specifiers should not be displayed, remove text
	 * from the leftmost space to the rightmost colon prior to any paren.
	 */
	if (!(dmp->dm_flags & MDB_DM_SCOPE)) {
		char *c, *s, *lp = strchr(dmp->dm_dem, '(');

		if (lp != NULL)
			*lp = '\0';

		c = strrchr(dmp->dm_dem, ':');
		s = strchr(dmp->dm_dem, ' ');

		if (lp != NULL)
			*lp = '(';

		if (c != NULL) {
			if (s == NULL || s > c)
				bcopy(c + 1, dmp->dm_dem, strlen(c + 1) + 1);
			else
				bcopy(c + 1, s + 1, strlen(c + 1) + 1);
		}
	}

	len = strlen(dmp->dm_dem); /* recompute length of buffer */

	/*
	 * Compute bytes remaining
	 */
	resid = (dmp->dm_buf + dmp->dm_len) - (dmp->dm_dem + len);

	/*
	 * If we want to append the mangled name as well and there is enough
	 * space for "[]\0" and at least one character, append "["+name+"]".
	 */
	if ((dmp->dm_flags & MDB_DM_MANGLED) && resid > 3) {
		char *p = dmp->dm_dem + len;

		*p++ = '[';
		(void) strncpy(p, name, resid - 3);
		p[resid - 3] = '\0';
		p += strlen(p);
		(void) strcpy(p, "]");
	}

	/*
	 * We return the whole string
	 */
	return (dmp->dm_buf);
}

/*
 * Take a name: (the foo`bar` is optional)
 *	foo`bar`__mangled_
 * and put:
 *	foo`bar`demangled
 * into dmp->dm_buf.  Point dmp->dm_dem to the beginning of the
 * demangled section of the result.
 */
static int
mdb_dem_process(mdb_demangler_t *dmp, const char *name)
{
	char *buf = dmp->dm_buf;
	size_t len = dmp->dm_len;

	char *prefix = strrchr(name, '`');
	size_t prefixlen;

	if (prefix) {
		prefix++;		/* the ` is part of the prefix */
		prefixlen = prefix - name;

		if (prefixlen >= len)
			return (DEMANGLE_ESPACE);

		(void) strncpy(buf, name, prefixlen);

		/*
		 * Fix up the arguments to dmp->dm_convert()
		 */
		name += prefixlen;
		buf += prefixlen;
		len -= prefixlen;
	}

	/*
	 * Save the position of the demangled string for mdb_dem_filter()
	 */
	dmp->dm_dem = buf;

	return (dmp->dm_convert(name, buf, len));
}

const char *
mdb_dem_convert(mdb_demangler_t *dmp, const char *name)
{
	int err;

	while ((err = mdb_dem_process(dmp, name)) == DEMANGLE_ESPACE) {
		size_t len = dmp->dm_len * 2;
		char *buf = mdb_alloc(len, UM_NOSLEEP);

		if (buf == NULL) {
			mdb_warn("failed to allocate memory for demangling");
			return (name); /* just return original name */
		}

		mdb_free(dmp->dm_buf, dmp->dm_len);
		dmp->dm_buf = buf;
		dmp->dm_len = len;
	}

	if (err != 0 || strcmp(dmp->dm_buf, name) == 0)
		return (name); /* return original name if not mangled */

	return (mdb_dem_filter(dmp, name));
}

/*ARGSUSED*/
int
cmd_demangle(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_demangler_t *dmp = mdb.m_demangler;
	const char *path;
	char buf[MAXPATHLEN];

	if (argc > 1 || (argc > 0 && argv->a_type != MDB_TYPE_STRING))
		return (DCMD_USAGE);

	if (argc > 0) {
		if (dmp != NULL)
			mdb_dem_unload(mdb.m_demangler);
		path = argv->a_un.a_str;
	} else {
		(void) snprintf(buf, MAXPATHLEN,
		    "%s/%s", mdb.m_root, LIB_DEMANGLE);
		path = buf;
	}

	if (dmp != NULL && argc == 0 && !(mdb.m_flags & MDB_FL_DEMANGLE)) {
		mdb_printf("C++ symbol demangling enabled\n");
		mdb.m_flags |= MDB_FL_DEMANGLE;

	} else if (dmp == NULL || argc > 0) {
		if ((mdb.m_demangler = mdb_dem_load(path)) != NULL) {
			mdb_printf("C++ symbol demangling enabled\n");
			mdb.m_flags |= MDB_FL_DEMANGLE;
		} else {
			mdb_warn("failed to load C++ demangler %s", path);
			mdb.m_flags &= ~MDB_FL_DEMANGLE;
		}

	} else {
		mdb_dem_unload(mdb.m_demangler);
		mdb.m_flags &= ~MDB_FL_DEMANGLE;
		mdb.m_demangler = NULL;
		mdb_printf("C++ symbol demangling disabled\n");
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
int
cmd_demflags(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	static const char *const dm_desc[] = {
		"static/const/volatile member func qualifiers displayed",
		"scope resolution specifiers displayed",
		"function arguments displayed",
		"mangled name displayed"
	};

	mdb_demangler_t *dmp = mdb.m_demangler;
	int i;

	if (argc > 0)
		return (DCMD_USAGE);

	if (dmp == NULL || !(mdb.m_flags & MDB_FL_DEMANGLE)) {
		mdb_warn("C++ demangling facility is currently disabled\n");
		return (DCMD_ERR);
	}

	if (flags & DCMD_ADDRSPEC)
		dmp->dm_flags = ((uint_t)addr & MDB_DM_ALL);

	for (i = 0; i < sizeof (dm_desc) / sizeof (dm_desc[0]); i++) {
		mdb_printf("0x%x\t%s\t%s\n", 1 << i,
		    (dmp->dm_flags & (1 << i)) ? "on" : "off", dm_desc[i]);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
int
cmd_demstr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags & DCMD_ADDRSPEC) || argc == 0)
		return (DCMD_USAGE);

	if (mdb.m_demangler == NULL && (mdb.m_demangler =
	    mdb_dem_load(LIB_DEMANGLE)) == NULL) {
		mdb_warn("failed to load C++ demangler %s", LIB_DEMANGLE);
		return (DCMD_ERR);
	}

	for (; argc != 0; argc--, argv++) {
		mdb_printf("%s == %s\n", argv->a_un.a_str,
		    mdb_dem_convert(mdb.m_demangler, argv->a_un.a_str));
	}

	return (DCMD_OK);
}
