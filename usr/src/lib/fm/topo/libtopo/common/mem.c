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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <errno.h>
#include <kstat.h>
#include <limits.h>
#include <strings.h>
#include <unistd.h>
#include <topo_error.h>
#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>

#include <topo_method.h>
#include <mem.h>

/*
 * platform specific mem module
 */
#define	PLATFORM_MEM_VERSION	MEM_VERSION
#define	PLATFORM_MEM_NAME	"platform-mem"

static int mem_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void mem_release(topo_mod_t *, tnode_t *);
static int mem_nvl2str(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int mem_fmri_create(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static const topo_method_t mem_methods[] = {
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, mem_nvl2str },
	{ TOPO_METH_FMRI, TOPO_METH_FMRI_DESC, TOPO_METH_FMRI_VERSION,
	    TOPO_STABILITY_INTERNAL, mem_fmri_create },
	{ NULL }
};

static const topo_modops_t mem_ops =
	{ mem_enum, mem_release };
static const topo_modinfo_t mem_info =
	{ "mem", FM_FMRI_SCHEME_MEM, MEM_VERSION, &mem_ops };

int
mem_init(topo_mod_t *mod, topo_version_t version)
{

	topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing mem builtin\n");

	if (version != MEM_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_mod_register(mod, &mem_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register mem_info: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1); /* mod errno already set */
	}

	return (0);
}

void
mem_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

/*ARGSUSED*/
static int
mem_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused1, void *notused2)
{
	topo_mod_t *nmp;

	if ((nmp = topo_mod_load(mod, PLATFORM_MEM_NAME,
	    PLATFORM_MEM_VERSION)) == NULL) {
		if (topo_mod_errno(mod) == ETOPO_MOD_NOENT) {
			/*
			 * There is no platform specific mem module.
			 */
			(void) topo_method_register(mod, pnode, mem_methods);
			return (0);
		} else {
			/* Fail to load the module */
			topo_mod_dprintf(mod, "Failed to load module %s: %s",
			    PLATFORM_MEM_NAME, topo_mod_errmsg(mod));
			return (-1);
		}
	}

	if (topo_mod_enumerate(nmp, pnode, PLATFORM_MEM_NAME, name,
	    min, max, NULL) < 0) {
		topo_mod_dprintf(mod, "%s failed to enumerate: %s",
		    PLATFORM_MEM_NAME, topo_mod_errmsg(mod));
		return (-1);
	}
	(void) topo_method_register(mod, pnode, mem_methods);

	return (0);
}

static void
mem_release(topo_mod_t *mod, tnode_t *node)
{
	topo_method_unregister_all(mod, node);
}

/*
 * Convert an input string to a URI escaped string and return the new string.
 * RFC2396 Section 2.4 says that data must be escaped if it does not have a
 * representation using an unreserved character, where an unreserved character
 * is one that is either alphanumeric or one of the marks defined in S2.3.
 */
static size_t
mem_fmri_uriescape(const char *s, const char *xmark, char *buf, size_t len)
{
	static const char rfc2396_mark[] = "-_.!~*'()";
	static const char hex_digits[] = "0123456789ABCDEF";
	static const char empty_str[] = "";

	const char *p;
	char c, *q;
	size_t n = 0;

	if (s == NULL)
		s = empty_str;

	if (xmark == NULL)
		xmark = empty_str;

	for (p = s; (c = *p) != '\0'; p++) {
		if (isalnum(c) || strchr(rfc2396_mark, c) || strchr(xmark, c))
			n++;    /* represent c as itself */
		else
			n += 3; /* represent c as escape */
	}

	if (buf == NULL)
		return (n);

	for (p = s, q = buf; (c = *p) != '\0' && q < buf + len; p++) {
		if (isalnum(c) || strchr(rfc2396_mark, c) || strchr(xmark, c)) {
			*q++ = c;
		} else {
			*q++ = '%';
			*q++ = hex_digits[((uchar_t)c & 0xf0) >> 4];
			*q++ = hex_digits[(uchar_t)c & 0xf];
		}
	}

	if (q == buf + len)
		q--; /* len is too small: truncate output string */

	*q = '\0';
	return (n);
}

/*ARGSUSED*/
static int
mem_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	const char *format;
	nvlist_t *nvl;
	uint64_t val;
	char *buf, *unum;
	size_t len;
	int err;
	char *preunum, *escunum, *prefix;
	ssize_t presz;
	int i;

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (nvlist_lookup_string(in, FM_FMRI_MEM_UNUM, &unum) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	/*
	 * If we have a DIMM offset, include it in the string.  If we have a
	 * PA then use that.  Otherwise just format the unum element.
	 */
	if (nvlist_lookup_uint64(in, FM_FMRI_MEM_OFFSET, &val) == 0) {
		format = FM_FMRI_SCHEME_MEM ":///%1$s%2$s/"
		    FM_FMRI_MEM_OFFSET "=%3$llx";
	} else if (nvlist_lookup_uint64(in, FM_FMRI_MEM_PHYSADDR, &val) == 0) {
		format = FM_FMRI_SCHEME_MEM ":///%1$s%2$s/"
		    FM_FMRI_MEM_PHYSADDR "=%3$llx";
	} else
		format = FM_FMRI_SCHEME_MEM ":///%1$s%2$s";

	/*
	 * If we have a well-formed unum we step over the hc:// and
	 * authority prefix
	 */
	if (strncmp(unum, "hc://", 5) == 0) {
		unum += 5;
		unum = strchr(unum, '/');
		++unum;
		prefix = "";
		escunum = unum;
	} else {
		prefix = FM_FMRI_MEM_UNUM "=";
		preunum = topo_mod_strdup(mod, unum);
		presz = strlen(preunum) + 1;

		for (i = 0; i < presz - 1; i++) {
			if (preunum[i] == ':' && preunum[i + 1] == ' ') {
				bcopy(preunum + i + 2, preunum + i + 1,
				    presz - (i + 2));
			} else if (preunum[i] == ' ') {
				preunum[i] = ',';
			}
		}

		i = mem_fmri_uriescape(preunum, ":,/", NULL, 0);
		escunum = topo_mod_alloc(mod, i + 1);
		(void) mem_fmri_uriescape(preunum, ":,/", escunum, i + 1);
		topo_mod_free(mod, preunum, presz);
	}

	len = snprintf(NULL, 0, format, prefix, escunum, val) + 1;
	buf = topo_mod_zalloc(mod, len);

	if (buf == NULL) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	(void) snprintf(buf, len, format, prefix, escunum, val);
	if (escunum != unum)
		topo_mod_strfree(mod, escunum);
	err = nvlist_add_string(nvl, "fmri-string", buf);
	topo_mod_free(mod, buf, len);

	if (err != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*out = nvl;
	return (0);
}

static nvlist_t *
mem_fmri(topo_mod_t *mod, uint64_t pa, uint64_t offset, char *unum, int flags)
{
	int err;
	nvlist_t *asru;

	if (topo_mod_nvalloc(mod, &asru, NV_UNIQUE_NAME) != 0)
		return (NULL);

	/*
	 * If we have a well-formed unum we step over the hc:/// and
	 * authority prefix
	 */
	if (strncmp(unum, "hc://", 5) == 0) {
		char *tstr;

		tstr = strchr(unum, '/');
		unum = ++tstr;
	}

	err = nvlist_add_uint8(asru, FM_VERSION, FM_MEM_SCHEME_VERSION);
	err |= nvlist_add_string(asru, FM_FMRI_SCHEME, FM_FMRI_SCHEME_MEM);
	err |= nvlist_add_string(asru, FM_FMRI_MEM_UNUM, unum);
	if (flags & TOPO_MEMFMRI_PA)
		err |= nvlist_add_uint64(asru, FM_FMRI_MEM_PHYSADDR, pa);
	if (flags & TOPO_MEMFMRI_OFFSET)
		err |= nvlist_add_uint64(asru, FM_FMRI_MEM_OFFSET, offset);

	if (err != 0) {
		nvlist_free(asru);
		return (NULL);
	}

	return (asru);
}

/*ARGSUSED*/
static int
mem_fmri_create(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint64_t pa = 0, offset = 0;
	int flags = 0;
	nvlist_t *asru;
	char *unum;

	if (nvlist_lookup_uint64(in, FM_FMRI_MEM_PHYSADDR, &pa) == 0)
		flags |= TOPO_MEMFMRI_PA;
	if (nvlist_lookup_uint64(in, FM_FMRI_MEM_OFFSET, &offset) == 0)
		flags |= TOPO_MEMFMRI_OFFSET;
	if (nvlist_lookup_string(in, FM_FMRI_MEM_UNUM, &unum) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	asru = mem_fmri(mod, pa, offset, unum, flags);

	if (asru == NULL)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	*out = asru;

	return (0);
}
