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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <alloca.h>
#include <limits.h>
#include <fm/topo_mod.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/fm/protocol.h>
#include <sys/stat.h>

#include <topo_method.h>
#include <topo_subr.h>
#include <legacy_hc.h>

static int legacy_hc_enum(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, topo_instance_t, void *, void *);
static void legacy_hc_release(topo_mod_t *, tnode_t *);
static int legacy_hc_fmri_nvl2str(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

const topo_method_t legacy_hc_methods[] = {
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, legacy_hc_fmri_nvl2str },
	{ NULL }
};

static const topo_modops_t legacy_hc_ops =
	{ legacy_hc_enum, legacy_hc_release };
static const topo_modinfo_t legacy_hc_info =
	{ LEGACY_HC, FM_FMRI_SCHEME_LEGACY, LEGACY_HC_VERSION, &legacy_hc_ops };

int
legacy_hc_init(topo_mod_t *mod, topo_version_t version)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOLEGACY_HCDEBUG"))
		topo_mod_setdebug(mod);

	topo_mod_dprintf(mod, "initializing legacy_hc builtin\n");

	if (version != LEGACY_HC_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_mod_register(mod, &legacy_hc_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register legacy_hc: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1); /* mod errno already set */
	}

	return (0);
}

void
legacy_hc_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}


/*ARGSUSED*/
int
legacy_hc_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused1, void *notused2)
{
	(void) topo_method_register(mod, pnode, legacy_hc_methods);
	return (0);
}

/*ARGSUSED*/
static void
legacy_hc_release(topo_mod_t *mp, tnode_t *node)
{
	topo_method_unregister_all(mp, node);
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

static ssize_t
fmri_nvl2str(topo_mod_t *mod, nvlist_t *nvl, char *buf, size_t buflen)
{
	uint8_t version;
	ssize_t size;
	char *c;
	char *escc;
	int i;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_LEGACY_SCHEME_VERSION ||
	    nvlist_lookup_string(nvl, FM_FMRI_LEGACY_HC, &c) != 0)
		return (0);

	i = mem_fmri_uriescape(c, ":,/", NULL, 0);
	escc = topo_mod_alloc(mod, i + 1);
	(void) mem_fmri_uriescape(c, ":,/", escc, i + 1);
	size = snprintf(buf, buflen, "legacy-hc:///component=%s", escc);
	topo_mod_free(mod, escc, i + 1);

	return (size);
}

/*ARGSUSED*/
static int
legacy_hc_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *nvl, nvlist_t **out)
{
	ssize_t len;
	char *name = NULL;
	nvlist_t *fmristr;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if ((len = fmri_nvl2str(mod, nvl, NULL, 0)) == 0 ||
	    (name = topo_mod_alloc(mod, len + 1)) == NULL ||
	    fmri_nvl2str(mod, nvl, name, len + 1) == 0) {
		if (name != NULL)
			topo_mod_free(mod, name, len + 1);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	if (topo_mod_nvalloc(mod, &fmristr, NV_UNIQUE_NAME) != 0) {
		topo_mod_free(mod, name, len + 1);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	if (nvlist_add_string(fmristr, "fmri-string", name) != 0) {
		topo_mod_free(mod, name, len + 1);
		nvlist_free(fmristr);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	topo_mod_free(mod, name, len + 1);
	*out = fmristr;

	return (0);
}
