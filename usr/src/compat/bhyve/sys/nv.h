/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _COMPAT_FREEBSD_SYS_NV_H_
#define	_COMPAT_FREEBSD_SYS_NV_H_

#include <assert.h>
#include <libnvpair.h>

#define	NV_TYPE_NVLIST	DATA_TYPE_NVLIST
#define	NV_TYPE_STRING	DATA_TYPE_STRING

static inline const char *
nvlist_next(const nvlist_t *nvl, int *type, void **cookie)
{
	nvpair_t *nvp = *cookie;

	nvp = nvlist_next_nvpair((nvlist_t *)nvl, nvp);
	if (nvp == NULL)
		return (NULL);

	*cookie = nvp;
	*type = nvpair_type(nvp);
	return (nvpair_name(nvp));
}

static inline nvlist_t *
nvlist_create(int flag)
{
	nvlist_t *nvl;

	/*
	 * We only emulate this with flag == 0, which is equivalent to the
	 * illumos NV_UNIQUE_NAME.
	 */
	assert(flag == 0);

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
		return (NULL);
	return (nvl);
}

static inline bool
nvlist_exists_nvlist(const nvlist_t *nvl, const char *name)
{
	nvlist_t *snvl;

	return (nvlist_lookup_nvlist((nvlist_t *)nvl, name, &snvl) == 0);
}

static inline nvlist_t *
nvlist_get_nvlist(const nvlist_t *nvl, const char *name)
{
	nvlist_t *snvl;

	if (nvlist_lookup_nvlist((nvlist_t *)nvl, name, &snvl) == 0)
		return (snvl);
	return (NULL);
}

static inline bool
nvlist_exists_string(const nvlist_t *nvl, const char *name)
{
	char *str;

	return (nvlist_lookup_string((nvlist_t *)nvl, name, &str) == 0);
}

static inline char *
nvlist_get_string(const nvlist_t *nvl, const char *name)
{
	char *str;

	if (nvlist_lookup_string((nvlist_t *)nvl, name, &str) == 0)
		return (str);
	return (NULL);
}

#define nvlist_free_string(nvl, name) nvlist_remove_all((nvl), (name))

#endif /* _COMPAT_FREEBSD_SYS_NV_H_ */
