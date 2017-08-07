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

/*
 * libfstyp module for zfs
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <string.h>
#include <libnvpair.h>
#include <libzfs.h>
#include <libfstyp_module.h>
#include <errno.h>

struct fstyp_zfs {
	int		fd;
	nvlist_t	*config;
};

int	fstyp_mod_init(int fd, off_t offset, fstyp_mod_handle_t *handle);
void	fstyp_mod_fini(fstyp_mod_handle_t handle);
int	fstyp_mod_ident(fstyp_mod_handle_t handle);
int	fstyp_mod_get_attr(fstyp_mod_handle_t handle, nvlist_t **attrp);

int
fstyp_mod_init(int fd, off_t offset, fstyp_mod_handle_t *handle)
{
	struct fstyp_zfs *h;

	if (offset != 0) {
		return (FSTYP_ERR_OFFSET);
	}

	if ((h = calloc(1, sizeof (struct fstyp_zfs))) == NULL) {
		return (FSTYP_ERR_NOMEM);
	}
	h->fd = fd;

	*handle = (fstyp_mod_handle_t)h;
	return (0);
}

void
fstyp_mod_fini(fstyp_mod_handle_t handle)
{
	struct fstyp_zfs *h = (struct fstyp_zfs *)handle;

	if (h->config != NULL) {
		nvlist_free(h->config);
	}
	free(h);
}

int
fstyp_mod_ident(fstyp_mod_handle_t handle)
{
	struct fstyp_zfs *h = (struct fstyp_zfs *)handle;
	uint64_t state;
	char	*str;
	uint64_t u64;
	char	buf[64];

	if (zpool_read_label(h->fd, &h->config) != 0) {
		return (FSTYP_ERR_NO_MATCH);
	}

	if (nvlist_lookup_uint64(h->config, ZPOOL_CONFIG_POOL_STATE,
	    &state) != 0 || state == POOL_STATE_DESTROYED) {
		nvlist_free(h->config);
		h->config = NULL;
		return (FSTYP_ERR_NO_MATCH);
	}

	/* add generic attributes */
	(void) nvlist_add_boolean_value(h->config, "gen_clean", B_TRUE);
	if (nvlist_lookup_uint64(h->config, "guid", &u64) == 0) {
		(void) snprintf(buf, sizeof (buf), "%llu", (u_longlong_t)u64);
		(void) nvlist_add_string(h->config, "gen_guid", buf);
	}
	if (nvlist_lookup_uint64(h->config, "version", &u64) == 0) {
		(void) snprintf(buf, sizeof (buf), "%llu", (u_longlong_t)u64);
		(void) nvlist_add_string(h->config, "gen_version", buf);
	}
	if (nvlist_lookup_string(h->config, "name", &str) == 0) {
		(void) nvlist_add_string(h->config, "gen_volume_label", str);
	}

	return (0);
}

int
fstyp_mod_get_attr(fstyp_mod_handle_t handle, nvlist_t **attrp)
{
	struct fstyp_zfs *h = (struct fstyp_zfs *)handle;

	*attrp = h->config;
	return (0);
}
