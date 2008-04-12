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

#include <sys/spa.h>
#include <sys/bootconf.h>

char *
spa_get_bootfs()
{
	int proplen;
	char *zfs_bp;

	proplen = BOP_GETPROPLEN(bootops, "zfs-bootfs");
	if (proplen == 0)
		return (NULL);

	zfs_bp = kmem_zalloc(proplen, KM_SLEEP);
	if (BOP_GETPROP(bootops, "zfs-bootfs", zfs_bp) == -1) {
		kmem_free(zfs_bp, proplen);
		return (NULL);
	}

	return (zfs_bp);
}

void
spa_free_bootfs(char *bootfs)
{
	kmem_free(bootfs, strlen(bootfs) + 1);
}

/*
 * Given the boot device physpath, check if the device is in a valid state.
 * If so, return the configuration from the vdev label.
 */
int
spa_get_rootconf(char *devpath, char **bestdev, nvlist_t **bestconf)
{
	nvlist_t *conf = NULL;
	char *dev = NULL;
	uint64_t txg = 0;
	nvlist_t *nvtop, **child;
	char *type;
	uint_t children, c;

	spa_check_rootconf(devpath, &dev, &conf, &txg);
	if (txg == 0 || conf == NULL)
		return (EINVAL);

	VERIFY(nvlist_lookup_nvlist(conf, ZPOOL_CONFIG_VDEV_TREE,
	    &nvtop) == 0);
	VERIFY(nvlist_lookup_string(nvtop, ZPOOL_CONFIG_TYPE, &type) == 0);

	if (strcmp(type, VDEV_TYPE_DISK) == 0) {
		if (spa_rootdev_validate(nvtop))
			goto out;
		else
			return (EINVAL);
	}

	ASSERT(strcmp(type, VDEV_TYPE_MIRROR) == 0);

	VERIFY(nvlist_lookup_nvlist_array(nvtop, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0);

	/*
	 * Go thru vdevs in the mirror to see if the given device (devpath)
	 * is in a healthy state. Also check if the given device has the most
	 * recent txg. Only the device with the most recent txg has valid
	 * information and can be booted.
	 */
	for (c = 0; c < children; c++) {
		char *physpath;

		if (nvlist_lookup_string(child[c], ZPOOL_CONFIG_PHYS_PATH,
		    &physpath) != 0)
			return (EINVAL);

		if (strcmp(devpath, physpath) == 0) {
			if (!spa_rootdev_validate(child[c]))
				return (EINVAL);
		} else {
			/* get dev with the highest txg */
			if (spa_rootdev_validate(child[c])) {
				spa_check_rootconf(physpath, &dev,
				    &conf, &txg);
			}
		}
	}

	/* Does the given device have the most recent txg? */
	if (strcmp(devpath, dev) != 0)
		return (EINVAL);
out:
	*bestdev = dev;
	*bestconf = conf;
	return (0);
}
