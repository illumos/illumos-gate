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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <libdevinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/dkio.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <unistd.h>

#include "libdiskmgt.h"
#include "disks_private.h"

static int		get_status(disk_t *diskp, int fd, nvlist_t *attrs);

descriptor_t **
alias_get_assoc_descriptors(descriptor_t *desc, dm_desc_type_t type,
    int *errp)
{
	switch (type) {
	case DM_DRIVE:
	    return (drive_get_assocs(desc, errp));
	}

	*errp = EINVAL;
	return (NULL);
}

nvlist_t *
alias_get_attributes(descriptor_t *dp, int *errp)
{
	alias_t		*ap;
	nvlist_t	*attrs = NULL;

	/* Find the alias for this descriptor */

	*errp = ENODEV;
	for (ap = dp->p.disk->aliases; ap != NULL; ap = ap->next) {
	    if (libdiskmgt_str_eq(dp->name, ap->alias)) {
		/* we found the alias for this descriptor */

		if (nvlist_alloc(&attrs, NVATTRS, 0) != 0) {
		    *errp = ENOMEM;
		    return (NULL);
		}

		if (ap->target >= 0) {
		    if (nvlist_add_uint32(attrs, DM_LUN, ap->lun) != 0) {
			nvlist_free(attrs);
			*errp = ENOMEM;
			return (NULL);
		    }

		    if (nvlist_add_uint32(attrs, DM_TARGET, ap->target) != 0) {
			nvlist_free(attrs);
			*errp = ENOMEM;
			return (NULL);
		    }
		}

		if (ap->wwn != NULL) {
		    if (nvlist_add_string(attrs, DM_WWN, ap->wwn) != 0) {
			nvlist_free(attrs);
			*errp = ENOMEM;
			return (NULL);
		    }
		}

		if (ap->devpaths != NULL) {
		    /* get the status for this alias */
		    int		fd;

		    fd = open(ap->devpaths->devpath, O_RDONLY|O_NDELAY);

		    if ((*errp = get_status(dp->p.disk, fd, attrs)) != 0) {
			nvlist_free(attrs);
			attrs = NULL;
		    }

		    if (fd >= 0) {
			(void) close(fd);
		    }
		}

		*errp = 0;
		break;
	    }
	}

	return (attrs);
}

descriptor_t *
alias_get_descriptor_by_name(char *name, int *errp)
{
	descriptor_t	**aliases;
	int		i;
	descriptor_t	*alias = NULL;

	aliases = cache_get_descriptors(DM_ALIAS, errp);
	if (*errp != 0) {
	    return (NULL);
	}

	for (i = 0; aliases[i]; i++) {
	    if (libdiskmgt_str_eq(name, aliases[i]->name)) {
		alias = aliases[i];
	    } else {
		/* clean up the unused descriptors */
		cache_free_descriptor(aliases[i]);
	    }
	}
	free(aliases);

	if (alias == NULL) {
	    *errp = ENODEV;
	}

	return (alias);
}

/* ARGSUSED */
descriptor_t **
alias_get_descriptors(int filter[], int *errp)
{
	return (cache_get_descriptors(DM_ALIAS, errp));
}

char *
alias_get_name(descriptor_t *desc)
{
	return (desc->name);
}

/* ARGSUSED */
nvlist_t *
alias_get_stats(descriptor_t *dp, int stat_type, int *errp)
{
	/* There are no stat types defined for aliases */
	*errp = EINVAL;
	return (NULL);
}

int
alias_make_descriptors()
{
	int		error;
	disk_t		*dp;

	dp = cache_get_disklist();
	while (dp != NULL) {
	    alias_t *ap;

	    ap = dp->aliases;
	    while (ap != NULL) {
		if (ap->alias != NULL) {
		    cache_load_desc(DM_ALIAS, dp, ap->alias, NULL, &error);
		    if (error != 0) {
			return (error);
		    }
		}
		ap = ap->next;
	    }
	    dp = dp->next;
	}

	return (0);
}

static int
get_status(disk_t *diskp, int fd, nvlist_t *attrs)
{
	struct dk_minfo	minfo;

	/* Make sure media is inserted and spun up. */
	if (fd >= 0 && media_read_info(fd, &minfo)) {

	    if (nvlist_add_uint32(attrs, DM_STATUS, DM_DISK_UP) != 0) {
		return (ENOMEM);
	    }

	} else {
	    /* Not ready, so either no media or dead. */

	    if (diskp->removable) {
		/* This is a removable drive with no media. */
		if (nvlist_add_uint32(attrs, DM_STATUS, DM_DISK_UP) != 0) {
		    return (ENOMEM);
		}
	    } else {
		/* not removable, so must be dead */
		if (nvlist_add_uint32(attrs, DM_STATUS, DM_DISK_DOWN) != 0) {
		    return (ENOMEM);
		}
	    }
	}

	return (0);
}
