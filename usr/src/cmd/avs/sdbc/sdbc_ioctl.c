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

/*
 * SDBC user level ioctl interface
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <strings.h>

#include <sys/nsctl/sd_cache.h>
#include <sys/nsctl/sd_conf.h>
#include <sys/nsctl/sdbc_ioctl.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>

#include <sys/nsctl/sv.h>
#include <sys/nsctl/sv_impl.h>


const char *__sdbc_dev = "/dev/sdbc";
static int __sdbc_fd;


static int
__sdbc_open(void)
{
	int fd;

	fd = open("/dev/nsctl", O_RDONLY);
	if (fd >= 0)
		(void) close(fd);

	fd = open(__sdbc_dev, O_RDONLY);
	if (fd < 0)
		return (-1);

	return (__sdbc_fd = fd);
}


static void
sv_list()
{
	sv_name_t svn[1];
	sv_name_t *svn_system;
	sv_list_t svl;
	static int fd = -1;

	if (fd < 0)
		fd = open(SV_DEVICE, O_RDONLY);
	if (fd < 0)
		return;

	bzero(&svl, sizeof (svl));
	bzero(&svn[0], sizeof (svn));

	svl.svl_names = &svn[0];
	svl.svl_error = spcs_s_ucreate();

	if (ioctl(fd, SVIOC_LIST, &svl) < 0)
		return;

	svn_system = calloc(svl.svl_maxdevs, sizeof (*svn));
	if (svn_system == NULL)
		return;

	/* Grab the system list from the driver */
	svl.svl_count = svl.svl_maxdevs;
	svl.svl_names = svn_system;

	(void) ioctl(fd, SVIOC_LIST, &svl);

	free(svn_system);
	spcs_s_ufree(&svl.svl_error);
}


int
sdbc_ioctl(long cmd, long a0, long a1, long a2, long a3, long a4,
    spcs_s_info_t *ustatus)
{
	_sdbc_ioctl_t args;
	int rc;

	*ustatus = NULL;

	if (!__sdbc_fd && __sdbc_open() < 0)
		return (-1);

	switch (cmd) {
	/*
	 * These ioctls work on open cache descriptors. The sv_list() function
	 * has the side-effect of re-opening all configured descriptors.
	 * Without this call, devices seem to "disappear" from the system when
	 * certain reconfiguration operations, for example II or SNDR disable,
	 * are done.
	 * It does rely on SV being configured, so in an STE-only environment
	 * the disappearing will still seem to happen.
	 */
	case SDBC_SET_CD_HINT:
	case SDBC_GET_CD_HINT:
	case SDBC_STATS:
	case SDBC_GET_CD_BLK:
	case SDBC_INJ_IOERR:
	case SDBC_CLR_IOERR:
		sv_list();
		break;

	default:
		break;
	}

	args.arg0 = a0;
	args.arg1 = a1;
	args.arg2 = a2;
	args.arg3 = a3;
	args.arg4 = a4;
	args.magic = _SD_MAGIC; /* for versioning */
	args.sdbc_ustatus = spcs_s_ucreate();

	if ((rc = ioctl(__sdbc_fd, cmd, &args)) < 0) {
		*ustatus = args.sdbc_ustatus;
	} else {
		spcs_s_ufree(&args.sdbc_ustatus);
		*ustatus = NULL;
	}

	return (rc);
}
