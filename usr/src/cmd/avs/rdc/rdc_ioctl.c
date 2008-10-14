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
 * RDC user level ioctl interface
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#include <sys/nsctl/sd_cache.h>
#include <sys/nsctl/sd_conf.h>
#include <sys/nsctl/rdc_ioctl.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>

const char *__rdc_dev = "/dev/rdc";
static int __rdc_fd;


static int
__rdc_open(void)
{
	int fd = open(__rdc_dev, O_RDONLY);

	if (fd < 0)
		return (-1);

	return (__rdc_fd = fd);
}


int
rdc_ioctl(long cmd, long a0, long a1, long a2, long a3, long a4,
	spcs_s_info_t ustatus)
{
	_rdc_ioctl_t args;

	if (!__rdc_fd && __rdc_open() < 0)
		return (-1);

	args.arg0 = a0;
	args.arg1 = a1;
	args.arg2 = a2;
	args.arg3 = a3;
	args.arg4 = a4;
	args.magic = RDC_MAGIC; /* for versioning */
	args.ustatus = ustatus;

	return (ioctl(__rdc_fd, cmd, &args));
}

/*
 * Simple form of the ioctl, just pass the command and buffer address
 * to the kernel.
 */
int
rdc_ioctl_simple(long cmd, void *addr)
{
	if (!__rdc_fd && __rdc_open() < 0)
		return (-1);
	return (ioctl(__rdc_fd, cmd, addr));
}
