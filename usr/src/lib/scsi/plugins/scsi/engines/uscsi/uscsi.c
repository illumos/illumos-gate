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
 *
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/generic/commands.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <limits.h>

#include <scsi/libscsi.h>
#include "libscsi_impl.h"

struct uscsi_dev {
	int fd;
	char *dev;
};

static void *
uscsi_open(libscsi_hdl_t *hp, const void *target)
{
	struct uscsi_dev *dp;
	const char *target_name = (const char *)target;

	if ((dp = libscsi_zalloc(hp, sizeof (struct uscsi_dev))) == NULL)
		return (NULL);

	if ((dp->dev = libscsi_strdup(hp, target_name)) == NULL) {
		libscsi_free(hp, dp);
		return (NULL);
	}

	if ((dp->fd = open(target_name, O_RDONLY)) < 0) {
		(void) libscsi_error(hp, ESCSI_BADTARGET, "failed to open %s "
		    "for reading: %s", target_name, strerror(errno));
		libscsi_free(hp, dp->dev);
		libscsi_free(hp, dp);
		return (NULL);
	}

	return (dp);
}

static void
uscsi_close(libscsi_hdl_t *hp, void *private)
{
	struct uscsi_dev *dp = (struct uscsi_dev *)private;

	if (dp == NULL)
		return;

	if (dp->fd > 0)
		(void) close(dp->fd);

	libscsi_free(hp, dp->dev);
	libscsi_free(hp, dp);
}

static int
xlate_flags(libscsi_hdl_t *hp, uint_t flags, int *uf)
{
	uint_t f;
	int i;

	f = 0;

	for (i = 0; i < sizeof (flags) * 8; i++) {
		switch (flags & (1 << i)) {
		case 0:
			continue;
		case LIBSCSI_AF_READ:
			f |= USCSI_READ;
			break;
		case LIBSCSI_AF_WRITE:
			f |= USCSI_WRITE;
			break;
		case LIBSCSI_AF_SILENT:
			f |= USCSI_SILENT;
			break;
		case LIBSCSI_AF_DIAGNOSE:
			f |= USCSI_DIAGNOSE;
			break;
		case LIBSCSI_AF_ISOLATE:
			f |= USCSI_ISOLATE;
			break;
		case LIBSCSI_AF_RQSENSE:
			f |= USCSI_RQENABLE;
			break;
		default:
			return (libscsi_error(hp, ESCSI_BOGUSFLAGS,
			    "flag 0x%x is unknown", 1 << i));
		}
	}

	*uf = f;

	return (0);
}

static int
uscsi_exec(libscsi_hdl_t *hp, void *private, libscsi_action_t *ap)
{
	struct uscsi_dev *dp = (struct uscsi_dev *)private;
	struct uscsi_cmd cmd;
	size_t data_a, data_v;
	uint8_t *cp;
	uint_t flags;

	bzero(&cmd, sizeof (cmd));

	cp = libscsi_action_get_cdb(ap);
	if (cp == NULL)
		return (-1);

	flags = libscsi_action_get_flags(ap);
	if (xlate_flags(hp, flags, &cmd.uscsi_flags) != 0)
		return (-1);

	cmd.uscsi_status = (short)-1;
	cmd.uscsi_timeout = (short)libscsi_action_get_timeout(ap);

	cmd.uscsi_cdb = (caddr_t)cp;
	cmd.uscsi_cdblen = libscsi_cmd_cdblen(hp, *cp);
	if (cmd.uscsi_cdblen == 0)
		return (-1);

	if (flags & (LIBSCSI_AF_READ | LIBSCSI_AF_WRITE)) {
		if (libscsi_action_get_buffer(ap,
		    (uint8_t **)&cmd.uscsi_bufaddr, &data_a, &data_v) != 0)
			return (-1);
		if (flags & LIBSCSI_AF_READ)
			cmd.uscsi_buflen = data_a;
		else
			cmd.uscsi_buflen = data_v;
	}
	if (flags & LIBSCSI_AF_RQSENSE) {
		if (libscsi_action_get_sense(ap, (uint8_t **)&cmd.uscsi_rqbuf,
		    &data_a, NULL) != 0)
			return (-1);
		if (data_a > UCHAR_MAX)
			data_a = UCHAR_MAX;
		cmd.uscsi_rqlen = (uchar_t)data_a;
		cmd.uscsi_rqstatus = (uchar_t)-1;
	}

	if (ioctl(dp->fd, USCSICMD, &cmd) < 0) {
		ASSERT(errno != EFAULT);
		switch (errno) {
		case EINVAL:
			return (libscsi_error(hp, ESCSI_BADCMD, "internal "
			    "uscsi error"));
		case EPERM:
			return (libscsi_error(hp, ESCSI_PERM, "insufficient "
			    "privileges "));
		case EIO:
			/* Command never executed at all */
			if (cmd.uscsi_status == (short)-1)
				return (libscsi_error(hp, ESCSI_IO, "I/O "
				    "error", strerror(errno)));
			break;
		default:
			return (libscsi_error(hp, ESCSI_SYS, "uscsi ioctl "
			    "failed: %s", strerror(errno)));
		}
	}

	libscsi_action_set_status(ap, cmd.uscsi_status);
	if ((flags & LIBSCSI_AF_READ) && libscsi_action_set_datalen(ap,
	    cmd.uscsi_buflen - cmd.uscsi_resid) != 0)
		return (-1);
	if ((flags & LIBSCSI_AF_RQSENSE) && libscsi_action_set_senselen(ap,
	    cmd.uscsi_rqlen - cmd.uscsi_rqresid) != 0)
		return (-1);

	return (0);
}

/*ARGSUSED*/
static void
uscsi_target_name(libscsi_hdl_t *hp, void *private, char *buf, size_t len)
{
	struct uscsi_dev *dp = (struct uscsi_dev *)private;

	(void) snprintf(buf, len, "%s", dp->dev);
}

static int
uscsi_max_transfer(libscsi_hdl_t *hp, void *private, size_t *sizep)
{
	uscsi_xfer_t xfer;
	struct uscsi_dev *dp = (struct uscsi_dev *)private;

	if (ioctl(dp->fd, USCSIMAXXFER, &xfer) < 0) {
		ASSERT(errno != EFAULT);
		switch (errno) {
		case EINVAL:
			return (libscsi_error(hp, ESCSI_BADCMD, "internal "
			    "uscsi error"));
		case EPERM:
			return (libscsi_error(hp, ESCSI_PERM, "insufficient "
			    "privileges "));
		case ENOTTY:
			return (libscsi_error(hp, ESCSI_NOTSUP, "max transfer "
			    "request not supported on device"));
		default:
			return (libscsi_error(hp, ESCSI_SYS, "uscsi ioctl "
			    "failed: %s", strerror(errno)));
		}
	}

	if (xfer > SIZE_MAX)
		xfer = SIZE_MAX;

	*sizep = (size_t)xfer;
	return (0);
}

static const libscsi_engine_ops_t uscsi_ops = {
	.lseo_open = uscsi_open,
	.lseo_close = uscsi_close,
	.lseo_exec = uscsi_exec,
	.lseo_target_name = uscsi_target_name,
	.lseo_max_transfer = uscsi_max_transfer
};

static const libscsi_engine_t uscsi_engine = {
	.lse_name = "uscsi",
	.lse_libversion = LIBSCSI_VERSION,
	.lse_ops = &uscsi_ops
};

/*ARGSUSED*/
const libscsi_engine_t *
libscsi_uscsi_init(libscsi_hdl_t *hp)
{
	return (&uscsi_engine);
}
