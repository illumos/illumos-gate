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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/scsi/scsi_address.h>
#include <sys/scsi/impl/usmp.h>
#include <sys/libdevid.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <limits.h>

#include <scsi/libsmp.h>
#include <scsi/libsmp_plugin.h>

#include <libdevinfo.h>

struct usmp_dev {
	int ud_fd;
	char *ud_dev;
	uint64_t ud_addr;
};

struct di_walk_arg {
	dev_t dev;
	uint64_t addr;
};

static int
di_walk(di_node_t node, di_minor_t minor, void *arg)
{
	struct di_walk_arg *wp = arg;
	char *wwn;

	if (di_minor_spectype(minor) != S_IFCHR)
		return (DI_WALK_CONTINUE);

	if (di_minor_devt(minor) == wp->dev) {
		if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
		    SCSI_ADDR_PROP_TARGET_PORT, &wwn) != 1 &&
		    di_prop_lookup_strings(DDI_DEV_T_ANY, node,
		    "smp-wwn", &wwn) != 1)
			return (DI_WALK_CONTINUE);

		if (scsi_wwnstr_to_wwn(wwn, &wp->addr) != DDI_SUCCESS)
			return (DI_WALK_CONTINUE);

		return (DI_WALK_TERMINATE);
	}

	return (DI_WALK_CONTINUE);
}

static void *
usmp_open(const void *target)
{
	struct usmp_dev *dp;
	const char *target_name = (const char *)target;

	struct stat64 st;
	di_node_t root, smp;
	struct di_walk_arg walk;

	if ((dp = smp_zalloc(sizeof (struct usmp_dev))) == NULL)
		return (NULL);

	if ((dp->ud_dev = smp_strdup(target_name)) == NULL) {
		smp_free(dp);
		return (NULL);
	}

	if ((dp->ud_fd = open(target_name, O_RDONLY)) < 0) {
		(void) smp_error(ESMP_BADTARGET,
		    "failed to open %s for reading: %s",
		    target_name, strerror(errno));
		smp_free(dp->ud_dev);
		smp_free(dp);
		return (NULL);
	}

	if (fstat64(dp->ud_fd, &st) != 0) {
		(void) smp_error(ESMP_BADTARGET,
		    "failed to stat %s: %s", target_name, strerror(errno));
		(void) close(dp->ud_fd);
		smp_free(dp->ud_dev);
		smp_free(dp);
		return (NULL);
	}

	if ((root = di_init("/", DINFOCACHE)) != DI_NODE_NIL) {
		for (smp = di_drv_first_node("smp", root); smp != DI_NODE_NIL;
		    smp = di_drv_next_node(smp)) {
			bzero(&walk, sizeof (walk));
			walk.dev = st.st_rdev;
			(void) di_walk_minor(smp, NULL, 0, &walk, di_walk);
			if (walk.addr != 0) {
				dp->ud_addr = walk.addr;
				break;
			}
		}
		di_fini(root);
	}

	return (dp);
}

static void
usmp_close(void *private)
{
	struct usmp_dev *dp = (struct usmp_dev *)private;

	if (dp == NULL)
		return;

	if (dp->ud_fd > 0)
		(void) close(dp->ud_fd);

	smp_free(dp->ud_dev);
	smp_free(dp);
}

static int
usmp_exec(void *private, smp_action_t *ap)
{
	struct usmp_dev *dp = (struct usmp_dev *)private;
	struct usmp_cmd cmd;
	void *req, *resp;
	size_t reqlen, resplen;

	bzero(&cmd, sizeof (cmd));

	smp_action_get_request_frame(ap, &req, &reqlen);
	smp_action_get_response_frame(ap, &resp, &resplen);

	ASSERT(req != NULL);
	ASSERT(resp != NULL);
	ASSERT(reqlen != 0);
	ASSERT(resplen != 0);

	cmd.usmp_req = req;
	cmd.usmp_reqsize = reqlen;
	cmd.usmp_rsp = resp;
	cmd.usmp_rspsize = resplen;
	cmd.usmp_timeout = (int)smp_action_get_timeout(ap);

	if (ioctl(dp->ud_fd, USMPFUNC, &cmd) < 0) {
		ASSERT(errno != EFAULT);
		switch (errno) {
		case EINVAL:
			return (smp_error(ESMP_BADFUNC, "internal usmp error"));
		case EPERM:
			return (smp_error(ESMP_PERM,
			    "insufficient privileges"));
		case EIO:
			return (smp_error(ESMP_IO, "I/O error"));
		default:
			return (smp_error(ESMP_SYS, "usmp ioctl failed: %s",
			    strerror(errno)));
		}
	}

	/*
	 * There is no way to determine the amount of data actually transferred
	 * so we will just place the upper bound at the allocated size.
	 */
	smp_action_set_response_len(ap, resplen);

	return (0);
}

static void
usmp_target_name(void *private, char *buf, size_t len)
{
	struct usmp_dev *dp = (struct usmp_dev *)private;

	(void) strlcpy(buf, dp->ud_dev, len);
}

static uint64_t
usmp_target_addr(void *private)
{
	struct usmp_dev *dp = (struct usmp_dev *)private;

	return (dp->ud_addr);
}

static const smp_engine_ops_t usmp_ops = {
	.seo_open = usmp_open,
	.seo_close = usmp_close,
	.seo_exec = usmp_exec,
	.seo_target_name = usmp_target_name,
	.seo_target_addr = usmp_target_addr
};

int
_smp_init(smp_engine_t *ep)
{
	smp_engine_config_t config = {
		.sec_name = "usmp",
		.sec_ops = &usmp_ops
	};

	return (smp_engine_register(ep, LIBSMP_ENGINE_VERSION, &config));
}
