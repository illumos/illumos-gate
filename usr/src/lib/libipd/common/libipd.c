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
 * Copyright (c) 2012 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

#include <libipd.h>
#include <sys/ipd.h>

__thread ipd_errno_t ipd_errno = 0;
__thread char ipd_errmsg[512];

struct ipd_stat {
	uint_t is_nzones;
	zoneid_t *is_zoneids;
	struct ipd_config *is_configs;
};

static ipd_errno_t
xlate_errno(int e)
{
	switch (e) {
	case 0:
		return (EIPD_NOERROR);
	case ENOMEM:
	case EAGAIN:
		return (EIPD_NOMEM);
	case ERANGE:
		return (EIPD_RANGE);
	case EPERM:
		return (EIPD_PERM);
	case EFAULT:
		return (EIPD_FAULT);
	case ENOTTY:
		return (EIPD_INTERNAL);
	default:
		return (EIPD_UNKNOWN);
	}
}

const char *
ipd_strerror(ipd_errno_t e)
{
	switch (e) {
	case EIPD_NOERROR:
		return ("no error");
	case EIPD_NOMEM:
		return ("out of memory");
	case EIPD_ZC_NOENT:
		return ("zone does not exist or is not using ipd");
	case EIPD_RANGE:
		return ("argument out of range");
	case EIPD_PERM:
		return ("permission denied");
	case EIPD_FAULT:
		return ("bad pointer");
	case EIPD_INTERNAL:
		return ("internal library error");
	case EIPD_UNKNOWN:
	default:
		return ("unknown error");
	}
}

static int
ipd_set_errno(ipd_errno_t e, const char *fmt, ...)
{
	va_list ap;

	ipd_errno = e;
	if (fmt != NULL) {
		va_start(ap, fmt);
		(void) vsnprintf(ipd_errmsg, sizeof (ipd_errmsg), fmt, ap);
		va_end(ap);
	} else {
		(void) strlcpy(ipd_errmsg,
		    ipd_strerror(e), sizeof (ipd_errmsg));
	}

	return (-1);
}

int
ipd_open(const char *path)
{
	int fd;

	if (path == NULL)
		path = IPD_DEV_PATH;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		return (ipd_set_errno(xlate_errno(errno),
		    "unable to open %s: %s", path, strerror(errno)));
	}

	return (fd);
}

int
ipd_close(int fd)
{
	(void) close(fd);
	return (0);
}

int
ipd_status_read(int fd, ipd_stathdl_t *ispp)
{
	struct ipd_stat *isp = NULL;
	ipd_ioc_list_t ipil;
	uint_t rzones;
	uint_t i;

	bzero(&ipil, sizeof (ipil));
	if (ioctl(fd, IPDIOC_LIST, &ipil) != 0) {
		return (ipd_set_errno(xlate_errno(errno),
		    "unable to retrieve ipd zone list: %s", strerror(errno)));
	}

	for (;;) {
		if ((rzones = ipil.ipil_nzones) == 0)
			break;

		ipil.ipil_info =
		    malloc(sizeof (ipd_ioc_info_t) * ipil.ipil_nzones);
		if (ipil.ipil_info == NULL)
			return (ipd_set_errno(EIPD_NOMEM, NULL));

		if (ioctl(fd, IPDIOC_LIST, &ipil) != 0) {
			free(ipil.ipil_info);
			return (ipd_set_errno(xlate_errno(errno),
			    "unable to retrieve ipd zone list: %s",
			    strerror(errno)));
		}

		if (ipil.ipil_nzones <= rzones)
			break;

		free(ipil.ipil_info);
	}

	if ((isp = malloc(sizeof (struct ipd_stat))) == NULL) {
		free(ipil.ipil_info);
		return (ipd_set_errno(EIPD_NOMEM, NULL));
	}

	isp->is_nzones = ipil.ipil_nzones;

	if (isp->is_nzones == 0) {
		isp->is_zoneids = NULL;
		isp->is_configs = NULL;
		*ispp = isp;
		return (0);
	}

	isp->is_zoneids = malloc(sizeof (zoneid_t) * ipil.ipil_nzones);
	if (isp->is_zoneids == NULL) {
		free(ipil.ipil_info);
		free(isp);
		return (ipd_set_errno(EIPD_NOMEM, NULL));
	}
	isp->is_configs = malloc(sizeof (struct ipd_config) * ipil.ipil_nzones);
	if (isp->is_configs == NULL) {
		free(ipil.ipil_info);
		free(isp->is_zoneids);
		free(isp);
		return (ipd_set_errno(EIPD_NOMEM, NULL));
	}

	for (i = 0; i < isp->is_nzones; i++) {
		isp->is_zoneids[i] = ipil.ipil_info[i].ipii_zoneid;

		isp->is_configs[i].ic_corrupt = ipil.ipil_info[i].ipii_corrupt;
		isp->is_configs[i].ic_drop = ipil.ipil_info[i].ipii_drop;
		isp->is_configs[i].ic_delay = ipil.ipil_info[i].ipii_delay;

		isp->is_configs[i].ic_mask =
		    ((!!isp->is_configs[i].ic_corrupt) * IPDM_CORRUPT) |
		    ((!!isp->is_configs[i].ic_drop) * IPDM_DROP) |
		    ((!!isp->is_configs[i].ic_delay) * IPDM_DELAY);
	}

	*ispp = isp;
	return (0);
}

void
ipd_status_foreach_zone(const ipd_stathdl_t hdl, ipd_status_cb_f f, void *arg)
{
	const struct ipd_stat *isp = hdl;
	uint_t i;

	for (i = 0; i < isp->is_nzones; i++)
		f(isp->is_zoneids[i], &isp->is_configs[i], arg);
}

int
ipd_status_get_config(const ipd_stathdl_t hdl, zoneid_t z, ipd_config_t **icpp)
{
	const struct ipd_stat *isp = hdl;
	uint_t i;

	for (i = 0; i < isp->is_nzones; i++) {
		if (isp->is_zoneids[i] == z) {
			*icpp = &isp->is_configs[i];
			return (0);
		}
	}

	return (ipd_set_errno(EIPD_ZC_NOENT,
	    "zone %d does not exist or has no ipd configuration", z));
}

void
ipd_status_free(ipd_stathdl_t hdl)
{
	struct ipd_stat *isp = hdl;

	if (isp != NULL) {
		free(isp->is_zoneids);
		free(isp->is_configs);
	}
	free(isp);
}

int
ipd_ctl(int fd, zoneid_t z, const ipd_config_t *icp)
{
	ipd_ioc_perturb_t ipip;

	bzero(&ipip, sizeof (ipd_ioc_perturb_t));
	ipip.ipip_zoneid = z;

	if (icp->ic_mask & IPDM_CORRUPT) {
		if (icp->ic_corrupt == 0)
			ipip.ipip_arg |= IPD_CORRUPT;
	}
	if (icp->ic_mask & IPDM_DELAY) {
		if (icp->ic_delay == 0)
			ipip.ipip_arg |= IPD_DELAY;
	}
	if (icp->ic_mask & IPDM_DROP) {
		if (icp->ic_drop == 0)
			ipip.ipip_arg |= IPD_DROP;
	}

	if (ipip.ipip_arg != 0 && ioctl(fd, IPDIOC_REMOVE, &ipip) != 0) {
		return (ipd_set_errno(xlate_errno(errno),
		    "unable to remove cleared ipd settings: %s",
		    strerror(errno)));
	}

	if ((icp->ic_mask & IPDM_CORRUPT) && icp->ic_corrupt != 0) {
		ipip.ipip_zoneid = z;
		ipip.ipip_arg = icp->ic_corrupt;
		if (ioctl(fd, IPDIOC_CORRUPT, &ipip) != 0) {
			return (ipd_set_errno(xlate_errno(errno),
			    "unable to set corruption rate to %d: %s",
			    ipip.ipip_arg, strerror(errno)));
		}
	}
	if ((icp->ic_mask & IPDM_DELAY) && icp->ic_delay != 0) {
		ipip.ipip_zoneid = z;
		ipip.ipip_arg = icp->ic_delay;
		if (ioctl(fd, IPDIOC_DELAY, &ipip) != 0) {
			return (ipd_set_errno(xlate_errno(errno),
			    "unable to set delay time to %d: %s",
			    ipip.ipip_arg, strerror(errno)));
		}
	}
	if ((icp->ic_mask & IPDM_DROP) && icp->ic_drop != 0) {
		ipip.ipip_zoneid = z;
		ipip.ipip_arg = icp->ic_drop;
		if (ioctl(fd, IPDIOC_DROP, &ipip) != 0) {
			return (ipd_set_errno(xlate_errno(errno),
			    "unable to set drop probability to %d: %s",
			    ipip.ipip_arg, strerror(errno)));
		}
	}

	return (0);
}
