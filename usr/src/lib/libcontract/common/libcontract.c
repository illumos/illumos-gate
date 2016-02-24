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

#include <sys/ctfs.h>
#include <sys/contract.h>
#include <string.h>
#include <libnvpair.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <libcontract.h>
#include "libcontract_impl.h"

/*
 * Common template routines
 */

int
ct_tmpl_activate(int fd)
{
	if (ioctl(fd, CT_TACTIVATE) == -1)
		return (errno);
	return (0);
}

int
ct_tmpl_clear(int fd)
{
	if (ioctl(fd, CT_TCLEAR) == -1)
		return (errno);
	return (0);
}

int
ct_tmpl_create(int fd, ctid_t *ctidp)
{
	ctid_t ctid = ioctl(fd, CT_TCREATE);
	if (ctid == -1)
		return (errno);
	*ctidp = ctid;
	return (0);
}

int
ct_tmpl_set_internal(int fd, uint_t id, uintptr_t value)
{
	ct_param_t param;
	uint64_t param_value = value;

	param.ctpm_id = id;
	param.ctpm_size = sizeof (uint64_t);
	param.ctpm_value = &param_value;
	if (ioctl(fd, CT_TSET, &param) == -1)
		return (errno);

	return (0);
}

int
ct_tmpl_set_internal_string(int fd, uint_t id, const char *value)
{
	ct_param_t param;

	if (value == NULL)
		return (EINVAL);
	param.ctpm_id = id;
	param.ctpm_size = strlen(value) + 1;
	param.ctpm_value = (void *)value;
	if (ioctl(fd, CT_TSET, &param) == -1)
		return (errno);

	return (0);
}

int
ct_tmpl_set_critical(int fd, uint_t events)
{
	return (ct_tmpl_set_internal(fd, CTP_EV_CRITICAL, events));
}

int
ct_tmpl_set_informative(int fd, uint_t events)
{
	return (ct_tmpl_set_internal(fd, CTP_EV_INFO, events));
}

int
ct_tmpl_set_cookie(int fd, uint64_t cookie)
{
	ct_param_t param;
	uint64_t param_value = cookie;

	param.ctpm_id = CTP_COOKIE;
	param.ctpm_size = sizeof (uint64_t);
	param.ctpm_value = &param_value;
	if (ioctl(fd, CT_TSET, &param) == -1)
		return (errno);
	return (0);
}

int
ct_tmpl_get_internal(int fd, uint_t id, uint_t *value)
{
	ct_param_t param;
	uint64_t param_value;

	param.ctpm_id = id;
	param.ctpm_size = sizeof (uint64_t);
	param.ctpm_value = &param_value;
	if (ioctl(fd, CT_TGET, &param) == -1)
		return (errno);
	*value = param_value;
	return (0);
}

int
ct_tmpl_get_internal_string(int fd, uint32_t id, char *buf, size_t size)
{
	ct_param_t param;

	param.ctpm_id = id;
	param.ctpm_size = size;
	param.ctpm_value = buf;
	if (ioctl(fd, CT_TGET, &param) == -1)
		return (-1);
	return (param.ctpm_size);
}

int
ct_tmpl_get_critical(int fd, uint_t *events)
{
	return (ct_tmpl_get_internal(fd, CTP_EV_CRITICAL, events));
}

int
ct_tmpl_get_informative(int fd, uint_t *events)
{
	return (ct_tmpl_get_internal(fd, CTP_EV_INFO, events));
}

int
ct_tmpl_get_cookie(int fd, uint64_t *cookie)
{
	ct_param_t param;

	param.ctpm_id = CTP_COOKIE;
	param.ctpm_size = sizeof (uint64_t);
	param.ctpm_value = cookie;
	if (ioctl(fd, CT_TGET, &param) == -1)
		return (errno);
	return (0);
}

/*
 * Common ctl routines
 */

int
ct_ctl_adopt(int fd)
{
	if (ioctl(fd, CT_CADOPT) == -1)
		return (errno);
	return (0);
}

int
ct_ctl_abandon(int fd)
{
	if (ioctl(fd, CT_CABANDON) == -1)
		return (errno);
	return (0);
}

/*ARGSUSED*/
int
ct_ctl_newct(int cfd, ctevid_t evid, int tfd)
{
	if (ioctl(cfd, CT_CNEWCT, tfd) == -1)
		return (errno);
	return (0);
}

int
ct_ctl_ack(int fd, ctevid_t event)
{
	if (ioctl(fd, CT_CACK, &event) == -1)
		return (errno);
	return (0);
}

int
ct_ctl_nack(int fd, ctevid_t event)
{
	if (ioctl(fd, CT_CNACK, &event) == -1)
		return (errno);
	return (0);
}

int
ct_ctl_qack(int fd, ctevid_t event)
{
	if (ioctl(fd, CT_CQREQ, &event) == -1)
		return (errno);
	return (0);
}

/*
 * Common status routines
 */

int
ct_status_read(int fd, int detail, ct_stathdl_t *stathdl)
{
	char *status_buffer = NULL;
	int status_nbytes = 0;
	struct ctlib_status_info *info;
	int error;

	info = malloc(sizeof (struct ctlib_status_info));
	if (info == NULL)
		return (errno);

	info->status.ctst_detail = detail;
	if (detail != CTD_COMMON) {
		for (;;) {
			info->status.ctst_nbytes = status_nbytes;
			info->status.ctst_buffer = status_buffer;
			do
				error = ioctl(fd, CT_SSTATUS, &info->status);
			while (error == -1 && errno == EINTR);
			if (error == -1)
				goto errout;
			if (info->status.ctst_nbytes <= status_nbytes)
				break;

			if (status_buffer)
				free(status_buffer);
			status_nbytes = info->status.ctst_nbytes;
			status_buffer = malloc(status_nbytes);
			if (status_buffer == NULL)
				goto errout;
		}
		if ((errno = nvlist_unpack(info->status.ctst_buffer,
		    info->status.ctst_nbytes, &info->nvl, 0)) != 0)
			goto errout;

		free(status_buffer);
		status_buffer = NULL;

	} else {
		info->status.ctst_nbytes = 0;
		info->nvl = NULL;
		if (ioctl(fd, CT_SSTATUS, &info->status) == -1)
			goto errout;
	}

	*stathdl = info;
	return (0);

errout:
	error = errno;
	if (status_buffer)
		free(status_buffer);
	if (info)
		free(info);
	return (error);
}

void
ct_status_free(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;

	if (info->nvl) {
		assert(info->status.ctst_detail != CTD_COMMON);
		nvlist_free(info->nvl);
	}

	free(info);
}

ctid_t
ct_status_get_id(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;
	return (info->status.ctst_id);
}

zoneid_t
ct_status_get_zoneid(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;
	return (info->status.ctst_zoneid);
}

const char *
ct_status_get_type(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;
	return (types[info->status.ctst_type].type_name);
}

id_t
ct_status_get_holder(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;
	return (info->status.ctst_holder);
}

ctstate_t
ct_status_get_state(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;
	return (info->status.ctst_state);
}

int
ct_status_get_nevents(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;
	return (info->status.ctst_nevents);
}

int
ct_status_get_ntime(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;
	return (info->status.ctst_ntime);
}

int
ct_status_get_qtime(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;
	return (info->status.ctst_qtime);
}

ctevid_t
ct_status_get_nevid(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;
	return (info->status.ctst_nevid);
}

uint_t
ct_status_get_informative(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;
	return (info->status.ctst_informative);
}

uint_t
ct_status_get_critical(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;
	return (info->status.ctst_critical);
}

uint64_t
ct_status_get_cookie(ct_stathdl_t stathdl)
{
	struct ctlib_status_info *info = stathdl;
	return (info->status.ctst_cookie);
}

/*
 * Common event routines
 */

static int
unpack_and_merge(nvlist_t **nvl, char *buffer, size_t len)
{
	nvlist_t *tmpnvl;
	int error;

	if ((error = nvlist_unpack(buffer, len, &tmpnvl, 0)) != 0)
		return (error);

	if (*nvl == NULL) {
		*nvl = tmpnvl;
		return (0);
	}

	error = nvlist_merge(*nvl, tmpnvl, 0);
	nvlist_free(tmpnvl);
	return (error);
}

static int
ct_event_read_internal(int fd, int cmd, ct_evthdl_t *evt)
{
	char *event_buffer = NULL;
	int event_nbytes = 0;
	struct ctlib_event_info *info;
	ct_event_t *event;
	int error;

	info = malloc(sizeof (struct ctlib_event_info));
	if (info == NULL)
		return (errno);
	info->nvl = NULL;
	event = &info->event;

	for (;;) {
		event->ctev_nbytes = event_nbytes;
		event->ctev_buffer = event_buffer;
		do
			error = ioctl(fd, cmd, event);
		while (error == -1 && errno == EINTR);
		if (error == -1) {
			error = errno;
			goto errout;
		}
		if (event->ctev_nbytes <= event_nbytes)
			break;

		if (event_buffer)
			free(event_buffer);
		event_nbytes = event->ctev_nbytes;
		event_buffer = malloc(event_nbytes);
		if (event_buffer == NULL) {
			error = errno;
			goto errout;
		}
	}

	if (event->ctev_goffset > 0 && (error = unpack_and_merge(&info->nvl,
	    event->ctev_buffer, event->ctev_goffset)) != 0)
		goto errout;

	if (event->ctev_goffset < event->ctev_nbytes &&
	    (error = unpack_and_merge(&info->nvl,
	    event->ctev_buffer + event->ctev_goffset,
	    event->ctev_nbytes - event->ctev_goffset)) != 0)
		goto errout;

	free(event_buffer);

	*evt = info;
	return (0);

errout:
	if (event_buffer)
		free(event_buffer);
	if (info) {
		nvlist_free(info->nvl);
		free(info);
	}
	return (error);
}

int
ct_event_read(int fd, ct_evthdl_t *evthdl)
{
	return (ct_event_read_internal(fd, CT_ERECV, evthdl));
}

int
ct_event_read_critical(int fd, ct_evthdl_t *evthdl)
{
	return (ct_event_read_internal(fd, CT_ECRECV, evthdl));
}

int
ct_event_reset(int fd)
{
	if (ioctl(fd, CT_ERESET) == -1)
		return (errno);
	return (0);
}

int
ct_event_reliable(int fd)
{
	if (ioctl(fd, CT_ERELIABLE) == -1)
		return (errno);
	return (0);
}

void
ct_event_free(ct_evthdl_t evthdl)
{
	struct ctlib_event_info *info = evthdl;

	nvlist_free(info->nvl);
	free(info);
}


uint_t
ct_event_get_flags(ct_evthdl_t evthdl)
{
	struct ctlib_event_info *info = evthdl;
	return (info->event.ctev_flags);
}

ctid_t
ct_event_get_ctid(ct_evthdl_t evthdl)
{
	struct ctlib_event_info *info = evthdl;
	return (info->event.ctev_id);
}

ctevid_t
ct_event_get_evid(ct_evthdl_t evthdl)
{
	struct ctlib_event_info *info = evthdl;
	return (info->event.ctev_evid);
}

uint_t
ct_event_get_type(ct_evthdl_t evthdl)
{
	struct ctlib_event_info *info = evthdl;
	return (info->event.ctev_type);
}

int
ct_event_get_nevid(ct_evthdl_t evthdl, ctevid_t *evidp)
{
	struct ctlib_event_info *info = evthdl;
	if (info->nvl == NULL ||
	    nvlist_lookup_uint64(info->nvl, CTS_NEVID, evidp))
		return (EINVAL);
	return (0);
}

int
ct_event_get_newct(ct_evthdl_t evthdl, ctid_t *ctidp)
{
	struct ctlib_event_info *info = evthdl;
	if (info->nvl == NULL ||
	    nvlist_lookup_int32(info->nvl, CTS_NEWCT, (int *)ctidp))
		return (EINVAL);
	return (0);
}
