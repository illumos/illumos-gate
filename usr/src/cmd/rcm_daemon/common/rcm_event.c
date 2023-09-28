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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <door.h>
#include <assert.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <librcm_event.h>

#include "rcm_impl.h"

/*
 * Event handling routine
 */

#define	RCM_NOTIFY	0
#define	RCM_GETINFO	1
#define	RCM_REQUEST	2
#define	RCM_EFAULT	3
#define	RCM_EPERM	4
#define	RCM_EINVAL	5

static void process_event(int, int, nvlist_t *, nvlist_t **);
static void generate_reply_event(int, rcm_info_t *, nvlist_t **);
static void rcm_print_nvlist(nvlist_t *);

/*
 * Top level function for event service
 */
void
event_service(void **data, size_t *datalen)
{
	int cmd;
	int lerrno;
	int seq_num;
	nvlist_t *nvl;
	nvlist_t *ret;

	rcm_log_message(RCM_TRACE1, "received door operation\n");

	/* Decode the data from the door into an unpacked nvlist */
	if (data == NULL || datalen == NULL) {
		rcm_log_message(RCM_ERROR, "received null door argument\n");
		return;
	}
	if (lerrno = nvlist_unpack(*data, *datalen, &nvl, 0)) {
		rcm_log_message(RCM_ERROR, "received bad door argument, %s\n",
		    strerror(lerrno));
		return;
	}

	/* Do nothing if the door is just being knocked on */
	if (errno = nvlist_lookup_int32(nvl, RCM_CMD, &cmd)) {
		rcm_log_message(RCM_ERROR,
		    "bad door argument (nvlist_lookup=%s)\n", strerror(errno));
		nvlist_free(nvl);
		return;
	}
	if (cmd == CMD_KNOCK) {
		rcm_log_message(RCM_TRACE1, "door event was just a knock\n");
		nvlist_free(nvl);
		*data = NULL;
		*datalen = 0;
		return;
	}

	/*
	 * Go increment thread count. Before daemon is fully initialized,
	 * the event processing blocks inside this function.
	 */
	seq_num = rcmd_thr_incr(cmd);

	process_event(cmd, seq_num, nvl, &ret);
	nvlist_free(nvl);
	assert(ret != NULL);

	/*
	 * Decrement thread count
	 */
	rcmd_thr_decr();

	*data = ret;
	*datalen = 0;
}

/*
 * Actually processes events; returns a reply event
 */
static void
process_event(int cmd, int seq_num, nvlist_t *nvl, nvlist_t **ret)
{
	int i;
	int error;
	uint_t nvl_nrsrcs = 0;
	pid_t pid;
	uint32_t flag = (uint32_t)0;
	uint64_t pid64 = (uint64_t)0;
	size_t buflen = 0;
	size_t interval_size = 0;
	timespec_t *interval = NULL;
	nvlist_t *change_data = NULL;
	nvlist_t *event_data = NULL;
	rcm_info_t *info = NULL;
	char *modname = NULL;
	char *buf = NULL;
	char **rsrcnames = NULL;
	char **nvl_rsrcs = NULL;

	rcm_log_message(RCM_TRACE2, "servicing door command=%d\n", cmd);

	rcm_print_nvlist(nvl);

	/*
	 * Extract data from the door argument nvlist.  Not all arguments
	 * are needed; sanity checks are performed later.
	 */
	(void) nvlist_lookup_string_array(nvl, RCM_RSRCNAMES, &nvl_rsrcs,
	    &nvl_nrsrcs);
	(void) nvlist_lookup_string(nvl, RCM_CLIENT_MODNAME, &modname);
	(void) nvlist_lookup_uint64(nvl, RCM_CLIENT_ID, (uint64_t *)&pid64);
	pid = (pid_t)pid64;
	(void) nvlist_lookup_uint32(nvl, RCM_REQUEST_FLAG, (uint32_t *)&flag);
	(void) nvlist_lookup_byte_array(nvl, RCM_SUSPEND_INTERVAL,
	    (uchar_t **)&interval, &interval_size);
	(void) nvlist_lookup_byte_array(nvl, RCM_CHANGE_DATA, (uchar_t **)&buf,
	    &buflen);
	if (buf != NULL && buflen > 0) {
		(void) nvlist_unpack(buf, buflen, &change_data, 0);
		buf = NULL;
		buflen = 0;
	}
	(void) nvlist_lookup_byte_array(nvl, RCM_EVENT_DATA, (uchar_t **)&buf,
	    &buflen);
	if (buf != NULL && buflen > 0)
		(void) nvlist_unpack(buf, buflen, &event_data, 0);

	rsrcnames = s_calloc(nvl_nrsrcs + 1, sizeof (char *));
	for (i = 0; i < nvl_nrsrcs; i++) {
		rsrcnames[i] = nvl_rsrcs[i];
	}
	rsrcnames[nvl_nrsrcs] = NULL;

	/*
	 * Switch off the command being performed to do the appropriate
	 * sanity checks and dispatch the arguments to the appropriate
	 * implementation routine.
	 */
	switch (cmd) {
	case CMD_REGISTER:
		if ((modname == NULL) || (rsrcnames == NULL) ||
		    (rsrcnames[0] == NULL))
			goto faildata;
		error = add_resource_client(modname, rsrcnames[0], pid, flag,
		    &info);
		break;

	case CMD_UNREGISTER:
		if ((modname == NULL) || (rsrcnames == NULL) ||
		    (rsrcnames[0] == NULL))
			goto faildata;
		error = remove_resource_client(modname, rsrcnames[0], pid,
		    flag);
		break;

	case CMD_GETINFO:
		if ((rsrcnames == NULL) &&
		    ((flag & (RCM_DR_OPERATION | RCM_MOD_INFO)) == 0))
			goto faildata;
		if ((error = get_resource_info(rsrcnames, flag, seq_num, &info))
		    == EINVAL) {
			rcm_log_message(RCM_DEBUG,
			    "invalid argument in get info request\n");
			generate_reply_event(EINVAL, NULL, ret);
			return;
		}
		break;

	case CMD_SUSPEND:
		if ((rsrcnames == NULL) || (rsrcnames[0] == NULL) ||
		    (interval == NULL))
			goto faildata;
		error = process_resource_suspend(rsrcnames, pid, flag, seq_num,
		    interval, &info);
		break;

	case CMD_RESUME:
		if ((rsrcnames == NULL) || (rsrcnames[0] == NULL))
			goto faildata;
		error = notify_resource_resume(rsrcnames, pid, flag, seq_num,
		    &info);
		break;

	case CMD_OFFLINE:
		if ((rsrcnames == NULL) || (rsrcnames[0] == NULL))
			goto faildata;
		error = process_resource_offline(rsrcnames, pid, flag, seq_num,
		    &info);
		break;

	case CMD_ONLINE:
		if ((rsrcnames == NULL) || (rsrcnames[0] == NULL))
			goto faildata;
		error = notify_resource_online(rsrcnames, pid, flag, seq_num,
		    &info);
		break;

	case CMD_REMOVE:
		if ((rsrcnames == NULL) || (rsrcnames[0] == NULL))
			goto faildata;
		error = notify_resource_remove(rsrcnames, pid, flag, seq_num,
		    &info);
		break;

	case CMD_EVENT:
		if ((rsrcnames == NULL) || (rsrcnames[0] == NULL) ||
		    (event_data == NULL))
			goto faildata;
		error = notify_resource_event(rsrcnames[0], pid, flag, seq_num,
		    event_data, &info);
		nvlist_free(event_data);
		break;

	case CMD_REQUEST_CHANGE:
		if ((rsrcnames == NULL) || (rsrcnames[0] == NULL) ||
		    (change_data == NULL))
			goto faildata;
		error = request_capacity_change(rsrcnames[0], pid, flag,
		    seq_num, change_data, &info);
		nvlist_free(change_data);
		break;

	case CMD_NOTIFY_CHANGE:
		if ((rsrcnames == NULL) || (rsrcnames[0] == NULL) ||
		    (change_data == NULL))
			goto faildata;
		error = notify_capacity_change(rsrcnames[0], pid, flag, seq_num,
		    change_data, &info);
		nvlist_free(change_data);
		break;

	case CMD_GETSTATE:
		if ((rsrcnames == NULL) || (rsrcnames[0] == NULL))
			goto faildata;
		error = get_resource_state(rsrcnames[0], pid, &info);
		break;

	default:
		rcm_log_message(RCM_WARNING,
		    gettext("unknown door command: %d\n"), cmd);
		generate_reply_event(EFAULT, NULL, ret);
		(void) free(rsrcnames);
		return;
	}

	rcm_log_message(RCM_TRACE2, "finish processing event 0x%x\n", cmd);
	generate_reply_event(error, info, ret);
	(void) free(rsrcnames);
	return;

faildata:
	rcm_log_message(RCM_WARNING,
	    gettext("data error in door arguments for cmd 0x%x\n"), cmd);

	generate_reply_event(EFAULT, NULL, ret);
	(void) free(rsrcnames);
}


/*
 * Generate reply event from resource registration information
 */
static void
generate_reply_event(int error, rcm_info_t *info, nvlist_t **ret)
{
	nvlist_t *nvl = NULL;
	rcm_info_t *tmp;
	char *buf = NULL;
	size_t buflen = 0;

	rcm_log_message(RCM_TRACE4, "generating reply event\n");

	/* Allocate an empty nvlist */
	if ((errno = nvlist_alloc(&nvl, 0, 0)) > 0) {
		rcm_log_message(RCM_ERROR,
		    gettext("nvlist_alloc failed: %s\n"), strerror(errno));
		rcmd_exit(errno);
	}

	/* Encode the result of the operation in the nvlist */
	if (errno = nvlist_add_int32(nvl, RCM_RESULT, error)) {
		rcm_log_message(RCM_ERROR,
		    gettext("nvlist_add(RESULT) failed: %s\n"),
		    strerror(errno));
		rcmd_exit(errno);
	}

	/* Go through the RCM info tuples, appending them all to the nvlist */
	tmp = info;
	while (tmp) {
		if (tmp->info) {
			buf = NULL;
			buflen = 0;
			if (errno = nvlist_pack(tmp->info, &buf, &buflen,
			    NV_ENCODE_NATIVE, 0)) {
				rcm_log_message(RCM_ERROR,
				    gettext("nvlist_pack(INFO) failed: %s\n"),
				    strerror(errno));
				rcmd_exit(errno);
			}
			if (errno = nvlist_add_byte_array(nvl, RCM_RESULT_INFO,
			    (uchar_t *)buf, buflen)) {
				rcm_log_message(RCM_ERROR,
				    gettext("nvlist_add(INFO) failed: %s\n"),
				    strerror(errno));
				rcmd_exit(errno);
			}
			(void) free(buf);
			nvlist_free(tmp->info);
		}
		info = tmp->next;
		(void) free(tmp);
		tmp = info;
	}

	/* Return the nvlist (unpacked) in the return argument */
	rcm_print_nvlist(nvl);
	*ret = nvl;
}

static void
rcm_print_nvlist(nvlist_t *nvl)
{
	uchar_t data_byte;
	int16_t data_int16;
	uint16_t data_uint16;
	int32_t data_int32;
	uint32_t data_uint32;
	int64_t data_int64;
	uint64_t data_uint64;
	char *data_string;
	char **data_strings;
	uint_t data_nstrings;
	nvpair_t *nvp = NULL;
	int i;
	char *name;
	data_type_t type;

	rcm_log_message(RCM_TRACE3, "event attributes:\n");

	while (nvp = nvlist_next_nvpair(nvl, nvp)) {
		type = nvpair_type(nvp);
		name = nvpair_name(nvp);
		rcm_log_message(RCM_TRACE3, "\t%s(%d)=", name, type);

		switch (type) {
		case DATA_TYPE_BOOLEAN:
			rcm_log_message(RCM_TRACE3, "True (boolean)\n");
			break;

		case DATA_TYPE_BYTE:
			(void) nvpair_value_byte(nvp, &data_byte);
			rcm_log_message(RCM_TRACE3, "0x%x (byte)\n",
			    data_byte);
			break;

		case DATA_TYPE_INT16:
			(void) nvpair_value_int16(nvp, &data_int16);
			rcm_log_message(RCM_TRACE3, "0x%x (int16)\n",
			    data_int16);
			break;

		case DATA_TYPE_UINT16:
			(void) nvpair_value_uint16(nvp, &data_uint16);
			rcm_log_message(RCM_TRACE3, "0x%x (uint16)\n",
			    data_uint16);
			break;

		case DATA_TYPE_INT32:
			(void) nvpair_value_int32(nvp, &data_int32);
			rcm_log_message(RCM_TRACE3, "0x%x (int32)\n",
			    data_int32);
			break;

		case DATA_TYPE_UINT32:
			(void) nvpair_value_uint32(nvp, &data_uint32);
			rcm_log_message(RCM_TRACE3, "0x%x (uint32)\n",
			    data_uint32);
			break;

		case DATA_TYPE_INT64:
			(void) nvpair_value_int64(nvp, &data_int64);
			rcm_log_message(RCM_TRACE3, "0x%lx (int64)\n",
			    data_int64);
			break;

		case DATA_TYPE_UINT64:
			(void) nvpair_value_uint64(nvp, &data_uint64);
			rcm_log_message(RCM_TRACE3, "0x%lx (uint64)\n",
			    data_uint64);
			break;

		case DATA_TYPE_STRING:
			(void) nvpair_value_string(nvp, &data_string);
			rcm_log_message(RCM_TRACE3, "\"%s\" (string)\n",
			    data_string);
			break;

		case DATA_TYPE_STRING_ARRAY:
			(void) nvpair_value_string_array(nvp, &data_strings,
			    &data_nstrings);
			for (i = 0; i < data_nstrings; i++) {
				rcm_log_message(RCM_TRACE3,
				    "\t\"%s\" (string)\n", data_strings[i]);
				if (i < (data_nstrings - 1))
					rcm_log_message(RCM_TRACE3, "\t\t\t");
			}
			break;

		default:
			rcm_log_message(RCM_TRACE3, "<not dumped>\n");
			break;
		}
	}
}
