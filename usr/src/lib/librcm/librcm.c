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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "librcm_impl.h"
#include "librcm_event.h"

#ifdef	DEBUG
static int rcm_debug = 1;
#define	dprintf(args) if (rcm_debug) (void) fprintf args
#else
#define	dprintf(args) /* nothing */
#endif	/* DEBUG */

static int extract_info(nvlist_t *, rcm_info_t **);
static int rcm_daemon_is_alive();
static int rcm_common(int, rcm_handle_t *, char **, uint_t, void *,
    rcm_info_t **);
static int rcm_direct_call(int, rcm_handle_t *, char **, uint_t, void *,
    rcm_info_t **);
static int rcm_daemon_call(int, rcm_handle_t *, char **, uint_t, void *,
    rcm_info_t **);
static int rcm_generate_nvlist(int, rcm_handle_t *, char **, uint_t, void *,
    char **, size_t *);
static int rcm_check_permission(void);

/*
 * Allocate a handle structure
 */
/*ARGSUSED2*/
int
rcm_alloc_handle(char *modname, uint_t flag, void *arg, rcm_handle_t **hdp)
{
	rcm_handle_t *hd;
	void *temp;
	char namebuf[MAXPATHLEN];

	if ((hdp == NULL) || (flag & ~RCM_ALLOC_HDL_MASK)) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	if (rcm_check_permission() == 0) {
		errno = EPERM;
		return (RCM_FAILURE);
	}

	if ((hd = calloc(1, sizeof (*hd))) == NULL) {
		return (RCM_FAILURE);
	}

	if (modname) {
		(void) snprintf(namebuf, MAXPATHLEN, "%s%s", modname,
			RCM_MODULE_SUFFIX);

		if ((hd->modname = strdup(namebuf)) == NULL) {
			free(hd);
			return (RCM_FAILURE);
		}

		if ((temp = rcm_module_open(namebuf)) == NULL) {
			free(hd->modname);
			free(hd);
			errno = EINVAL;
			return (RCM_FAILURE);
		}

		rcm_module_close(temp);
	}

	if (flag & RCM_NOPID) {
		hd->pid = (pid_t)0;
	} else {
		hd->pid = (pid_t)getpid();
	}

	*hdp = hd;
	return (RCM_SUCCESS);
}

/* free handle structure */
int
rcm_free_handle(rcm_handle_t *hd)
{
	if (hd == NULL) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	if (hd->modname) {
		free(hd->modname);
	}

	free(hd);
	return (RCM_SUCCESS);
}


/*
 * Operations which require daemon processing
 */

/* get registration and DR information from rcm_daemon */
int
rcm_get_info(rcm_handle_t *hd, char *rsrcname, uint_t flag, rcm_info_t **infop)
{
	char *rsrcnames[2];

	if ((flag & ~RCM_GET_INFO_MASK) || (infop == NULL)) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	/*
	 * rsrcname may be NULL if requesting dr operations or modinfo
	 */
	if ((rsrcname == NULL) &&
	    ((flag & RCM_DR_OPERATION|RCM_MOD_INFO) == 0)) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	return (rcm_common(CMD_GETINFO, hd, rsrcnames, flag, NULL, infop));
}

/* get registration and DR information from rcm_daemon (list version) */
int
rcm_get_info_list(rcm_handle_t *hd, char **rsrcnames, uint_t flag,
    rcm_info_t **infop)
{
	/* Requesting the current DR operations with a *list() is invalid */
	if ((flag & RCM_DR_OPERATION) || (flag & RCM_MOD_INFO)) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	return (rcm_common(CMD_GETINFO, hd, rsrcnames, flag, NULL, infop));
}

/* request to offline a resource before DR removal */
int
rcm_request_offline(rcm_handle_t *hd, char *rsrcname, uint_t flag,
    rcm_info_t **infop)
{
	char *rsrcnames[2];

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	return (rcm_request_offline_list(hd, rsrcnames, flag, infop));
}

/* request to offline a resource before DR removal (list version) */
int
rcm_request_offline_list(rcm_handle_t *hd, char **rsrcnames, uint_t flag,
    rcm_info_t **infop)
{
	if (flag & ~RCM_REQUEST_MASK) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	return (rcm_common(CMD_OFFLINE, hd, rsrcnames, flag, NULL, infop));
}

/* cancel offline request and allow apps to use rsrcname */
int
rcm_notify_online(rcm_handle_t *hd, char *rsrcname, uint_t flag,
    rcm_info_t **infop)
{
	char *rsrcnames[2];

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	return (rcm_notify_online_list(hd, rsrcnames, flag, infop));
}

/* cancel offline and allow apps to use resources (list version) */
int
rcm_notify_online_list(rcm_handle_t *hd, char **rsrcnames, uint_t flag,
    rcm_info_t **infop)
{
	if (flag & ~RCM_NOTIFY_MASK) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	return (rcm_common(CMD_ONLINE, hd, rsrcnames, flag, NULL, infop));
}

/* notify that rsrcname has been removed */
int
rcm_notify_remove(rcm_handle_t *hd, char *rsrcname, uint_t flag,
    rcm_info_t **infop)
{
	char *rsrcnames[2];

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	return (rcm_notify_remove_list(hd, rsrcnames, flag, infop));
}

/* notify that resrouces have been removed (list form) */
int
rcm_notify_remove_list(rcm_handle_t *hd, char **rsrcnames, uint_t flag,
    rcm_info_t **infop)
{
	if (flag & ~RCM_NOTIFY_MASK) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	return (rcm_common(CMD_REMOVE, hd, rsrcnames, flag, NULL, infop));
}

/* request for permission to suspend resource of interval time */
int
rcm_request_suspend(rcm_handle_t *hd, char *rsrcname, uint_t flag,
    timespec_t *interval, rcm_info_t **infop)
{
	char *rsrcnames[2];

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	return (rcm_request_suspend_list(hd, rsrcnames, flag, interval, infop));
}

/* request for permission to suspend resource of interval time (list form) */
int
rcm_request_suspend_list(rcm_handle_t *hd, char **rsrcnames, uint_t flag,
    timespec_t *interval, rcm_info_t **infop)
{
	if ((flag & ~RCM_REQUEST_MASK) || (interval == NULL) ||
	    (interval->tv_sec < 0) || (interval->tv_nsec < 0)) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	return (rcm_common(CMD_SUSPEND, hd, rsrcnames, flag, (void *)interval,
	    infop));
}

/* notify apps of the completion of resource suspension */
int
rcm_notify_resume(rcm_handle_t *hd, char *rsrcname, uint_t flag,
    rcm_info_t **infop)
{
	char *rsrcnames[2];

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	return (rcm_notify_resume_list(hd, rsrcnames, flag, infop));
}

/* notify apps of the completion of resource suspension (list form) */
int
rcm_notify_resume_list(rcm_handle_t *hd, char **rsrcnames, uint_t flag,
    rcm_info_t **infop)
{
	if (flag & ~(RCM_NOTIFY_MASK | RCM_SUSPENDED)) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	return (rcm_common(CMD_RESUME, hd, rsrcnames, flag, NULL, infop));
}

/* request a capacity change from apps */
int
rcm_request_capacity_change(rcm_handle_t *hd, char *rsrcname, uint_t flag,
    nvlist_t *nvl, rcm_info_t **infop)
{
	int rv;
	char *rsrcnames[2];

	if ((nvl == NULL) || (flag & ~RCM_REQUEST_MASK)) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	rv = rcm_common(CMD_REQUEST_CHANGE, hd, rsrcnames, flag, (void *)nvl,
	    infop);

	return (rv);
}

/* notify apps of a capacity change */
int
rcm_notify_capacity_change(rcm_handle_t *hd, char *rsrcname, uint_t flag,
    nvlist_t *nvl, rcm_info_t **infop)
{
	int rv;
	char *rsrcnames[2];

	if ((nvl == NULL) || (flag & ~RCM_REQUEST_MASK)) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	rv = rcm_common(CMD_NOTIFY_CHANGE, hd, rsrcnames, flag, (void *)nvl,
	    infop);

	return (rv);
}

/* notify apps of an event */
int
rcm_notify_event(rcm_handle_t *hd, char *rsrcname, uint_t flag, nvlist_t *nvl,
    rcm_info_t **infop)
{
	int rv;
	char *rsrcnames[2];

	/* No flags are defined yet for rcm_notify_event() */
	if ((nvl == NULL) || (flag != 0)) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	rv = rcm_common(CMD_EVENT, hd, rsrcnames, 0, (void *)nvl, infop);

	return (rv);
}

/*
 * Register to receive capacity changes. This requires a module to exist in
 * module directory. It should be called prior to using a new resource.
 */
/* ARGSUSED */
int
rcm_register_capacity(rcm_handle_t *hd, char *rsrcname, uint_t flag,
    rcm_info_t **infop)
{
	char *rsrcnames[2];

	if (flag & ~RCM_REGISTER_MASK) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	flag |= RCM_REGISTER_CAPACITY;

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	return (rcm_common(CMD_REGISTER, hd, rsrcnames, flag, NULL, NULL));
}

/* unregister interest in capacity changes */
int
rcm_unregister_capacity(rcm_handle_t *hd, char *rsrcname, uint_t flag)
{
	char *rsrcnames[2];

	if (flag & ~RCM_REGISTER_MASK) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	flag |= RCM_REGISTER_CAPACITY;

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	return (rcm_common(CMD_UNREGISTER, hd, rsrcnames, flag, NULL, NULL));
}

/*
 * Register to receive events. This requires a module to exist in module
 * directory. It should be called prior to using a new resource.
 */
/* ARGSUSED */
int
rcm_register_event(rcm_handle_t *hd, char *rsrcname, uint_t flag,
    rcm_info_t **infop)
{
	char *rsrcnames[2];

	if (flag & ~RCM_REGISTER_MASK) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	flag |= RCM_REGISTER_EVENT;

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	return (rcm_common(CMD_REGISTER, hd, rsrcnames, flag, NULL, NULL));
}

/* unregister interest in events */
int
rcm_unregister_event(rcm_handle_t *hd, char *rsrcname, uint_t flag)
{
	char *rsrcnames[2];

	if (flag & ~RCM_REGISTER_MASK) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	flag |= RCM_REGISTER_EVENT;

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	return (rcm_common(CMD_UNREGISTER, hd, rsrcnames, flag, NULL, NULL));
}

/*
 * Register interest in a resource. This requires a module to exist in module
 * directory. It should be called prior to using a new resource.
 *
 * Registration may be denied if it is presently locked by a DR operation.
 */
/* ARGSUSED */
int
rcm_register_interest(rcm_handle_t *hd, char *rsrcname, uint_t flag,
    rcm_info_t **infop)
{
	char *rsrcnames[2];

	if (flag & ~RCM_REGISTER_MASK) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	flag |= RCM_REGISTER_DR;

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	return (rcm_common(CMD_REGISTER, hd, rsrcnames, flag, NULL, NULL));
}

/* unregister interest in rsrcname */
int
rcm_unregister_interest(rcm_handle_t *hd, char *rsrcname, uint_t flag)
{
	char *rsrcnames[2];

	if (flag & ~RCM_REGISTER_MASK) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	flag |= RCM_REGISTER_DR;

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	return (rcm_common(CMD_UNREGISTER, hd, rsrcnames, flag, NULL, NULL));
}

/* get the current state of a resource */
int
rcm_get_rsrcstate(rcm_handle_t *hd, char *rsrcname, int *statep)
{
	int result;
	int flag = 0;
	rcm_info_t *infop = NULL;
	rcm_info_tuple_t *tuple = NULL;
	char *rsrcnames[2];

	if (statep == NULL) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	rsrcnames[0] = rsrcname;
	rsrcnames[1] = NULL;

	result = rcm_common(CMD_GETSTATE, hd, rsrcnames, flag, NULL, &infop);

	/*
	 * A successful result implies the presence of exactly one RCM info
	 * tuple containing the state of this resource (a combination of each
	 * client's resources).  If that's not true, change the result to
	 * RCM_FAILURE.
	 */
	if (result == RCM_SUCCESS) {
		if ((infop == NULL) ||
		    ((tuple = rcm_info_next(infop, NULL)) == NULL) ||
		    (rcm_info_next(infop, tuple) != NULL)) {
			result = RCM_FAILURE;
		} else if (infop && tuple) {
			*statep = rcm_info_state(tuple);
		}
	}

	if (infop)
		rcm_free_info(infop);

	return (result);
}

/*
 * RCM helper functions exposed to librcm callers.
 */

/* Free linked list of registration info */
void
rcm_free_info(rcm_info_t *info)
{
	while (info) {
		rcm_info_t *tmp = info->next;

		nvlist_free(info->info);
		free(info);

		info = tmp;
	}
}

/* return the next tuple in the info structure */
rcm_info_tuple_t *
rcm_info_next(rcm_info_t *info, rcm_info_tuple_t *tuple)
{
	if (info == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if (tuple == NULL) {
		return ((rcm_info_tuple_t *)info);
	}
	return ((rcm_info_tuple_t *)tuple->next);
}

/* return resource name */
const char *
rcm_info_rsrc(rcm_info_tuple_t *tuple)
{
	char *rsrcname = NULL;

	if (tuple == NULL || tuple->info == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if (errno = nvlist_lookup_string(tuple->info, RCM_RSRCNAME, &rsrcname))
		return (NULL);

	return (rsrcname);
}

const char *
rcm_info_info(rcm_info_tuple_t *tuple)
{
	char *info = NULL;

	if (tuple == NULL || tuple->info == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if (errno = nvlist_lookup_string(tuple->info, RCM_CLIENT_INFO, &info))
		return (NULL);

	return (info);
}

const char *
rcm_info_error(rcm_info_tuple_t *tuple)
{
	char *errstr = NULL;

	if (tuple == NULL || tuple->info == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if (errno = nvlist_lookup_string(tuple->info, RCM_CLIENT_ERROR,
	    &errstr))
		return (NULL);

	return (errstr);
}

/* return info string in the tuple */
const char *
rcm_info_modname(rcm_info_tuple_t *tuple)
{
	char *modname = NULL;

	if (tuple == NULL || tuple->info == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if (errno = nvlist_lookup_string(tuple->info, RCM_CLIENT_MODNAME,
	    &modname))
		return (NULL);

	return (modname);
}

/* return client pid in the tuple */
pid_t
rcm_info_pid(rcm_info_tuple_t *tuple)
{
	uint64_t pid64 = (uint64_t)0;

	if (tuple == NULL || tuple->info == NULL) {
		errno = EINVAL;
		return ((pid_t)0);
	}

	if (errno = nvlist_lookup_uint64(tuple->info, RCM_CLIENT_ID, &pid64))
		return ((pid_t)0);

	return ((pid_t)pid64);
}

/* return client state in the tuple */
int
rcm_info_state(rcm_info_tuple_t *tuple)
{
	int state;

	if (tuple == NULL || tuple->info == NULL) {
		errno = EINVAL;
		return (RCM_STATE_UNKNOWN);
	}

	if (errno = nvlist_lookup_int32(tuple->info, RCM_RSRCSTATE, &state))
		return (RCM_STATE_UNKNOWN);

	return (state);
}

/* return the generic properties in the tuple */
nvlist_t *
rcm_info_properties(rcm_info_tuple_t *tuple)
{
	char *buf;
	uint_t buflen;
	nvlist_t *nvl;

	if (tuple == NULL || tuple->info == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if (errno = nvlist_lookup_byte_array(tuple->info, RCM_CLIENT_PROPERTIES,
	    (uchar_t **)&buf, &buflen))
		return (NULL);

	if (errno = nvlist_unpack(buf, buflen, &nvl, 0)) {
		free(buf);
		return (NULL);
	}

	return (nvl);
}

/*
 * return operation sequence number
 *
 * This is private. Called by rcmctl only for testing purposes.
 */
int
rcm_info_seqnum(rcm_info_tuple_t *tuple)
{
	int seqnum;

	if (tuple == NULL || tuple->info == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (errno = nvlist_lookup_int32(tuple->info, RCM_SEQ_NUM, &seqnum))
		return (-1);

	return (seqnum);
}


/*
 * The following interfaces are PRIVATE to the RCM framework. They are not
 * declared static because they are called by rcm_daemon.
 */

/*
 * Invoke shell to execute command in MT safe manner.
 * Returns wait status or -1 on error.
 */
int
rcm_exec_cmd(char *cmd)
{
	pid_t pid;
	int status, w;
	char *argvec[] = {"sh", "-c", NULL, NULL};

	argvec[2] = cmd;
	if ((pid = fork1()) == 0) {
		(void) execv("/bin/sh", argvec);
		_exit(127);
	} else if (pid == -1) {
		return (-1);
	}

	do {
		w = waitpid(pid, &status, 0);
	} while (w == -1 && errno == EINTR);

	return ((w == -1) ? w : status);
}

/* Append info at the very end */
int
rcm_append_info(rcm_info_t **head, rcm_info_t *info)
{
	rcm_info_t *tuple;

	if (head == NULL) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	if ((tuple = *head) == NULL) {
		*head = info;
		return (RCM_SUCCESS);
	}

	while (tuple->next) {
		tuple = tuple->next;
	}
	tuple->next = info;
	return (RCM_SUCCESS);
}

/* get rcm module and rcm script directory names */

#define	N_MODULE_DIR	3	/* search 3 directories for modules */
#define	MODULE_DIR_HW	"/usr/platform/%s/lib/rcm/modules/"
#define	MODULE_DIR_GEN	"/usr/lib/rcm/modules/"

#define	N_SCRIPT_DIR	4	/* search 4 directories for scripts */
#define	SCRIPT_DIR_HW	"/usr/platform/%s/lib/rcm/scripts/"
#define	SCRIPT_DIR_GEN	"/usr/lib/rcm/scripts/"
#define	SCRIPT_DIR_ETC	"/etc/rcm/scripts/"


char *
rcm_module_dir(uint_t dirnum)
{
	if (dirnum < N_MODULE_DIR)
		return (rcm_dir(dirnum, NULL));
	else
		return (NULL);
}

char *
rcm_script_dir(uint_t dirnum)
{
	if (dirnum < N_SCRIPT_DIR)
		return (rcm_dir(dirnum + N_MODULE_DIR, NULL));
	else
		return (NULL);
}

char *
rcm_dir(uint_t dirnum, int *rcm_script)
{
	static char dir_name[N_MODULE_DIR + N_SCRIPT_DIR][MAXPATHLEN];

	char infobuf[MAXPATHLEN];

	if (dirnum >= (N_MODULE_DIR + N_SCRIPT_DIR))
		return (NULL);

	if (dir_name[0][0] == '\0') {
		/*
		 * construct the module directory names
		 */
		if (sysinfo(SI_PLATFORM, infobuf, MAXPATHLEN) == -1) {
			dprintf((stderr, "sysinfo %s\n", strerror(errno)));
			return (NULL);
		} else {
			if (snprintf(dir_name[0], MAXPATHLEN, MODULE_DIR_HW,
			    infobuf) >= MAXPATHLEN ||
			    snprintf(dir_name[N_MODULE_DIR + 1], MAXPATHLEN,
			    SCRIPT_DIR_HW, infobuf) >= MAXPATHLEN) {
				dprintf((stderr,
				    "invalid module or script directory for "
				    "platform %s\n", infobuf));
				return (NULL);
			}
		}

		if (sysinfo(SI_MACHINE, infobuf, MAXPATHLEN) == -1) {
			dprintf((stderr, "sysinfo %s\n", strerror(errno)));
			return (NULL);
		} else {
			if (snprintf(dir_name[1], MAXPATHLEN, MODULE_DIR_HW,
			    infobuf) >= MAXPATHLEN ||
			    snprintf(dir_name[N_MODULE_DIR + 2], MAXPATHLEN,
			    SCRIPT_DIR_HW, infobuf) >= MAXPATHLEN) {
				dprintf((stderr,
				    "invalid module or script directory for "
				    "machine type %s\n", infobuf));
				return (NULL);
			}
		}

		if (strlcpy(dir_name[2], MODULE_DIR_GEN, MAXPATHLEN) >=
		    MAXPATHLEN ||
		    strlcpy(dir_name[N_MODULE_DIR + 3], SCRIPT_DIR_GEN,
		    MAXPATHLEN) >= MAXPATHLEN ||
		    strlcpy(dir_name[N_MODULE_DIR + 0], SCRIPT_DIR_ETC,
		    MAXPATHLEN) >= MAXPATHLEN) {
			dprintf((stderr,
			    "invalid module or script generic directory\n"));
			return (NULL);
		}
	}

	if (rcm_script)
		*rcm_script = (dirnum < N_MODULE_DIR) ? 0 : 1;

	return (dir_name[dirnum]);
}

/*
 * Find the directory where the script is located.
 * If the script is found return a pointer to the directory where the
 * script was found otherwise return NULL.
 */
char *
rcm_get_script_dir(char *script_name)
{
	uint_t i;
	char *dir_name;
	char path[MAXPATHLEN];
	struct stat stats;

	for (i = 0; (dir_name = rcm_script_dir(i)) != NULL; i++) {
		if (snprintf(path, MAXPATHLEN, "%s%s", dir_name, script_name)
		    >= MAXPATHLEN) {
			dprintf((stderr, "invalid script %s skipped\n",
			    script_name));
			continue;
		}
		if (stat(path, &stats) == 0)
			return (dir_name);
	}

	return (NULL);
}

/*
 * Returns 1 if the filename is an rcm script.
 * Returns 0 if the filename is an rcm module.
 */
int
rcm_is_script(char *filename)
{
	char *tmp;

	if (((tmp = strstr(filename, RCM_MODULE_SUFFIX)) != NULL) &&
		(tmp[strlen(RCM_MODULE_SUFFIX)] == '\0'))
		return (0);
	else
		return (1);
}

/* Locate the module and call dlopen */
void *
rcm_module_open(char *modname)
{
	unsigned i;
	char *dir_name;
	void *dlhandle = NULL;
	char modpath[MAXPATHLEN];

#ifdef DEBUG
	struct stat sbuf;
#endif

	/*
	 * dlopen the module
	 */
	for (i = 0; (dir_name = rcm_module_dir(i)) != NULL; i++) {
		if (snprintf(modpath, MAXPATHLEN, "%s%s", dir_name, modname)
		    >= MAXPATHLEN) {
			dprintf((stderr, "invalid module %s skipped\n",
			    modname));
			continue;
		}

		if ((dlhandle = dlopen(modpath, RTLD_LAZY)) != NULL) {
			return (dlhandle);
		}

		dprintf((stderr, "failure (dlopen=%s)\n", dlerror()));
#ifdef DEBUG
		if (stat(modpath, &sbuf) == 0) {
			(void) fprintf(stderr, "%s is not a valid module\n",
			    modpath);
		}
#endif
	}

	dprintf((stderr, "module %s not found\n", modname));
	return (NULL);
}

/* dlclose module */
void
rcm_module_close(void *dlhandle)
{
	if (dlclose(dlhandle) == 0)
		return;

	dprintf((stderr, "dlclose: %s\n", dlerror()));
}


/*
 * stub implementation of rcm_log_message allows dlopen of rcm modules
 * to proceed in absence of rcm_daemon.
 *
 * This definition is interposed by the definition in rcm_daemon because of the
 * default search order implemented by the linker and dlsym(). All RCM modules
 * will see the daemon version when loaded by the rcm_daemon.
 */
/* ARGSUSED */
void
rcm_log_message(int level, char *message, ...)
{
	dprintf((stderr, "rcm_log_message stub\n"));
}

/*
 * Helper functions
 */

/*
 * Common routine for all rcm calls which require daemon processing
 */
static int
rcm_common(int cmd, rcm_handle_t *hd, char **rsrcnames, uint_t flag, void *arg,
    rcm_info_t **infop)
{
	int i;

	if (hd == NULL) {
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	if (getuid() != 0) {
		errno = EPERM;
		return (RCM_FAILURE);
	}

	if ((flag & (RCM_DR_OPERATION | RCM_MOD_INFO)) == 0) {
		if ((rsrcnames == NULL) || (rsrcnames[0] == NULL)) {
			errno = EINVAL;
			return (RCM_FAILURE);
		}

		for (i = 0; rsrcnames[i] != NULL; i++) {
			if (*rsrcnames[i] == '\0') {
				errno = EINVAL;
				return (RCM_FAILURE);
			}
		}
	}

	/*
	 * Check if handle is allocated by rcm_daemon. If so, this call came
	 * from an RCM module, so we make a direct call into rcm_daemon.
	 */
	if (hd->lrcm_ops != NULL) {
		return (rcm_direct_call(cmd, hd, rsrcnames, flag, arg, infop));
	}

	/*
	 * When not called from a RCM module (i.e. no recursion), zero the
	 * pointer just in case caller did not do so. For recursive calls,
	 * we want to append rcm_info_t after infop; zero it may cause
	 * memory leaks.
	 */
	if (infop) {
		*infop = NULL;
	}

	/*
	 * Now call into the daemon.
	 */
	return (rcm_daemon_call(cmd, hd, rsrcnames, flag, arg, infop));
}

/*
 * Caller is an RCM module, call directly into rcm_daemon.
 */
static int
rcm_direct_call(int cmd, rcm_handle_t *hd, char **rsrcnames, uint_t flag,
    void *arg, rcm_info_t **infop)
{
	int error;

	librcm_ops_t *ops = (librcm_ops_t *)hd->lrcm_ops;
	switch (cmd) {
	case CMD_GETINFO:
		error = ops->librcm_getinfo(rsrcnames, flag, hd->seq_num,
		    infop);
		break;

	case CMD_OFFLINE:
		error = ops->librcm_offline(rsrcnames, hd->pid, flag,
		    hd->seq_num, infop);
		break;

	case CMD_ONLINE:
		error = ops->librcm_online(rsrcnames, hd->pid, flag,
		    hd->seq_num, infop);
		break;

	case CMD_REMOVE:
		error = ops->librcm_remove(rsrcnames, hd->pid, flag,
		    hd->seq_num, infop);
		break;

	case CMD_SUSPEND:
		error = ops->librcm_suspend(rsrcnames, hd->pid, flag,
		    hd->seq_num, (timespec_t *)arg, infop);
		break;

	case CMD_RESUME:
		error = ops->librcm_resume(rsrcnames, hd->pid, flag,
		    hd->seq_num, infop);
		break;

	case CMD_REGISTER:
		error = ops->librcm_regis(hd->modname, rsrcnames[0], hd->pid,
		    flag, infop);
		break;

	case CMD_UNREGISTER:
		error = ops->librcm_unregis(hd->modname, rsrcnames[0], hd->pid,
		    flag);
		break;

	case CMD_REQUEST_CHANGE:
		error = ops->librcm_request_change(rsrcnames[0], hd->pid, flag,
		    hd->seq_num, (nvlist_t *)arg, infop);
		break;

	case CMD_NOTIFY_CHANGE:
		error = ops->librcm_notify_change(rsrcnames[0], hd->pid, flag,
		    hd->seq_num, (nvlist_t *)arg, infop);
		break;

	case CMD_EVENT:
		error = ops->librcm_notify_event(rsrcnames[0], hd->pid, flag,
		    hd->seq_num, (nvlist_t *)arg, infop);
		break;

	case CMD_GETSTATE:
		error = ops->librcm_getstate(rsrcnames[0], hd->pid, infop);
		break;

	default:
		dprintf((stderr, "invalid command: %d\n", cmd));
		error = EFAULT;
	}

	if (error > 0) {
		errno = error;
		error = RCM_FAILURE;
	}
	return (error);
}

/*
 * Call into rcm_daemon door to process the request
 */
static int
rcm_daemon_call(int cmd, rcm_handle_t *hd, char **rsrcnames, uint_t flag,
    void *arg, rcm_info_t **infop)
{
	int errno_found;
	int daemon_errno = 0;
	int error = RCM_SUCCESS;
	int delay = 300;
	int maxdelay = 10000;	/* 10 seconds */
	char *nvl_packed = NULL;
	size_t nvl_size = 0;
	nvlist_t *ret = NULL;
	nvpair_t *nvp;
	size_t rsize = 0;
	rcm_info_t *info = NULL;

	errno = 0;

	/*
	 * Decide whether to start the daemon
	 */
	switch (cmd) {
	case CMD_GETINFO:
	case CMD_OFFLINE:
	case CMD_ONLINE:
	case CMD_REMOVE:
	case CMD_SUSPEND:
	case CMD_RESUME:
	case CMD_REGISTER:
	case CMD_UNREGISTER:
	case CMD_EVENT:
	case CMD_REQUEST_CHANGE:
	case CMD_NOTIFY_CHANGE:
	case CMD_GETSTATE:
		break;

	default:
		errno = EFAULT;
		return (RCM_FAILURE);
	}

	if (rcm_daemon_is_alive() != 1) {
		dprintf((stderr, "failed to start rcm_daemon\n"));
		errno = EFAULT;
		return (RCM_FAILURE);
	}

	/*
	 * Generate a packed nvlist for the request
	 */
	if (rcm_generate_nvlist(cmd, hd, rsrcnames, flag, arg, &nvl_packed,
	    &nvl_size) < 0) {
		dprintf((stderr, "error in nvlist generation\n"));
		errno = EFAULT;
		return (RCM_FAILURE);
	}

	/*
	 * Make the door call and get a return event. We go into a retry loop
	 * when RCM_ET_EAGAIN is returned.
	 */
retry:
	if (get_event_service(RCM_SERVICE_DOOR, (void *)nvl_packed, nvl_size,
	    (void **)&ret, &rsize) < 0) {
		dprintf((stderr, "rcm_daemon call failed: %s\n",
		    strerror(errno)));
		free(nvl_packed);
		return (RCM_FAILURE);
	}

	assert(ret != NULL);

	/*
	 * nvlist_lookup_* routines don't work because the returned nvlist
	 * was nvlist_alloc'ed without the NV_UNIQUE_NAME flag.  Implement
	 * a sequential search manually, which is fine since there is only
	 * one RCM_RESULT value in the nvlist.
	 */
	errno_found = 0;
	nvp = NULL;
	while (nvp = nvlist_next_nvpair(ret, nvp)) {
		if (strcmp(nvpair_name(nvp), RCM_RESULT) == 0) {
			if (errno = nvpair_value_int32(nvp, &daemon_errno)) {
				error = RCM_FAILURE;
				goto out;
			}
			errno_found++;
			break;
		}
	}
	if (errno_found == 0) {
		errno = EFAULT;
		error = RCM_FAILURE;
		goto out;
	}

	if (daemon_errno == EAGAIN) {
		/*
		 * Wait and retry
		 */
		dprintf((stderr, "retry door_call\n"));

		if (delay > maxdelay) {
			errno = EAGAIN;
			error = RCM_FAILURE;
			goto out;
		}

		(void) poll(NULL, 0, delay);
		delay *= 2;		/* exponential back off */
		nvlist_free(ret);
		goto retry;
	}

	/*
	 * The door call succeeded. Now extract info from returned event.
	 */
	if (extract_info(ret, &info) != 0) {
		dprintf((stderr, "error in extracting event data\n"));
		errno = EFAULT;
		error = RCM_FAILURE;
		goto out;
	}

	if (infop)
		*infop = info;
	else
		rcm_free_info(info);

	if (daemon_errno) {
		if (daemon_errno > 0) {
			errno = daemon_errno;
			error = RCM_FAILURE;
		} else {
			error = daemon_errno;
		}
	}

out:
	if (nvl_packed)
		free(nvl_packed);
	nvlist_free(ret);
	dprintf((stderr, "daemon call is done. error = %d, errno = %s\n", error,
	    strerror(errno)));
	return (error);
}

/*
 * Extract registration info from event data.
 * Return 0 on success and -1 on failure.
 */
static int
extract_info(nvlist_t *nvl, rcm_info_t **infop)
{
	rcm_info_t *info = NULL;
	rcm_info_t *prev = NULL;
	rcm_info_t *tmp = NULL;
	char *buf;
	uint_t buflen;
	nvpair_t *nvp = NULL;

	while (nvp = nvlist_next_nvpair(nvl, nvp)) {

		buf = NULL;
		buflen = 0;

		if (strcmp(nvpair_name(nvp), RCM_RESULT_INFO) != 0)
			continue;

		if ((tmp = calloc(1, sizeof (*tmp))) == NULL) {
			dprintf((stderr, "out of memory\n"));
			goto fail;
		}

		if (errno = nvpair_value_byte_array(nvp, (uchar_t **)&buf,
		    &buflen)) {
			free(tmp);
			dprintf((stderr, "failed (nvpair_value=%s)\n",
			    strerror(errno)));
			goto fail;
		}
		if (errno = nvlist_unpack(buf, buflen, &(tmp->info), 0)) {
			free(tmp);
			dprintf((stderr, "failed (nvlist_unpack=%s)\n",
			    strerror(errno)));
			goto fail;
		}

		if (info == NULL) {
			prev = info = tmp;
		} else {
			prev->next = tmp;
			prev = tmp;
		}
	}

	*infop = info;
	return (0);

fail:
	rcm_free_info(info);
	*infop = NULL;
	return (-1);
}

/* Generate a packed nvlist for communicating with RCM daemon */
static int
rcm_generate_nvlist(int cmd, rcm_handle_t *hd, char **rsrcnames, uint_t flag,
    void *arg, char **nvl_packed, size_t *nvl_size)
{
	int nrsrcnames;
	char *buf = NULL;
	size_t buflen = 0;
	nvlist_t *nvl = NULL;

	assert((nvl_packed != NULL) && (nvl_size != NULL));

	*nvl_size = 0;
	*nvl_packed = NULL;

	/* Allocate an empty nvlist */
	if ((errno = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0)) > 0) {
		dprintf((stderr, "failed (nvlist_alloc=%s).\n",
		    strerror(errno)));
		return (-1);
	}

	/* Stuff in all the arguments for the daemon call */
	if (nvlist_add_int32(nvl, RCM_CMD, cmd) != 0) {
		dprintf((stderr, "failed (nvlist_add(CMD)=%s).\n",
		    strerror(errno)));
		goto fail;
	}
	if (rsrcnames) {
		nrsrcnames = 0;
		while (rsrcnames[nrsrcnames] != NULL)
			nrsrcnames++;
		if (nvlist_add_string_array(nvl, RCM_RSRCNAMES, rsrcnames,
		    nrsrcnames) != 0) {
			dprintf((stderr, "failed (nvlist_add(RSRCNAMES)=%s).\n",
			    strerror(errno)));
			goto fail;
		}
	}
	if (hd->modname) {
		if (nvlist_add_string(nvl, RCM_CLIENT_MODNAME, hd->modname)
		    != 0) {
			dprintf((stderr,
			    "failed (nvlist_add(CLIENT_MODNAME)=%s).\n",
			    strerror(errno)));
			goto fail;
		}
	}
	if (hd->pid) {
		if (nvlist_add_uint64(nvl, RCM_CLIENT_ID, hd->pid) != 0) {
			dprintf((stderr, "failed (nvlist_add(CLIENT_ID)=%s).\n",
			    strerror(errno)));
			goto fail;
		}
	}
	if (flag) {
		if (nvlist_add_uint32(nvl, RCM_REQUEST_FLAG, flag) != 0) {
			dprintf((stderr,
			    "failed (nvlist_add(REQUEST_FLAG)=%s).\n",
			    strerror(errno)));
			goto fail;
		}
	}
	if (arg && cmd == CMD_SUSPEND) {
		if (nvlist_add_byte_array(nvl, RCM_SUSPEND_INTERVAL,
		    (uchar_t *)arg, sizeof (timespec_t)) != 0) {
			dprintf((stderr,
			    "failed (nvlist_add(SUSPEND_INTERVAL)=%s).\n",
			    strerror(errno)));
			goto fail;
		}
	}
	if (arg &&
	    ((cmd == CMD_REQUEST_CHANGE) || (cmd == CMD_NOTIFY_CHANGE))) {
		if (errno = nvlist_pack(arg, &buf, &buflen, NV_ENCODE_NATIVE,
		    0)) {
			dprintf((stderr,
			    "failed (nvlist_pack(CHANGE_DATA)=%s).\n",
			    strerror(errno)));
			goto fail;
		}
		if (nvlist_add_byte_array(nvl, RCM_CHANGE_DATA, (uchar_t *)buf,
		    buflen) != 0) {
			dprintf((stderr,
			    "failed (nvlist_add(CHANGE_DATA)=%s).\n",
			    strerror(errno)));
			goto fail;
		}
	}
	if (arg && cmd == CMD_EVENT) {
		if (errno = nvlist_pack(arg, &buf, &buflen, NV_ENCODE_NATIVE,
		    0)) {
			dprintf((stderr,
			    "failed (nvlist_pack(CHANGE_DATA)=%s).\n",
			    strerror(errno)));
			goto fail;
		}
		if (nvlist_add_byte_array(nvl, RCM_EVENT_DATA, (uchar_t *)buf,
		    buflen) != 0) {
			dprintf((stderr,
			    "failed (nvlist_add(EVENT_DATA)=%s).\n",
			    strerror(errno)));
			goto fail;
		}
	}

	/* Pack the nvlist */
	if (errno = nvlist_pack(nvl, nvl_packed, nvl_size, NV_ENCODE_NATIVE,
	    0)) {
		dprintf((stderr, "failed (nvlist_pack=%s).\n",
		    strerror(errno)));
		goto fail;
	}

	/* If an argument was packed intermediately, free the buffer */
	if (buf)
		free(buf);

	/* Free the unpacked version of the nvlist and return the packed list */
	nvlist_free(nvl);
	return (0);

fail:
	if (buf)
		free(buf);
	nvlist_free(nvl);
	if (*nvl_packed)
		free(*nvl_packed);
	*nvl_packed = NULL;
	*nvl_size = 0;
	return (-1);
}

/* check if rcm_daemon is up and running */
static int
rcm_daemon_is_alive()
{
	int lasttry;
	struct stat st;
	nvlist_t *nvl;
	char *buf = NULL;
	size_t buflen = 0;
	int delay = 300;
	const int maxdelay = 10000;	/* 10 sec */

	/* generate a packed nvlist for the door knocking */
	if (errno = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0)) {
		dprintf((stderr, "nvlist_alloc failed: %s\n", strerror(errno)));
		return (0);
	}
	if (errno = nvlist_add_int32(nvl, RCM_CMD, CMD_KNOCK)) {
		dprintf((stderr, "nvlist_add failed: %s\n", strerror(errno)));
		nvlist_free(nvl);
		return (0);
	}
	if (errno = nvlist_pack(nvl, &buf, &buflen, NV_ENCODE_NATIVE, 0)) {
		dprintf((stderr, "nvlist_pack failed: %s\n", strerror(errno)));
		nvlist_free(nvl);
		return (0);
	}
	nvlist_free(nvl);

	/*
	 * check the door and knock on it
	 */
	if ((stat(RCM_SERVICE_DOOR, &st) == 0) &&
	    (get_event_service(RCM_SERVICE_DOOR, (void *)buf, buflen, NULL,
	    NULL) == 0)) {
		free(buf);
		return (1);	/* daemon is alive */
	}

	/*
	 * Attempt to start the daemon.
	 * If caller has SIGCHLD set to SIG_IGN or its SA_NOCLDWAIT
	 * flag set, waitpid(2) (hence rcm_exec_cmd) will fail.
	 * get_event_service will determine if the rcm_daemon started.
	 */
	dprintf((stderr, "exec: %s\n", RCM_DAEMON_START));
	(void) rcm_exec_cmd(RCM_DAEMON_START);

	/*
	 * Wait for daemon to respond, timeout at 10 sec
	 */
	while (((lasttry = get_event_service(RCM_SERVICE_DOOR, (void *)buf,
	    buflen, NULL, NULL)) != 0) &&
	    ((errno == EBADF) || (errno == ESRCH))) {
		if (delay > maxdelay) {
			break;
		}
		(void) poll(NULL, 0, delay);
		delay *= 2;
	}

	free(buf);
	if (lasttry == 0)
		return (1);
	return (0);
}

/*
 * Check permission.
 *
 * The policy is root only for now. Need to relax this when interface level
 * is raised.
 */
static int
rcm_check_permission(void)
{
	return (getuid() == 0);
}

/*
 * Project private function - for use by RCM MSTC tests
 *
 * Get the client name (rcm module name or script name) corresponding to
 * the given rcm handle.
 */
const char *
rcm_get_client_name(rcm_handle_t *hd)
{
	return (hd->modname);
}
