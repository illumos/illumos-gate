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
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/fork.h>
#include <libcontract.h>
#include <libzonecfg.h>
#include <sys/contract/process.h>
#include <sys/ctfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zdoor-int.h"
#include "zerror.h"

#define	ZDOOR_FMT_STR	"/var/tmp/.%s"


static int
init_template(void)
{
	int fd = 0;
	int err = 0;

	fd = open64(CTFS_ROOT "/process/template", O_RDWR);
	if (fd == -1)
		return (-1);

	err |= ct_tmpl_set_critical(fd, 0);
	err |= ct_tmpl_set_informative(fd, 0);
	err |= ct_pr_tmpl_set_fatal(fd, CT_PR_EV_HWERR);
	err |= ct_pr_tmpl_set_param(fd, CT_PR_PGRPONLY | CT_PR_REGENT);
	if (err || ct_tmpl_activate(fd)) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

static int
contract_latest(ctid_t *id)
{
	int cfd = 0;
	int r = 0;
	ct_stathdl_t st = {0};
	ctid_t result = {0};

	if ((cfd = open64(CTFS_ROOT "/process/latest", O_RDONLY)) == -1)
		return (errno);
	if ((r = ct_status_read(cfd, CTD_COMMON, &st)) != 0) {
		(void) close(cfd);
		return (r);
	}

	result = ct_status_get_id(st);
	ct_status_free(st);
	(void) close(cfd);

	*id = result;
	return (0);
}

static int
close_on_exec(int fd)
{
	int flags = fcntl(fd, F_GETFD, 0);
	if ((flags != -1) && (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != -1))
		return (0);
	return (-1);
}

static int
contract_open(ctid_t ctid, const char *type, const char *file, int oflag)
{
	char path[PATH_MAX];
	int n = 0;
	int fd = 0;

	if (type == NULL)
		type = "all";

	n = snprintf(path, PATH_MAX, CTFS_ROOT "/%s/%ld/%s", type, ctid, file);
	if (n >= sizeof (path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	fd = open64(path, oflag);
	if (fd != -1) {
		if (close_on_exec(fd) == -1) {
			int err = errno;
			(void) close(fd);
			errno = err;
			return (-1);
		}
	}
	return (fd);
}

static int
contract_abandon_id(ctid_t ctid)
{
	int fd = 0;
	int err = 0;

	fd = contract_open(ctid, "all", "ctl", O_WRONLY);
	if (fd == -1)
		return (errno);

	err = ct_ctl_abandon(fd);
	(void) close(fd);

	return (err);
}

/*
 * zdoor_fattach(zone,service,door,detach_only) is heavily borrowed from
 * zonestatd.  Basically this forks, zone_enter's the targeted zone,
 * fattaches to /var/tmp/.<service> with the door you've opened.
 * detach_only gets passed in on door_stop to fdetach in the targeted zone.
 * Note that this code really does require all the contract calls, which are
 * all the static functions preceding this (have a look at zone_enter; without
 * that code zone_enter will kick back EINVAL).
 */
int
zdoor_fattach(zoneid_t zoneid, const char *service, int door, int detach_only)
{
	int fd = 0;
	int len = 0;
	int pid = 0;
	int stat = 0;
	int tmpl_fd = 0;
	char path[MAXPATHLEN] = {0};
	ctid_t ct = -1;

	if (zoneid < 0) {
		zdoor_debug("zdoor_fattach: zoneid < 0");
		return (ZDOOR_ARGS_ERROR);
	}

	if (service == NULL) {
		zdoor_debug("zdoor_fattach: NULL service");
		return (ZDOOR_ARGS_ERROR);
	}

	if ((tmpl_fd = init_template()) < 0) {
		zdoor_warn("zdoor_fattach: init contract for %d:%s failed",
		    zoneid, service);
		return (ZDOOR_ERROR);
	}

	len = snprintf(NULL, 0, ZDOOR_FMT_STR, service) + 1;
	if (len > MAXPATHLEN)
		return (ZDOOR_ARGS_ERROR);
	(void) snprintf(path, len, ZDOOR_FMT_STR, service);

	zdoor_info("zdoor_fattach: ensuring %s", path);

	pid = fork();
	if (pid < 0) {
		(void) ct_tmpl_clear(tmpl_fd);
		zdoor_error("zdoor_fattach: unable to fork for zone_enter: %s",
		    strerror(errno));
		return (ZDOOR_OK);
	}

	if (pid == 0) {
		zdoor_debug("zdoor_fattach(CHILD): starting");
		(void) ct_tmpl_clear(tmpl_fd);
		(void) close(tmpl_fd);
		if (zone_enter(zoneid) != 0) {
			zdoor_debug("zdoor_fattach(CHILD): zone_enter fail %s",
			    strerror(errno));
			if (errno == EINVAL) {
				_exit(0);
			}
			_exit(1);
		}
		(void) fdetach(path);
		(void) unlink(path);
		if (detach_only) {
			zdoor_debug("zdoor_fattach(CHILD): detach only, done");
			_exit(0);
		}
		fd = open(path, O_CREAT|O_RDWR, 0644);
		if (fd < 0) {
			zdoor_debug("zdoor_fattach(CHILD): open failed: %s",
			    strerror(errno));
			_exit(2);
		}
		if (fattach(door, path) != 0) {
			zdoor_debug("zdoor_fattach(CHILD): fattach failed: %s",
			    strerror(errno));
			_exit(3);
		}
		_exit(0);
	}
	if (contract_latest(&ct) == -1)
		ct = -1;
	(void) ct_tmpl_clear(tmpl_fd);
	(void) close(tmpl_fd);
	(void) contract_abandon_id(ct);

	zdoor_debug("zdoor_fattach: waiting for child...");
	while (waitpid(pid, &stat, 0) != pid)
		;
	if (WIFEXITED(stat) && WEXITSTATUS(stat) == 0) {
		zdoor_debug("   child exited with success");
		zdoor_debug("zdoor_fattach: returning ZDOOR_OK");
		return (ZDOOR_OK);
	}

	zdoor_debug("   child exited with %d", WEXITSTATUS(stat));
	zdoor_debug("zdoor_fattach: returning ZDOOR_ERROR");
	return (ZDOOR_ERROR);
}

/*
 * zdoor_zone_is_running(zone) returns 1 if the specified zone is running, or 0
 * if it is any other state. It additionally eats any other errors it
 * encounters and returns 0 upon encountering them.
 */
boolean_t
zdoor_zone_is_running(zoneid_t zoneid)
{
	zone_state_t state;
	char zone[ZONENAME_MAX];
	if (zoneid < 0)
		return (B_FALSE);

	if (getzonenamebyid(zoneid, zone, ZONENAME_MAX) < 0)
		return (B_FALSE);

	if (!zone_get_state((char *)zone, &state) == Z_OK)
		return (B_FALSE);

	return (state == ZONE_STATE_RUNNING);
}

/*
 * zdoor_cookie_create simply allocates and initializes
 * memory.  Returns NULL on any error.
 */
zdoor_cookie_t *
zdoor_cookie_create(const char *zonename, const char *service,
const void *biscuit)
{
	zdoor_cookie_t *cookie = NULL;

	if (zonename == NULL || service == NULL)
		return (NULL);

	cookie = (zdoor_cookie_t *)calloc(1, sizeof (zdoor_cookie_t));
	if (cookie == NULL) {
		OUT_OF_MEMORY();
		return (NULL);
	}
	cookie->zdc_biscuit = (void *)biscuit;
	cookie->zdc_zonename = strdup((char *)zonename);
	if (cookie->zdc_zonename == NULL) {
		zdoor_cookie_free(cookie);
		OUT_OF_MEMORY();
		return (NULL);
	}
	cookie->zdc_service = strdup((char *)service);
	if (cookie->zdc_service == NULL) {
		zdoor_cookie_free(cookie);
		OUT_OF_MEMORY();
		return (NULL);
	}

	return (cookie);
}

/*
 * zdoor_cookie_free(cookie) cleans up any memory associated with the
 * specified cookie.
 */
void
zdoor_cookie_free(zdoor_cookie_t *cookie)
{
	if (cookie == NULL)
		return;

	if (cookie->zdc_zonename != NULL) {
		free(cookie->zdc_zonename);
		cookie->zdc_zonename = NULL;
	}

	if (cookie->zdc_service != NULL) {
		free(cookie->zdc_service);
		cookie->zdc_service = NULL;
	}

	free(cookie);
}
