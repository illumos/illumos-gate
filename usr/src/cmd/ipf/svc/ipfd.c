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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file delivers svc.ipfd, the daemon that monitors changes to
 * firewall capable services and requests IPfilter configuration update
 * on behalf of the service. Essentially, the daemon listens for
 * service changes and forks the program that update a service's
 * IPfilter configuration.
 *
 * - A firewall capable SMF service can restrict network access to its
 *   service by providing a firewall policy that can be translated into
 *   a set of IPfilter rules. The mentioned firewall policy is stored in
 *   firewall_config and firewall_context property groups. If one of these
 *   two property groups exist, the service is considered to be firewall
 *   capable.
 *
 * - A request to update service's IPfilter configuration is made for
 *   actions that affect service's configuration or running state. The
 *   actions are:
 *	- enable/disable
 *	- refresh/restart
 *	- maintenance/clear maintenance
 *
 * Lacking a generic SMF mechanism to observe service state changes, the
 * daemon observe change events by listening to changes to 'general',
 * 'general_ovr', and 'restarter_actions' property groups. This is not a
 * stable interface and should be replaced when a SMF supported mechanism
 * becomes available.
 *
 * - The program responsible for updating service's IPfilter configuration
 *   is /lib/svc/method/ipfilter. This program is called as:
 *
 *   /lib/svc/method/ipfilter fw_update fmri
 *
 *   where fmri the instance fmri of the service to be updated.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <umem.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>

#define	IPFILTER_FMRI		"svc:/network/ipfilter:default"
#define	RPCBIND_FMRI		"svc:/network/rpc/bind:default"
#define	IPF_UPDATE_CMD		"/lib/svc/method/ipfilter"

#define	SCF_SNAPSHOT_RUNNING	"running"
#define	SCF_PG_FW_CONTEXT	"firewall_context"
#define	SCF_PG_FW_CONFIG	"firewall_config"
#define	SCF_PG_REFRESH		"refresh"
#define	SCF_PG_INETD		"inetd"

#define	SCF_PROPERTY_ISRPC	"isrpc"

#define	MAX_RETRY		7
#define	DEV_NULL		"/dev/null"

static scf_handle_t *h;
static ssize_t max_scf_fmri_size;
static ssize_t max_scf_name_size;

static scf_instance_t *inst;
static scf_snapshot_t *snap;
static scf_propertygroup_t *scratch_pg;
static scf_property_t *scratch_prop;
static scf_value_t *scratch_v;

static char *scratch_fmri;
static char *scratch_name;

static const char *all_props[] = {
	SCF_PROPERTY_REFRESH, SCF_PROPERTY_RESTART, SCF_PROPERTY_MAINT_ON,
	SCF_PROPERTY_MAINT_ON_IMMEDIATE, SCF_PROPERTY_MAINT_ON_IMMTEMP,
	SCF_PROPERTY_MAINT_ON_TEMPORARY, SCF_PROPERTY_MAINT_OFF
};
#define	ALL_PROPS_CNT		7

static const char *maint_props[] = {
	SCF_PROPERTY_REFRESH, SCF_PROPERTY_RESTART, SCF_PROPERTY_MAINT_OFF };
#define	MAINT_PROPS_CNT		3

static int ipfilter_update(const char *);

static int
daemonize_self(void)
{
	pid_t pid;
	int fd;

	(void) close(STDIN_FILENO);

	if ((fd = open(DEV_NULL, O_RDONLY)) == -1) {
		(void) printf("Could not open /dev/null: %s\n",
		    strerror(errno));
	} else if (fd != STDIN_FILENO) {
		(void) dup2(fd, STDIN_FILENO);
		(void) close(fd);
	}
	(void) dup2(STDERR_FILENO, STDOUT_FILENO);
	closefrom(3);

	if ((pid = fork1()) < 0) {
		(void) printf("fork() failed: %s\n", strerror(errno));
		return (1);
	}

	if (pid != 0)
		exit(0);

	(void) setsid();
	(void) chdir("/");

	return (0);
}

static void
repository_rebind(scf_handle_t *hndl)
{
	int c = 0;

	(void) scf_handle_unbind(hndl);
	while ((scf_handle_bind(hndl)) != 0) {
		if (c > MAX_RETRY) {
			syslog(LOG_ERR | LOG_DAEMON, "Repository access "
			    "unavailable. Couldn't bind handle: %s\n",
			    scf_strerror(scf_error()));
			syslog(LOG_ERR | LOG_DAEMON, "Service specific"
			    "IPfilter configuration may not be updated "
			    "properly\n");

			exit(1);
		} else {
			c++;
		}

		(void) sleep(1);
	}
}

static void
repository_notify_setup(scf_handle_t *h)
{
	for (;;) {
		if (_scf_notify_add_pgtype(h, SCF_GROUP_FRAMEWORK) ==
		    SCF_SUCCESS)
			break;

		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			repository_rebind(h);
			break;

		case SCF_ERROR_NO_RESOURCES:
			(void) sleep(1);
			break;

		default:
			syslog(LOG_ERR | LOG_DAEMON,
			    "Abort: Couldn't set up repository notification "
			    "for pg type %s: %s\n", SCF_GROUP_FRAMEWORK,
			    scf_strerror(scf_error()));
			abort();
		}
	}
}

/*
 * If the repository connection is lost, rebind and re-setup repository
 * notification. During the repository connection outage, services that
 * changed states wouldn't get the corresponding firewall update. To make
 * we're not out of sync, update the entire system firewall configuration,
 * invoke ipfilter_update(IPFILTER_FMRI).
 */
static void
repository_setup()
{
	repository_rebind(h);
	repository_notify_setup(h);
	if (ipfilter_update(IPFILTER_FMRI) == -1) {
		syslog(LOG_ERR | LOG_DAEMON,
		    "Failed to reconfigure system firewall.\n");
	}
}

static int
pg_get_prop_value(const scf_propertygroup_t *pg, const char *pname,
    scf_value_t *v)
{
	if (pg == NULL || pname == NULL || v == NULL)
		return (-1);

	if (scf_pg_get_property(pg, pname, scratch_prop) == -1 ||
	    scf_property_get_value(scratch_prop, v) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_DELETED:
			break;

		default:
			syslog(LOG_ERR | LOG_DAEMON,
			    "scf_pg_get_property failed for %s: %s\n",
			    pname, scf_strerror(scf_error()));
		}
		return (-1);
	}
	return (0);
}

static int
is_correct_event(const char *fmri, const scf_propertygroup_t *pg,
    const boolean_t isrpc)
{
	char *state = NULL;
	const char **proplist = all_props;
	int prop_cnt = ALL_PROPS_CNT;

	int i, ret = 0;

	if (scf_pg_get_name(pg, scratch_name, max_scf_name_size) < 0) {
		syslog(LOG_ERR | LOG_DAEMON, "scf_pg_get_name failed: %s\n",
		    scf_strerror(scf_error()));
		return (-1);
	}

	/*
	 * We care about enable, disable, and refresh since that's
	 * when we activate, deactivate, or change firewall policy.
	 *
	 *  - enable/disable -> change in "general" or "general_ovr"
	 *  - refresh/restart -> change in "restarter_actions"
	 */
	if (strcmp(scratch_name, SCF_PG_GENERAL) == 0 ||
	    strcmp(scratch_name, SCF_PG_GENERAL_OVR) == 0) {
		syslog(LOG_DEBUG | LOG_DAEMON, "Action: %s", scratch_name);
		return (1);
	}

	if ((state = smf_get_state(fmri)) == NULL) {
		syslog(LOG_ERR | LOG_DAEMON, "smf_get_state failed for %s: "
		    "%s\n", fmri, scf_strerror(scf_error()));
		return (-1);
	}

	syslog(LOG_DEBUG | LOG_DAEMON, "%s STATE: %s \n", fmri, state);
	if (strcmp(state, SCF_STATE_STRING_MAINT) == 0) {
		proplist = maint_props;
		prop_cnt = MAINT_PROPS_CNT;
	}

	/*
	 * Only concerned with refresh, restart, and maint on|off actions.
	 * RPC services are restarted whenever rpc/bind restarts so it's
	 * an automatic valid event for RPC services.
	 */
	if (isrpc) {
		ret = 1;
		goto out;
	} else if (strcmp(scratch_name, SCF_PG_RESTARTER_ACTIONS) == 0) {
		for (i = 0; i < prop_cnt; i++) {
			if (pg_get_prop_value(pg, proplist[i],
			    scratch_v) == 0) {
				syslog(LOG_DEBUG | LOG_DAEMON, "Action: %s/%s",
				    scratch_name, proplist[i]);

				ret = 1;
				goto out;
			}
		}
	}

out:
	if (state)
		free(state);

	return (ret);
}

static int
ipfilter_update(const char *fmri)
{
	pid_t pid;
	int status, ret = 0;

	syslog(LOG_DEBUG | LOG_DAEMON, "ipfilter_update: %s\n", fmri);

	/*
	 * Start refresh in another process
	 */
	if ((pid = fork1()) < 0) {
		syslog(LOG_ERR | LOG_DAEMON, "Couldn't fork to refresh "
		    "ipfilter for %s: %s", fmri, strerror(errno));
		ret = 1;
		goto out;
	}

	if (pid == 0) {
		if (execl(IPF_UPDATE_CMD, IPF_UPDATE_CMD, "fw_update", fmri,
		    NULL) == -1)
			syslog(LOG_ERR | LOG_DAEMON, "execl() failed for "
			    "%s: %s", fmri, strerror(errno));

		exit(1);
	}

	/*
	 * Parent - only one update at a time.
	 */
	(void) wait(&status);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		ret = 1;

out:
	if (ret == 1)
		syslog(LOG_ERR | LOG_DAEMON, "Firewall update failed "
		    "for: %s\n", fmri);

	return (ret);
}

/*
 * Determine whether a given instance is a RPC service. Repository and
 * libscf errors are treated as if the service isn't an RPC service,
 * returning B_FALSE to indicate validation failure.
 */
static boolean_t
service_is_rpc(const scf_instance_t *inst)
{
	scf_snapshot_t *lsnap = NULL;
	uint8_t	isrpc;

	if (scf_instance_get_snapshot(inst, SCF_SNAPSHOT_RUNNING, snap) != 0) {
		syslog(LOG_DEBUG | LOG_DAEMON,
		    "Could not get running snapshot, using editing value\n");
	} else {
		lsnap = snap;
	}

	if (scf_instance_get_pg_composed(inst, lsnap, SCF_PG_INETD,
	    scratch_pg) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_DELETED:
			break;

		default:
			syslog(LOG_ERR | LOG_DAEMON,
			    "scf_instance_get_pg_composed failed: %s\n",
			    scf_strerror(scf_error()));
			return (B_FALSE);
		}

		if (scf_instance_get_pg_composed(inst, lsnap,
		    SCF_PG_FW_CONTEXT, scratch_pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_NOT_FOUND:
			case SCF_ERROR_DELETED:
				break;

			default:
				syslog(LOG_ERR | LOG_DAEMON,
				    "scf_instance_get_pg_composed failed: %s\n",
				    scf_strerror(scf_error()));
			}
			return (B_FALSE);
		}
	}

	if (pg_get_prop_value(scratch_pg, SCF_PROPERTY_ISRPC, scratch_v) == -1)
		return (B_FALSE);

	if (scf_value_get_boolean(scratch_v, &isrpc) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "scf_value_get_boolean failed: "
		    "%s\n", scf_strerror(scf_error()));
		return (B_FALSE);
	}

	if (isrpc)
		return (B_TRUE);
	else
		return (B_FALSE);
}

static int
instance_has_firewall(scf_instance_t *inst)
{
	scf_snapshot_t *lsnap = NULL;

	if (scf_instance_get_snapshot(inst, SCF_SNAPSHOT_RUNNING, snap) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			syslog(LOG_ERR | LOG_DAEMON,
			    "scf_instance_get_snapshot failed: %s\n",
			    scf_strerror(scf_error()));
			repository_setup();
			return (-1);

		case SCF_ERROR_DELETED:
		default:
			/*
			 * If running snapshot is not available for
			 * other reasons, fall back to current values.
			 */
			syslog(LOG_DEBUG | LOG_DAEMON, "Could not get "
			    "running snapshot, using current value\n");
		}
	} else {
		lsnap = snap;
	}

	/*
	 * Update service's IPfilter configuration if either
	 * SCF_PG_FW_CONTEXT or SCF_PG_FW_CONFIG exists.
	 */
	if (scf_instance_get_pg_composed(inst, lsnap, SCF_PG_FW_CONTEXT,
	    scratch_pg) == 0) {
		return (1);
	} else {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_DELETED:
			break;

		case SCF_ERROR_CONNECTION_BROKEN:
			repository_setup();
			/* FALLTHROUGH */
		default:
			syslog(LOG_ERR | LOG_DAEMON,
			    "scf_instance_get_pg_composed failed: %s\n",
			    scf_strerror(scf_error()));
			return (-1);
		}
	}

	if (scf_instance_get_pg_composed(inst, lsnap, SCF_PG_FW_CONFIG,
	    scratch_pg) == -1) {
		/*
		 * It's either a non-firewall service or a failure to
		 * read firewall pg, just continue and listen for
		 * future events.
		 */
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_DELETED:
			return (0);

		case SCF_ERROR_CONNECTION_BROKEN:
			repository_setup();
			/* FALLTHROUGH */
		default:
			syslog(LOG_ERR | LOG_DAEMON,
			    "scf_instance_get_pg_composed failed: %s\n",
			    scf_strerror(scf_error()));
			return (-1);
		}
	}
	return (1);
}

static int
repository_event_process(scf_propertygroup_t *pg)
{
	boolean_t isrpc = B_FALSE;
	int res;

	/*
	 * Figure out it's a firewall capable instance and call ipfilter_update
	 * if it is.
	 */
	if (scf_pg_get_parent_instance(pg, inst) == -1) {
		/* Not an error if pg doesn't belong to a valid instance */
		if (scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED) {
			return (0);
		}

		syslog(LOG_ERR | LOG_DAEMON, "scf_pg_get_parent_instance "
		    "failed: %s\n", scf_strerror(scf_error()));

		if (scf_error() == SCF_ERROR_CONNECTION_BROKEN)
			repository_setup();

		return (1);
	}

	if (scf_instance_to_fmri(inst, scratch_fmri, max_scf_fmri_size) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "scf_instance_to_fmri "
		    "failed: %s\n", scf_strerror(scf_error()));

		if (scf_error() == SCF_ERROR_CONNECTION_BROKEN)
			repository_setup();

		return (1);
	}

	if (strcmp(scratch_fmri, IPFILTER_FMRI) == 0) {
		return (0);
	}

	isrpc = service_is_rpc(inst);

	/*
	 * If it's not an event we're interested in, returns success.
	 */
	res = is_correct_event(scratch_fmri, pg, isrpc);
	if (res == -1) {
		syslog(LOG_ERR | LOG_DAEMON,
		    "is_correct_event failed for %s.\n", scratch_fmri);
		return (1);
	} else if (res == 0) {
		return (0);
	}

	/*
	 * Proceed only if instance has firewall policy.
	 */
	res = instance_has_firewall(inst);
	if (res == -1) {
		syslog(LOG_ERR | LOG_DAEMON,
		    "instance_has_firewall failed for %s.\n", scratch_fmri);
		return (1);
	} else if (res == 0) {
		return (0);
	}

	if (ipfilter_update(scratch_fmri) == -1) {
		return (1);
	}

	return (0);
}

static int
repository_event_wait()
{
	scf_propertygroup_t *pg;
	char *fmri, *scratch;
	const char *inst_name, *pg_name;
	ssize_t res;

	if ((fmri = umem_alloc(max_scf_fmri_size, UMEM_DEFAULT)) == NULL) {
		syslog(LOG_ERR | LOG_DAEMON, "Out of memory");
		return (1);
	}

	if ((scratch = umem_alloc(max_scf_fmri_size, UMEM_DEFAULT)) == NULL) {
		syslog(LOG_ERR | LOG_DAEMON, "Out of memory");
		return (1);
	}

	if ((pg = scf_pg_create(h)) == NULL) {
		syslog(LOG_ERR | LOG_DAEMON, "scf_pg_create failed: %s\n",
		    scf_strerror(scf_error()));
		return (1);
	}

	repository_notify_setup(h);

	for (;;) {
		/*
		 * Calling _scf_notify_wait which will block this thread
		 * until it's notified of a framework event.
		 *
		 * Note: fmri is only set on delete events.
		 */
		res = _scf_notify_wait(pg, fmri, max_scf_fmri_size);
		if (res < 0) {
			syslog(LOG_ERR | LOG_DAEMON, "_scf_notify_wait "
			    "failed: %s\n", scf_strerror(scf_error()));
			repository_setup();
		} else if (res == 0) {
			if (repository_event_process(pg))
				syslog(LOG_ERR | LOG_DAEMON, "Service may have "
				    "incorrect IPfilter configuration\n");
		} else {
			/*
			 * The received event is a deletion of a service,
			 * instance or pg. If it's a deletion of an instance,
			 * update the instance's IPfilter configuration.
			 */
			syslog(LOG_DEBUG | LOG_DAEMON, "Deleted: %s", fmri);

			(void) strlcpy(scratch, fmri, max_scf_fmri_size);
			if (scf_parse_svc_fmri(scratch, NULL, NULL, &inst_name,
			    &pg_name, NULL) != SCF_SUCCESS)
				continue;

			if (inst_name != NULL && pg_name == NULL) {
				(void) ipfilter_update(fmri);
			}
		}
	}

	/*NOTREACHED*/
}

int
main()
{
	if (daemonize_self() == 1)
		return (1);

	max_scf_fmri_size = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH) + 1;
	max_scf_name_size = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;

	assert(max_scf_fmri_size > 0);
	assert(max_scf_name_size > 0);

	if ((h = scf_handle_create(SCF_VERSION)) == NULL) {
		syslog(LOG_ERR | LOG_DAEMON, "scf_handle_create failed: %s\n",
		    scf_strerror(scf_error()));
		return (1);
	}

	repository_rebind(h);

	scratch_fmri = umem_alloc(max_scf_fmri_size, UMEM_DEFAULT);
	scratch_name = umem_alloc(max_scf_name_size, UMEM_DEFAULT);

	if (scratch_fmri == NULL || scratch_name == NULL) {
		syslog(LOG_ERR | LOG_DAEMON, "Out of memory");
		return (1);
	}

	inst = scf_instance_create(h);
	snap = scf_snapshot_create(h);
	scratch_pg = scf_pg_create(h);
	scratch_prop = scf_property_create(h);
	scratch_v = scf_value_create(h);

	if (inst == NULL || snap == NULL || scratch_pg == NULL ||
	    scratch_prop == NULL || scratch_v == NULL) {
		syslog(LOG_ERR | LOG_DAEMON, "Initialization failed: %s\n",
		    scf_strerror(scf_error()));
		return (1);
	}

	return (repository_event_wait());
}
