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
 * Main startup code for SMB/NETBIOS and some utility routines
 * for the NETBIOS layer.
 */

#include <sys/tzfile.h>
#include <assert.h>
#include <synch.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <smbns_netbios.h>

#define	SMB_NETBIOS_DUMP_FILE		"netbios"

static netbios_service_t nbtd;

static void smb_netbios_shutdown(void);
static void *smb_netbios_service(void *);
static void smb_netbios_dump(void);

/*
 * Start the NetBIOS services
 */
int
smb_netbios_start(void)
{
	pthread_t	tid;
	pthread_attr_t	attr;
	int		rc;

	if (smb_netbios_cache_init() < 0)
		return (-1);

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&tid, &attr, smb_netbios_service, NULL);
	(void) pthread_attr_destroy(&attr);
	return (rc);
}

/*
 * Stop the NetBIOS services
 */
void
smb_netbios_stop(void)
{
	char	fname[MAXPATHLEN];

	smb_netbios_event(NETBIOS_EVENT_STOP);

	(void) snprintf(fname, MAXPATHLEN, "%s/%s",
	    SMB_VARRUN_DIR, SMB_NETBIOS_DUMP_FILE);
	(void) unlink(fname);

}

/*
 * Launch the NetBIOS Name Service, Datagram and Browser services
 * and then sit in a loop providing a 1 second resolution timer.
 * The timer will:
 *	- update the netbios stats file every 10 minutes
 *	- clean the cache every 10 minutes
 */
/*ARGSUSED*/
static void *
smb_netbios_service(void *arg)
{
	static uint32_t	ticks = 0;
	pthread_t	tid;
	int		rc;

	smb_netbios_event(NETBIOS_EVENT_START);

	rc = pthread_create(&tid, NULL, smb_netbios_name_service, NULL);
	if (rc != 0) {
		smb_netbios_shutdown();
		return (NULL);
	}

	smb_netbios_wait(NETBIOS_EVENT_NS_START);
	if (smb_netbios_error()) {
		smb_netbios_shutdown();
		return (NULL);
	}

	smb_netbios_name_config();

	rc = pthread_create(&tid, NULL, smb_netbios_datagram_service, NULL);
	if (rc != 0) {
		smb_netbios_shutdown();
		return (NULL);
	}

	smb_netbios_wait(NETBIOS_EVENT_DGM_START);
	if (smb_netbios_error()) {
		smb_netbios_shutdown();
		return (NULL);
	}

	rc = pthread_create(&tid, NULL, smb_browser_service, NULL);
	if (rc != 0) {
		smb_netbios_shutdown();
		return (NULL);
	}

	smb_netbios_event(NETBIOS_EVENT_TIMER_START);

	for (;;) {
		(void) sleep(1);
		ticks++;

		if (!smb_netbios_running())
			break;

		smb_netbios_datagram_tick();
		smb_netbios_name_tick();

		if ((ticks % 600) == 0) {
			smb_netbios_event(NETBIOS_EVENT_DUMP);
			smb_netbios_cache_clean();
		}
	}

	smb_netbios_event(NETBIOS_EVENT_TIMER_STOP);
	smb_netbios_shutdown();
	return (NULL);
}

static void
smb_netbios_shutdown(void)
{
	(void) pthread_join(nbtd.nbs_browser.s_tid, 0);
	(void) pthread_join(nbtd.nbs_dgm.s_tid, 0);
	(void) pthread_join(nbtd.nbs_ns.s_tid, 0);

	nbtd.nbs_browser.s_tid = 0;
	nbtd.nbs_dgm.s_tid = 0;
	nbtd.nbs_ns.s_tid = 0;

	smb_netbios_cache_fini();

	if (smb_netbios_error()) {
		smb_netbios_event(NETBIOS_EVENT_RESET);
		if (smb_netbios_start() != 0)
			syslog(LOG_ERR, "netbios: restart failed");
	}
}

int
smb_first_level_name_encode(struct name_entry *name,
				unsigned char *out, int max_out)
{
	return (netbios_first_level_name_encode(name->name, name->scope,
	    out, max_out));
}

int
smb_first_level_name_decode(unsigned char *in, struct name_entry *name)
{
	return (netbios_first_level_name_decode((char *)in, (char *)name->name,
	    (char *)name->scope));
}

/*
 * smb_encode_netbios_name
 *
 * Set up the name and scope fields in the destination name_entry structure.
 * The name is padded with spaces to 15 bytes. The suffix is copied into the
 * last byte, i.e. "netbiosname    <suffix>". The scope is copied and folded
 * to uppercase.
 */
void
smb_encode_netbios_name(unsigned char *name, char suffix, unsigned char *scope,
    struct name_entry *dest)
{
	smb_tonetbiosname((char *)name, (char *)dest->name, suffix);

	if (scope) {
		(void) strlcpy((char *)dest->scope, (const char *)scope,
		    sizeof (dest->scope));
	} else {
		(void) smb_config_getstr(SMB_CI_NBSCOPE, (char *)dest->scope,
		    sizeof (dest->scope));
	}

	(void) utf8_strupr((char *)dest->scope);
}

void
smb_init_name_struct(unsigned char *name, char suffix, unsigned char *scope,
    uint32_t ipaddr, unsigned short port, uint32_t attr,
    uint32_t addr_attr, struct name_entry *dest)
{
	bzero(dest, sizeof (struct name_entry));
	smb_encode_netbios_name(name, suffix, scope, dest);

	switch (smb_node_type) {
	case 'H':
		dest->attributes = attr | NAME_ATTR_OWNER_TYPE_HNODE;
		break;
	case 'M':
		dest->attributes = attr | NAME_ATTR_OWNER_TYPE_MNODE;
		break;
	case 'P':
		dest->attributes = attr | NAME_ATTR_OWNER_TYPE_PNODE;
		break;
	case 'B':
	default:
		dest->attributes = attr | NAME_ATTR_OWNER_TYPE_BNODE;
		break;
	}

	dest->addr_list.refresh_ttl = dest->addr_list.ttl =
	    TO_SECONDS(DEFAULT_TTL);

	dest->addr_list.sin.sin_family = AF_INET;
	dest->addr_list.sinlen = sizeof (dest->addr_list.sin);
	dest->addr_list.sin.sin_addr.s_addr = ipaddr;
	dest->addr_list.sin.sin_port = port;
	dest->addr_list.attributes = addr_attr;
	dest->addr_list.forw = dest->addr_list.back = &dest->addr_list;
}

void
smb_netbios_event(netbios_event_t event)
{
	static char *event_msg[] = {
		"startup",
		"shutdown",
		"restart",
		"name service started",
		"name service stopped",
		"datagram service started",
		"datagram service stopped",
		"browser service started",
		"browser service stopped",
		"timer service started",
		"timer service stopped",
		"error",
		"dump"
	};

	(void) mutex_lock(&nbtd.nbs_mtx);

	if (event == NETBIOS_EVENT_DUMP) {
		if (nbtd.nbs_last_event == NULL)
			nbtd.nbs_last_event = event_msg[event];
		smb_netbios_dump();
		(void) mutex_unlock(&nbtd.nbs_mtx);
		return;
	}

	nbtd.nbs_last_event = event_msg[event];
	syslog(LOG_DEBUG, "netbios: %s", nbtd.nbs_last_event);

	switch (nbtd.nbs_state) {
	case NETBIOS_STATE_INIT:
		if (event == NETBIOS_EVENT_START)
			nbtd.nbs_state = NETBIOS_STATE_RUNNING;
		break;

	case NETBIOS_STATE_RUNNING:
		switch (event) {
		case NETBIOS_EVENT_NS_START:
			nbtd.nbs_ns.s_tid = pthread_self();
			nbtd.nbs_ns.s_up = B_TRUE;
			break;
		case NETBIOS_EVENT_NS_STOP:
			nbtd.nbs_ns.s_up = B_FALSE;
			break;
		case NETBIOS_EVENT_DGM_START:
			nbtd.nbs_dgm.s_tid = pthread_self();
			nbtd.nbs_dgm.s_up = B_TRUE;
			break;
		case NETBIOS_EVENT_DGM_STOP:
			nbtd.nbs_dgm.s_up = B_FALSE;
			break;
		case NETBIOS_EVENT_BROWSER_START:
			nbtd.nbs_browser.s_tid = pthread_self();
			nbtd.nbs_browser.s_up = B_TRUE;
			break;
		case NETBIOS_EVENT_BROWSER_STOP:
			nbtd.nbs_browser.s_up = B_FALSE;
			break;
		case NETBIOS_EVENT_TIMER_START:
			nbtd.nbs_timer.s_tid = pthread_self();
			nbtd.nbs_timer.s_up = B_TRUE;
			break;
		case NETBIOS_EVENT_TIMER_STOP:
			nbtd.nbs_timer.s_up = B_FALSE;
			break;
		case NETBIOS_EVENT_STOP:
			nbtd.nbs_state = NETBIOS_STATE_CLOSING;
			break;
		case NETBIOS_EVENT_ERROR:
			nbtd.nbs_state = NETBIOS_STATE_ERROR;
			++nbtd.nbs_errors;
			break;
		default:
			break;
		}
		break;

	case NETBIOS_STATE_CLOSING:
	case NETBIOS_STATE_ERROR:
	default:
		switch (event) {
		case NETBIOS_EVENT_NS_STOP:
			nbtd.nbs_ns.s_up = B_FALSE;
			break;
		case NETBIOS_EVENT_DGM_STOP:
			nbtd.nbs_dgm.s_up = B_FALSE;
			break;
		case NETBIOS_EVENT_BROWSER_STOP:
			nbtd.nbs_browser.s_up = B_FALSE;
			break;
		case NETBIOS_EVENT_TIMER_STOP:
			nbtd.nbs_timer.s_up = B_FALSE;
			break;
		case NETBIOS_EVENT_STOP:
			nbtd.nbs_state = NETBIOS_STATE_CLOSING;
			break;
		case NETBIOS_EVENT_RESET:
			nbtd.nbs_state = NETBIOS_STATE_INIT;
			break;
		case NETBIOS_EVENT_ERROR:
			++nbtd.nbs_errors;
			break;
		default:
			break;
		}
		break;
	}

	smb_netbios_dump();
	(void) cond_broadcast(&nbtd.nbs_cv);
	(void) mutex_unlock(&nbtd.nbs_mtx);
}

void
smb_netbios_wait(netbios_event_t event)
{
	boolean_t *svc = NULL;
	boolean_t desired_state;

	(void) mutex_lock(&nbtd.nbs_mtx);

	switch (event) {
	case NETBIOS_EVENT_NS_START:
	case NETBIOS_EVENT_NS_STOP:
		svc = &nbtd.nbs_ns.s_up;
		desired_state =
		    (event == NETBIOS_EVENT_NS_START) ? B_TRUE : B_FALSE;
		break;
	case NETBIOS_EVENT_DGM_START:
	case NETBIOS_EVENT_DGM_STOP:
		svc = &nbtd.nbs_dgm.s_up;
		desired_state =
		    (event == NETBIOS_EVENT_DGM_START) ? B_TRUE : B_FALSE;
		break;
	case NETBIOS_EVENT_BROWSER_START:
	case NETBIOS_EVENT_BROWSER_STOP:
		svc = &nbtd.nbs_browser.s_up;
		desired_state =
		    (event == NETBIOS_EVENT_BROWSER_START) ? B_TRUE : B_FALSE;
		break;
	default:
		(void) mutex_unlock(&nbtd.nbs_mtx);
		return;
	}

	while (*svc != desired_state) {
		if (nbtd.nbs_state != NETBIOS_STATE_RUNNING)
			break;

		(void) cond_wait(&nbtd.nbs_cv, &nbtd.nbs_mtx);
	}

	(void) mutex_unlock(&nbtd.nbs_mtx);
}

void
smb_netbios_sleep(time_t seconds)
{
	timestruc_t reltimeout;

	(void) mutex_lock(&nbtd.nbs_mtx);

	if (nbtd.nbs_state == NETBIOS_STATE_RUNNING) {
		if (seconds == 0)
			seconds  = 1;
		reltimeout.tv_sec = seconds;
		reltimeout.tv_nsec = 0;

		(void) cond_reltimedwait(&nbtd.nbs_cv,
		    &nbtd.nbs_mtx, &reltimeout);
	}

	(void) mutex_unlock(&nbtd.nbs_mtx);
}

boolean_t
smb_netbios_running(void)
{
	boolean_t is_running;

	(void) mutex_lock(&nbtd.nbs_mtx);

	if (nbtd.nbs_state == NETBIOS_STATE_RUNNING)
		is_running = B_TRUE;
	else
		is_running = B_FALSE;

	(void) mutex_unlock(&nbtd.nbs_mtx);
	return (is_running);
}

boolean_t
smb_netbios_error(void)
{
	boolean_t error;

	(void) mutex_lock(&nbtd.nbs_mtx);

	if (nbtd.nbs_state == NETBIOS_STATE_ERROR)
		error = B_TRUE;
	else
		error = B_FALSE;

	(void) mutex_unlock(&nbtd.nbs_mtx);
	return (error);
}

/*
 * Write the service state to /var/run/smb/netbios.
 *
 * This is a private interface.  To update the file use:
 *	smb_netbios_event(NETBIOS_EVENT_DUMP);
 */
static void
smb_netbios_dump(void)
{
	static struct {
		netbios_state_t state;
		char		*text;
	} sm[] = {
		{ NETBIOS_STATE_INIT,		"init" },
		{ NETBIOS_STATE_RUNNING,	"running" },
		{ NETBIOS_STATE_CLOSING,	"closing" },
		{ NETBIOS_STATE_ERROR,		"error" }
	};

	char		fname[MAXPATHLEN];
	FILE		*fp;
	struct passwd	*pwd;
	struct group	*grp;
	uid_t		uid;
	gid_t		gid;
	char		*last_event = "none";
	int		i;

	(void) snprintf(fname, MAXPATHLEN, "%s/%s",
	    SMB_VARRUN_DIR, SMB_NETBIOS_DUMP_FILE);

	if ((fp = fopen(fname, "w")) == NULL)
		return;

	pwd = getpwnam("root");
	grp = getgrnam("sys");
	uid = (pwd == NULL) ? 0 : pwd->pw_uid;
	gid = (grp == NULL) ? 3 : grp->gr_gid;

	(void) lockf(fileno(fp), F_LOCK, 0);
	(void) fchmod(fileno(fp), 0600);
	(void) fchown(fileno(fp), uid, gid);

	if (nbtd.nbs_last_event)
		last_event = nbtd.nbs_last_event;

	for (i = 0; i < sizeof (sm) / sizeof (sm[0]); ++i) {
		if (nbtd.nbs_state == sm[i].state) {
			(void) fprintf(fp,
			    "State             %s  (event: %s, errors: %u)\n",
			    sm[i].text, last_event, nbtd.nbs_errors);
			break;
		}
	}

	(void) fprintf(fp, "Name Service      %-7s  (%u)\n",
	    nbtd.nbs_ns.s_up ? "up" : "down", nbtd.nbs_ns.s_tid);
	(void) fprintf(fp, "Datagram Service  %-7s  (%u)\n",
	    nbtd.nbs_dgm.s_up ? "up" : "down", nbtd.nbs_dgm.s_tid);
	(void) fprintf(fp, "Browser Service   %-7s  (%u)\n",
	    nbtd.nbs_browser.s_up ? "up" : "down", nbtd.nbs_browser.s_tid);
	(void) fprintf(fp, "Timer Service     %-7s  (%u)\n",
	    nbtd.nbs_timer.s_up ? "up" : "down", nbtd.nbs_timer.s_tid);

	smb_netbios_cache_dump(fp);

	(void) lockf(fileno(fp), F_ULOCK, 0);
	(void) fclose(fp);
}
