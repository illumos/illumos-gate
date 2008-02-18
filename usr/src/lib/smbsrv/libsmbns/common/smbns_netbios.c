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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Main startup code for SMB/NETBIOS and some utility routines
 * for the NETBIOS layer.
 */

#include <synch.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

#include <smbns_netbios.h>

netbios_status_t nb_status;

static pthread_t smb_nbns_thr; /* name service */
static pthread_t smb_nbds_thr; /* dgram service */
static pthread_t smb_nbts_thr; /* timer */
static pthread_t smb_nbbs_thr; /* browser */

static void *smb_netbios_timer(void *);

void
smb_netbios_chg_status(uint32_t status, int set)
{
	(void) mutex_lock(&nb_status.mtx);
	if (set)
		nb_status.state |= status;
	else
		nb_status.state &= ~status;
	(void) cond_broadcast(&nb_status.cv);
	(void) mutex_unlock(&nb_status.mtx);
}

void
smb_netbios_shutdown(void)
{
	smb_netbios_chg_status(NETBIOS_SHUTTING_DOWN, 1);

	(void) pthread_join(smb_nbts_thr, 0);
	(void) pthread_join(smb_nbbs_thr, 0);
	(void) pthread_join(smb_nbns_thr, 0);
	(void) pthread_join(smb_nbds_thr, 0);

	nb_status.state = NETBIOS_SHUT_DOWN;
}

int
smb_netbios_start(void)
{
	int rc;
	mutex_t *mp;
	cond_t *cvp;

	/* Startup Netbios named; port 137 */
	rc = pthread_create(&smb_nbns_thr, 0,
	    smb_netbios_name_service_daemon, 0);
	if (rc)
		return (-1);

	mp = &nb_status.mtx;
	cvp = &nb_status.cv;

	(void) mutex_lock(mp);
	while (!(nb_status.state & (NETBIOS_NAME_SVC_RUNNING |
	    NETBIOS_NAME_SVC_FAILED))) {
		(void) cond_wait(cvp, mp);
	}

	if (nb_status.state & NETBIOS_NAME_SVC_FAILED) {
		(void) mutex_unlock(mp);
		smb_netbios_shutdown();
		return (-1);
	}
	(void) mutex_unlock(mp);

	smb_netbios_name_config();

	/* Startup Netbios datagram service; port 138 */
	rc = pthread_create(&smb_nbds_thr, 0,
	    smb_netbios_datagram_service_daemon, 0);
	if (rc != 0) {
		smb_netbios_shutdown();
		return (-1);
	}

	(void) mutex_lock(mp);
	while (!(nb_status.state & (NETBIOS_DATAGRAM_SVC_RUNNING |
	    NETBIOS_DATAGRAM_SVC_FAILED))) {
		(void) cond_wait(cvp, mp);
	}

	if (nb_status.state & NETBIOS_DATAGRAM_SVC_FAILED) {
		(void) mutex_unlock(mp);
		smb_netbios_shutdown();
		return (-1);
	}
	(void) mutex_unlock(mp);

	/* Startup Netbios browser service */
	rc = pthread_create(&smb_nbbs_thr, 0, smb_browser_daemon, 0);
	if (rc) {
		smb_netbios_shutdown();
		return (-1);
	}

	/* Startup Our internal, 1 second resolution, timer */
	rc = pthread_create(&smb_nbts_thr, 0, smb_netbios_timer, 0);
	if (rc != 0) {
		smb_netbios_shutdown();
		return (-1);
	}

	(void) mutex_lock(mp);
	while (!(nb_status.state & (NETBIOS_TIMER_RUNNING |
	    NETBIOS_TIMER_FAILED))) {
		(void) cond_wait(cvp, mp);
	}

	if (nb_status.state & NETBIOS_TIMER_FAILED) {
		(void) mutex_unlock(mp);
		smb_netbios_shutdown();
		return (-1);
	}
	(void) mutex_unlock(mp);

	return (0);
}

/*ARGSUSED*/
static void *
smb_netbios_timer(void *arg)
{
	static unsigned int ticks = 0;

	smb_netbios_chg_status(NETBIOS_TIMER_RUNNING, 1);

	while ((nb_status.state & NETBIOS_SHUTTING_DOWN) == 0) {
		(void) sleep(1);
		ticks++;

		if ((nb_status.state & NETBIOS_DATAGRAM_SVC_RUNNING) == 0)
			break;

		if ((nb_status.state & NETBIOS_NAME_SVC_RUNNING) == 0)
			break;

		smb_netbios_datagram_tick();
		smb_netbios_name_tick();

		/* every 10 minutes */
		if ((ticks % 600) == 0)
			smb_netbios_cache_clean();
	}

	nb_status.state &= ~NETBIOS_TIMER_RUNNING;
	if ((nb_status.state & NETBIOS_SHUTTING_DOWN) == 0) {
		/* either name or datagram service has failed */
		smb_netbios_shutdown();
	}

	return (0);
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
