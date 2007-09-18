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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <libintl.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <libdlaggr.h>
#include <libdladm_impl.h>

/*
 * Link Aggregation Administration Library.
 *
 * This library is used by administration tools such as dladm(1M) to
 * configure link aggregations.
 *
 * Link aggregation configuration information is saved in a text
 * file of the following format:
 *
 * <db-file>	::= <groups>*
 * <group>	::= <key> <sep> <policy> <sep> <nports> <sep> <ports> <sep>
 *		      <mac> <sep> <lacp-mode> <sep> <lacp-timer>
 * <sep>	::= ' ' | '\t'
 * <key>	::= <number>
 * <nports>	::= <number>
 * <ports>	::= <port> <m-port>*
 * <m-port>	::= ',' <port>
 * <port>	::= <devname>
 * <devname>	::= <string>
 * <port-num>	::= <number>
 * <policy>	::= <pol-level> <m-pol>*
 * <m-pol>	::= ',' <pol-level>
 * <pol-level>	::= 'L2' | 'L3' | 'L4'
 * <mac>	::= 'auto' | <mac-addr>
 * <mac-addr>	::= <hex> ':' <hex> ':' <hex> ':' <hex> ':' <hex> ':' <hex>
 * <lacp-mode>	::= 'off' | 'active' | 'passive'
 * <lacp-timer>	::= 'short' | 'long'
 */

#define	DLADM_AGGR_DEV		"/devices/pseudo/aggr@0:" AGGR_DEVNAME_CTL
#define	DLADM_AGGR_DB		"/etc/dladm/aggregation.conf"
#define	DLADM_AGGR_DB_TMP	"/etc/dladm/aggregation.conf.new"
#define	DLADM_AGGR_DB_LOCK	"/tmp/aggregation.conf.lock"

#define	DLADM_AGGR_DB_PERMS	S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH
#define	DLADM_AGGR_DB_OWNER	15	/* "dladm" UID */
#define	DLADM_AGGR_DB_GROUP	3	/* "sys" GID */

/*
 * The largest configurable aggregation key.  Because by default the key is
 * used as the DLPI device PPA and default VLAN PPA's are calculated as
 * ((1000 * vid) + PPA), the largest key can't be > 999.
 */
#define	DLADM_AGGR_MAX_KEY	999

#define	BLANK_LINE(s)	((s[0] == '\0') || (s[0] == '#') || (s[0] == '\n'))

/* Limits on buffer size for LAIOC_INFO request */
#define	MIN_INFO_SIZE (4*1024)
#define	MAX_INFO_SIZE (128*1024)

#define	MAXPATHLEN	1024

static uchar_t	zero_mac[] = {0, 0, 0, 0, 0, 0};

/* configuration database entry */
typedef struct dladm_aggr_grp_attr_db {
	uint32_t	lt_key;
	uint32_t	lt_policy;
	uint32_t	lt_nports;
	dladm_aggr_port_attr_db_t *lt_ports;
	boolean_t	lt_mac_fixed;
	uchar_t		lt_mac[ETHERADDRL];
	aggr_lacp_mode_t lt_lacp_mode;
	aggr_lacp_timer_t lt_lacp_timer;
} dladm_aggr_grp_attr_db_t;

typedef struct dladm_aggr_up {
	uint32_t	lu_key;
	boolean_t	lu_found;
	int		lu_fd;
} dladm_aggr_up_t;

typedef struct dladm_aggr_down {
	uint32_t	ld_key;
	boolean_t	ld_found;
} dladm_aggr_down_t;

typedef struct dladm_aggr_modify_attr {
	uint32_t	ld_policy;
	boolean_t	ld_mac_fixed;
	uchar_t		ld_mac[ETHERADDRL];
	aggr_lacp_mode_t ld_lacp_mode;
	aggr_lacp_timer_t ld_lacp_timer;
} dladm_aggr_modify_attr_t;

typedef struct policy_s {
	char		*pol_name;
	uint32_t	policy;
} policy_t;

static policy_t policies[] = {
	{"L2",		AGGR_POLICY_L2},
	{"L3",		AGGR_POLICY_L3},
	{"L4",		AGGR_POLICY_L4}};

#define	NPOLICIES	(sizeof (policies) / sizeof (policy_t))

typedef struct dladm_aggr_lacpmode_s {
	char		*mode_str;
	aggr_lacp_mode_t mode_id;
} dladm_aggr_lacpmode_t;

static dladm_aggr_lacpmode_t lacp_modes[] = {
	{"off", AGGR_LACP_OFF},
	{"active", AGGR_LACP_ACTIVE},
	{"passive", AGGR_LACP_PASSIVE}};

#define	NLACP_MODES	(sizeof (lacp_modes) / sizeof (dladm_aggr_lacpmode_t))

typedef struct dladm_aggr_lacptimer_s {
	char		*lt_str;
	aggr_lacp_timer_t lt_id;
} dladm_aggr_lacptimer_t;

static dladm_aggr_lacptimer_t lacp_timers[] = {
	{"short", AGGR_LACP_TIMER_SHORT},
	{"long", AGGR_LACP_TIMER_LONG}};

#define	NLACP_TIMERS	(sizeof (lacp_timers) / sizeof (dladm_aggr_lacptimer_t))

typedef struct dladm_aggr_port_state {
	char			*state_str;
	aggr_port_state_t	state_id;
} dladm_aggr_port_state_t;

static dladm_aggr_port_state_t port_states[] = {
	{"standby", AGGR_PORT_STATE_STANDBY },
	{"attached", AGGR_PORT_STATE_ATTACHED }
};

#define	NPORT_STATES	\
	(sizeof (port_states) / sizeof (dladm_aggr_port_state_t))

typedef struct delete_db_state {
	uint32_t	ds_key;
	boolean_t	ds_found;
} delete_db_state_t;

typedef struct modify_db_state {
	uint32_t		us_key;
	uint32_t		us_mask;
	dladm_aggr_modify_attr_t *us_attr_new;
	dladm_aggr_modify_attr_t *us_attr_old;
	boolean_t		us_found;
} modify_db_state_t;

typedef struct add_db_state {
	dladm_aggr_grp_attr_db_t *as_attr;
	boolean_t	as_found;
} add_db_state_t;

static int i_dladm_aggr_fput_grp(FILE *, dladm_aggr_grp_attr_db_t *);

/*
 * Open and lock the aggregation configuration file lock. The lock is
 * acquired as a reader (F_RDLCK) or writer (F_WRLCK).
 */
static int
i_dladm_aggr_lock_db(short type)
{
	int lock_fd;
	struct flock lock;
	int errno_save;

	if ((lock_fd = open(DLADM_AGGR_DB_LOCK, O_RDWR | O_CREAT | O_TRUNC,
	    DLADM_AGGR_DB_PERMS)) < 0)
		return (-1);

	lock.l_type = type;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(lock_fd, F_SETLKW, &lock) < 0) {
		errno_save = errno;
		(void) close(lock_fd);
		(void) unlink(DLADM_AGGR_DB_LOCK);
		errno = errno_save;
		return (-1);
	}
	return (lock_fd);
}

/*
 * Unlock and close the specified file.
 */
static void
i_dladm_aggr_unlock_db(int fd)
{
	struct flock lock;

	if (fd < 0)
		return;

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	(void) fcntl(fd, F_SETLKW, &lock);
	(void) close(fd);
	(void) unlink(DLADM_AGGR_DB_LOCK);
}

/*
 * Walk through the groups defined on the system and for each group <grp>,
 * invoke <fn>(<arg>, <grp>);
 * Terminate the walk if at any time <fn> returns non-NULL value
 */
int
dladm_aggr_walk(int (*fn)(void *, dladm_aggr_grp_attr_t *), void *arg)
{
	laioc_info_t *ioc;
	laioc_info_group_t *grp;
	laioc_info_port_t *port;
	dladm_aggr_grp_attr_t attr;
	int rc, i, j, bufsize, fd;
	char *where;

	if ((fd = open(DLADM_AGGR_DEV, O_RDWR)) == -1)
		return (-1);

	bufsize = MIN_INFO_SIZE;
	ioc = (laioc_info_t *)calloc(1, bufsize);
	if (ioc == NULL) {
		(void) close(fd);
		errno = ENOMEM;
		return (-1);
	}

tryagain:
	rc = i_dladm_ioctl(fd, LAIOC_INFO, ioc, bufsize);

	if (rc != 0) {
		if (errno == ENOSPC) {
			/*
			 * The LAIOC_INFO call failed due to a short
			 * buffer. Reallocate the buffer and try again.
			 */
			bufsize *= 2;
			if (bufsize <= MAX_INFO_SIZE) {
				ioc = (laioc_info_t *)realloc(ioc, bufsize);
				if (ioc != NULL) {
					bzero(ioc, sizeof (bufsize));
					goto tryagain;
				}
			}
		}
		goto bail;
	}

	/*
	 * Go through each group returned by the aggregation driver.
	 */
	where = (char *)(ioc + 1);
	for (i = 0; i < ioc->li_ngroups; i++) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		grp = (laioc_info_group_t *)where;

		attr.lg_key = grp->lg_key;
		attr.lg_nports = grp->lg_nports;
		attr.lg_policy = grp->lg_policy;
		attr.lg_lacp_mode = grp->lg_lacp_mode;
		attr.lg_lacp_timer = grp->lg_lacp_timer;

		bcopy(grp->lg_mac, attr.lg_mac, ETHERADDRL);
		attr.lg_mac_fixed = grp->lg_mac_fixed;

		attr.lg_ports = malloc(grp->lg_nports *
		    sizeof (dladm_aggr_port_attr_t));
		if (attr.lg_ports == NULL) {
			errno = ENOMEM;
			goto bail;
		}

		where = (char *)(grp + 1);

		/*
		 * Go through each port that is part of the group.
		 */
		for (j = 0; j < grp->lg_nports; j++) {
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			port = (laioc_info_port_t *)where;

			bcopy(port->lp_devname, attr.lg_ports[j].lp_devname,
			    MAXNAMELEN + 1);
			bcopy(port->lp_mac, attr.lg_ports[j].lp_mac,
			    ETHERADDRL);
			attr.lg_ports[j].lp_state = port->lp_state;
			attr.lg_ports[j].lp_lacp_state = port->lp_lacp_state;

			where = (char *)(port + 1);
		}

		rc = fn(arg, &attr);
		free(attr.lg_ports);
		if (rc != 0)
			goto bail;
	}

bail:
	free(ioc);
	(void) close(fd);
	return (rc);
}

/*
 * Parse one line of the link aggregation DB, and return the corresponding
 * group. Memory for the ports associated with the aggregation may be
 * allocated. It is the responsibility of the caller to free the lt_ports
 * aggregation group attribute.
 *
 * Returns -1 on parsing failure, or 0 on success.
 */
static int
i_dladm_aggr_parse_db(char *line, dladm_aggr_grp_attr_db_t *attr)
{
	char	*token;
	int	i;
	int	value;
	char	*endp = NULL;
	char	*lasts = NULL;

	bzero(attr, sizeof (*attr));

	/* key */
	if ((token = strtok_r(line, " \t", &lasts)) == NULL)
		goto failed;

	errno = 0;
	value = (int)strtol(token, &endp, 10);
	if (errno != 0 || *endp != '\0')
		goto failed;

	attr->lt_key = value;

	/* policy */
	if ((token = strtok_r(NULL, " \t", &lasts)) == NULL ||
	    !dladm_aggr_str2policy(token, &attr->lt_policy))
		goto failed;

	/* number of ports */
	if ((token = strtok_r(NULL, " \t", &lasts)) == NULL)
		return (-1);

	errno = 0;
	value = (int)strtol(token, &endp, 10);
	if (errno != 0 || *endp != '\0')
		goto failed;

	attr->lt_nports = value;

	/* ports */
	if ((attr->lt_ports = malloc(attr->lt_nports *
	    sizeof (dladm_aggr_port_attr_db_t))) == NULL)
		goto failed;

	for (i = 0; i < attr->lt_nports; i++) {
		char *where, *devname;

		/* port */
		if ((token = strtok_r(NULL, ", \t\n", &lasts)) == NULL)
			goto failed;

		/*
		 * device name: In a previous version of this file, a port
		 * number could be specified using <devname>/<portnum>.
		 * This syntax is unecessary and obsolete.
		 */
		if ((devname = strtok_r(token, "/", &where)) == NULL)
			goto failed;
		if (strlcpy(attr->lt_ports[i].lp_devname, devname,
		    MAXNAMELEN) >= MAXNAMELEN)
			goto failed;
	}

	/* unicast MAC address */
	if ((token = strtok_r(NULL, " \t\n", &lasts)) == NULL ||
	    !dladm_aggr_str2macaddr(token, &attr->lt_mac_fixed,
	    attr->lt_mac))
		goto failed;

	/* LACP mode */
	if ((token = strtok_r(NULL, " \t\n", &lasts)) == NULL ||
	    !dladm_aggr_str2lacpmode(token, &attr->lt_lacp_mode))
		attr->lt_lacp_mode = AGGR_LACP_OFF;

	/* LACP timer */
	if ((token = strtok_r(NULL, " \t\n", &lasts)) == NULL ||
	    !dladm_aggr_str2lacptimer(token, &attr->lt_lacp_timer))
		attr->lt_lacp_timer = AGGR_LACP_TIMER_SHORT;

	return (0);

failed:
	free(attr->lt_ports);
	attr->lt_ports = NULL;
	return (-1);
}

/*
 * Walk through the groups defined in the DB and for each group <grp>,
 * invoke <fn>(<arg>, <grp>);
 */
static dladm_status_t
i_dladm_aggr_walk_db(dladm_status_t (*fn)(void *, dladm_aggr_grp_attr_db_t *),
    void *arg, const char *root)
{
	FILE *fp;
	char line[MAXLINELEN];
	dladm_aggr_grp_attr_db_t attr;
	char *db_file;
	char db_file_buf[MAXPATHLEN];
	int lock_fd;
	dladm_status_t status = DLADM_STATUS_OK;

	if (root == NULL) {
		db_file = DLADM_AGGR_DB;
	} else {
		(void) snprintf(db_file_buf, MAXPATHLEN, "%s%s", root,
		    DLADM_AGGR_DB);
		db_file = db_file_buf;
	}

	lock_fd = i_dladm_aggr_lock_db(F_RDLCK);

	if ((fp = fopen(db_file, "r")) == NULL) {
		status = dladm_errno2status(errno);
		i_dladm_aggr_unlock_db(lock_fd);
		return (status);
	}

	bzero(&attr, sizeof (attr));

	while (fgets(line, MAXLINELEN, fp) != NULL) {
		/* skip comments */
		if (BLANK_LINE(line))
			continue;

		if (i_dladm_aggr_parse_db(line, &attr) != 0) {
			status = DLADM_STATUS_REPOSITORYINVAL;
			goto done;
		}

		if ((status = fn(arg, &attr)) != DLADM_STATUS_OK)
			goto done;

		free(attr.lt_ports);
		attr.lt_ports = NULL;
	}

done:
	free(attr.lt_ports);
	(void) fclose(fp);
	i_dladm_aggr_unlock_db(lock_fd);
	return (status);
}

/*
 * Send an add or remove command to the link aggregation driver.
 */
static dladm_status_t
i_dladm_aggr_add_rem_sys(dladm_aggr_grp_attr_db_t *attr, int cmd)
{
	int i, rc, fd, len;
	laioc_add_rem_t *iocp;
	laioc_port_t *ports;
	dladm_status_t status = DLADM_STATUS_OK;

	len = sizeof (*iocp) + attr->lt_nports * sizeof (laioc_port_t);
	iocp = malloc(len);
	if (iocp == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	iocp->la_key = attr->lt_key;
	iocp->la_nports = attr->lt_nports;
	ports = (laioc_port_t *)(iocp + 1);

	for (i = 0; i < attr->lt_nports; i++) {
		if (strlcpy(ports[i].lp_devname,
		    attr->lt_ports[i].lp_devname,
		    MAXNAMELEN) >= MAXNAMELEN) {
			status = DLADM_STATUS_BADARG;
			goto done;
		}
	}

	if ((fd = open(DLADM_AGGR_DEV, O_RDWR)) < 0) {
		status = dladm_errno2status(errno);
		goto done;
	}

	rc = i_dladm_ioctl(fd, cmd, iocp, len);
	if (rc < 0) {
		if (errno == EINVAL)
			status = DLADM_STATUS_LINKINVAL;
		else
			status = dladm_errno2status(errno);
	}

	(void) close(fd);

done:
	free(iocp);
	return (status);
}

/*
 * Send a modify command to the link aggregation driver.
 */
static dladm_status_t
i_dladm_aggr_modify_sys(uint32_t key, uint32_t mask,
    dladm_aggr_modify_attr_t *attr)
{
	int rc, fd;
	laioc_modify_t ioc;
	dladm_status_t status = DLADM_STATUS_OK;

	ioc.lu_key = key;

	ioc.lu_modify_mask = 0;
	if (mask & DLADM_AGGR_MODIFY_POLICY)
		ioc.lu_modify_mask |= LAIOC_MODIFY_POLICY;
	if (mask & DLADM_AGGR_MODIFY_MAC)
		ioc.lu_modify_mask |= LAIOC_MODIFY_MAC;
	if (mask & DLADM_AGGR_MODIFY_LACP_MODE)
		ioc.lu_modify_mask |= LAIOC_MODIFY_LACP_MODE;
	if (mask & DLADM_AGGR_MODIFY_LACP_TIMER)
		ioc.lu_modify_mask |= LAIOC_MODIFY_LACP_TIMER;

	ioc.lu_policy = attr->ld_policy;
	ioc.lu_mac_fixed = attr->ld_mac_fixed;
	bcopy(attr->ld_mac, ioc.lu_mac, ETHERADDRL);
	ioc.lu_lacp_mode = attr->ld_lacp_mode;
	ioc.lu_lacp_timer = attr->ld_lacp_timer;

	if ((fd = open(DLADM_AGGR_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	rc = i_dladm_ioctl(fd, LAIOC_MODIFY, &ioc, sizeof (ioc));
	if (rc < 0) {
		if (errno == EINVAL)
			status = DLADM_STATUS_MACADDRINVAL;
		else
			status = dladm_errno2status(errno);
	}

	(void) close(fd);
	return (status);
}

/*
 * Send a create command to the link aggregation driver.
 */
static dladm_status_t
i_dladm_aggr_create_sys(int fd, dladm_aggr_grp_attr_db_t *attr)
{
	int i, rc, len;
	laioc_create_t *iocp;
	laioc_port_t *ports;
	dladm_status_t status = DLADM_STATUS_OK;

	len = sizeof (*iocp) + attr->lt_nports * sizeof (laioc_port_t);
	iocp = malloc(len);
	if (iocp == NULL)
		return (DLADM_STATUS_NOMEM);

	iocp->lc_key = attr->lt_key;
	iocp->lc_nports = attr->lt_nports;
	iocp->lc_policy = attr->lt_policy;
	iocp->lc_lacp_mode = attr->lt_lacp_mode;
	iocp->lc_lacp_timer = attr->lt_lacp_timer;

	ports = (laioc_port_t *)(iocp + 1);

	for (i = 0; i < attr->lt_nports; i++) {
		if (strlcpy(ports[i].lp_devname,
		    attr->lt_ports[i].lp_devname,
		    MAXNAMELEN) >= MAXNAMELEN) {
			free(iocp);
			return (DLADM_STATUS_BADARG);
		}
	}

	if (attr->lt_mac_fixed &&
	    ((bcmp(zero_mac, attr->lt_mac, ETHERADDRL) == 0) ||
	    (attr->lt_mac[0] & 0x01))) {
		free(iocp);
		return (DLADM_STATUS_MACADDRINVAL);
	}

	bcopy(attr->lt_mac, iocp->lc_mac, ETHERADDRL);
	iocp->lc_mac_fixed = attr->lt_mac_fixed;

	rc = i_dladm_ioctl(fd, LAIOC_CREATE, iocp, len);
	if (rc < 0)
		status = DLADM_STATUS_LINKINVAL;

	free(iocp);
	return (status);
}

/*
 * Invoked to bring up a link aggregation group.
 */
static dladm_status_t
i_dladm_aggr_up(void *arg, dladm_aggr_grp_attr_db_t *attr)
{
	dladm_aggr_up_t	*up = (dladm_aggr_up_t *)arg;
	dladm_status_t	status;

	if (up->lu_key != 0 && up->lu_key != attr->lt_key)
		return (DLADM_STATUS_OK);

	up->lu_found = B_TRUE;

	status = i_dladm_aggr_create_sys(up->lu_fd, attr);
	if (status != DLADM_STATUS_OK && up->lu_key != 0)
		return (status);

	return (DLADM_STATUS_OK);
}

/*
 * Bring up a link aggregation group or all of them if the key is zero.
 * If key is 0, walk may terminate early if any of the links fail
 */
dladm_status_t
dladm_aggr_up(uint32_t key, const char *root)
{
	dladm_aggr_up_t up;
	dladm_status_t status;

	if ((up.lu_fd = open(DLADM_AGGR_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	up.lu_key = key;
	up.lu_found = B_FALSE;

	status = i_dladm_aggr_walk_db(i_dladm_aggr_up, &up, root);
	if (status != DLADM_STATUS_OK) {
		(void) close(up.lu_fd);
		return (status);
	}
	(void) close(up.lu_fd);

	/*
	 * only return error if user specified key and key was
	 * not found
	 */
	if (!up.lu_found && key != 0)
		return (DLADM_STATUS_NOTFOUND);

	return (DLADM_STATUS_OK);
}
/*
 * Send a delete command to the link aggregation driver.
 */
static int
i_dladm_aggr_delete_sys(int fd, dladm_aggr_grp_attr_t *attr)
{
	laioc_delete_t ioc;

	ioc.ld_key = attr->lg_key;

	return (i_dladm_ioctl(fd, LAIOC_DELETE, &ioc, sizeof (ioc)));
}

/*
 * Invoked to bring down a link aggregation group.
 */
static int
i_dladm_aggr_down(void *arg, dladm_aggr_grp_attr_t *attr)
{
	dladm_aggr_down_t *down = (dladm_aggr_down_t *)arg;
	int fd, errno_save;

	if (down->ld_key != 0 && down->ld_key != attr->lg_key)
		return (0);

	down->ld_found = B_TRUE;

	if ((fd = open(DLADM_AGGR_DEV, O_RDWR)) < 0)
		return (-1);

	if (i_dladm_aggr_delete_sys(fd, attr) < 0 && down->ld_key != 0) {
		errno_save = errno;
		(void) close(fd);
		errno = errno_save;
		return (-1);
	}

	(void) close(fd);
	return (0);
}

/*
 * Bring down a link aggregation group or all of them if the key is zero.
 * If key is 0, walk may terminate early if any of the links fail
 */
dladm_status_t
dladm_aggr_down(uint32_t key)
{
	dladm_aggr_down_t down;

	down.ld_key = key;
	down.ld_found = B_FALSE;

	if (dladm_aggr_walk(i_dladm_aggr_down, &down) < 0)
		return (dladm_errno2status(errno));

	/*
	 * only return error if user specified key and key was
	 * not found
	 */
	if (!down.ld_found && key != 0)
		return (DLADM_STATUS_NOTFOUND);

	return (DLADM_STATUS_OK);
}

/*
 * For each group <grp> found in the DB, invokes <fn>(<grp>, <arg>).
 *
 * The following values can be returned by <fn>():
 *
 * -1: an error occured. This will cause the walk to be terminated,
 *     and the original DB file to be preserved.
 *
 *  0: success and write. The walker will write the contents of
 *     the attribute passed as argument to <fn>(), and continue walking
 *     the entries found in the DB.
 *
 *  1: skip. The walker should not write the contents of the current
 *     group attributes to the new DB, but should continue walking
 *     the entries found in the DB.
 */
static dladm_status_t
i_dladm_aggr_walk_rw_db(int (*fn)(void *, dladm_aggr_grp_attr_db_t *),
    void *arg, const char *root)
{
	FILE *fp, *nfp;
	int nfd, fn_rc, lock_fd;
	char line[MAXLINELEN];
	dladm_aggr_grp_attr_db_t attr;
	char *db_file, *tmp_db_file;
	char db_file_buf[MAXPATHLEN];
	char tmp_db_file_buf[MAXPATHLEN];
	dladm_status_t status;

	if (root == NULL) {
		db_file = DLADM_AGGR_DB;
		tmp_db_file = DLADM_AGGR_DB_TMP;
	} else {
		(void) snprintf(db_file_buf, MAXPATHLEN, "%s%s", root,
		    DLADM_AGGR_DB);
		(void) snprintf(tmp_db_file_buf, MAXPATHLEN, "%s%s", root,
		    DLADM_AGGR_DB_TMP);
		db_file = db_file_buf;
		tmp_db_file = tmp_db_file_buf;
	}

	if ((lock_fd = i_dladm_aggr_lock_db(F_WRLCK)) < 0)
		return (dladm_errno2status(errno));

	if ((fp = fopen(db_file, "r")) == NULL) {
		status = dladm_errno2status(errno);
		i_dladm_aggr_unlock_db(lock_fd);
		return (status);
	}

	if ((nfd = open(tmp_db_file, O_WRONLY|O_CREAT|O_TRUNC,
	    DLADM_AGGR_DB_PERMS)) == -1) {
		status = dladm_errno2status(errno);
		(void) fclose(fp);
		i_dladm_aggr_unlock_db(lock_fd);
		return (status);
	}

	if ((nfp = fdopen(nfd, "w")) == NULL) {
		status = dladm_errno2status(errno);
		(void) close(nfd);
		(void) fclose(fp);
		(void) unlink(tmp_db_file);
		i_dladm_aggr_unlock_db(lock_fd);
		return (status);
	}

	attr.lt_ports = NULL;

	while (fgets(line, MAXLINELEN, fp) != NULL) {

		/* skip comments */
		if (BLANK_LINE(line)) {
			if (fputs(line, nfp) == EOF) {
				status = dladm_errno2status(errno);
				goto failed;
			}
			continue;
		}

		if (i_dladm_aggr_parse_db(line, &attr) != 0) {
			status = DLADM_STATUS_REPOSITORYINVAL;
			goto failed;
		}

		fn_rc = fn(arg, &attr);

		switch (fn_rc) {
		case -1:
			/* failure, stop walking */
			status = dladm_errno2status(errno);
			goto failed;
		case 0:
			/*
			 * Success, write group attributes, which could
			 * have been modified by fn().
			 */
			if (i_dladm_aggr_fput_grp(nfp, &attr) != 0) {
				status = dladm_errno2status(errno);
				goto failed;
			}
			break;
		case 1:
			/* skip current group */
			break;
		}

		free(attr.lt_ports);
		attr.lt_ports = NULL;
	}

	if (getuid() == 0 || geteuid() == 0) {
		if (fchmod(nfd, DLADM_AGGR_DB_PERMS) == -1) {
			status = dladm_errno2status(errno);
			goto failed;
		}

		if (fchown(nfd, DLADM_AGGR_DB_OWNER,
		    DLADM_AGGR_DB_GROUP) == -1) {
			status = dladm_errno2status(errno);
			goto failed;
		}
	}

	if (fflush(nfp) == EOF) {
		status = dladm_errno2status(errno);
		goto failed;
	}

	(void) fclose(fp);
	(void) fclose(nfp);

	if (rename(tmp_db_file, db_file) == -1) {
		status = dladm_errno2status(errno);
		(void) unlink(tmp_db_file);
		i_dladm_aggr_unlock_db(lock_fd);
		return (status);
	}

	i_dladm_aggr_unlock_db(lock_fd);
	return (DLADM_STATUS_OK);

failed:
	free(attr.lt_ports);
	(void) fclose(fp);
	(void) fclose(nfp);
	(void) unlink(tmp_db_file);
	i_dladm_aggr_unlock_db(lock_fd);

	return (status);
}

/*
 * Remove an entry from the DB.
 */
static int
i_dladm_aggr_del_db_fn(void *arg, dladm_aggr_grp_attr_db_t *grp)
{
	delete_db_state_t *state = arg;

	if (grp->lt_key != state->ds_key)
		return (0);

	state->ds_found = B_TRUE;

	/* don't save matching group */
	return (1);
}

static dladm_status_t
i_dladm_aggr_del_db(dladm_aggr_grp_attr_db_t *attr, const char *root)
{
	delete_db_state_t state;
	dladm_status_t status;

	state.ds_key = attr->lt_key;
	state.ds_found = B_FALSE;

	status = i_dladm_aggr_walk_rw_db(i_dladm_aggr_del_db_fn, &state, root);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (!state.ds_found)
		return (DLADM_STATUS_NOTFOUND);

	return (DLADM_STATUS_OK);
}

/*
 * Modify the properties of an existing group in the DB.
 */
static int
i_dladm_aggr_modify_db_fn(void *arg, dladm_aggr_grp_attr_db_t *grp)
{
	modify_db_state_t *state = arg;
	dladm_aggr_modify_attr_t *new_attr = state->us_attr_new;
	dladm_aggr_modify_attr_t *old_attr = state->us_attr_old;

	if (grp->lt_key != state->us_key)
		return (0);

	state->us_found = B_TRUE;

	if (state->us_mask & DLADM_AGGR_MODIFY_POLICY) {
		if (old_attr != NULL)
			old_attr->ld_policy = grp->lt_policy;
		grp->lt_policy = new_attr->ld_policy;
	}

	if (state->us_mask & DLADM_AGGR_MODIFY_MAC) {
		if (old_attr != NULL) {
			old_attr->ld_mac_fixed = grp->lt_mac_fixed;
			bcopy(grp->lt_mac, old_attr->ld_mac, ETHERADDRL);
		}
		grp->lt_mac_fixed = new_attr->ld_mac_fixed;
		bcopy(new_attr->ld_mac, grp->lt_mac, ETHERADDRL);
	}

	if (state->us_mask & DLADM_AGGR_MODIFY_LACP_MODE) {
		if (old_attr != NULL)
			old_attr->ld_lacp_mode = grp->lt_lacp_mode;
		grp->lt_lacp_mode = new_attr->ld_lacp_mode;
	}

	if (state->us_mask & DLADM_AGGR_MODIFY_LACP_TIMER) {
		if (old_attr != NULL)
			old_attr->ld_lacp_timer = grp->lt_lacp_timer;
		grp->lt_lacp_timer = new_attr->ld_lacp_timer;
	}

	/* save modified group */
	return (0);
}

static dladm_status_t
i_dladm_aggr_modify_db(uint32_t key, uint32_t mask,
    dladm_aggr_modify_attr_t *new, dladm_aggr_modify_attr_t *old,
    const char *root)
{
	modify_db_state_t state;
	dladm_status_t status;

	state.us_key = key;
	state.us_mask = mask;
	state.us_attr_new = new;
	state.us_attr_old = old;
	state.us_found = B_FALSE;

	if ((status = i_dladm_aggr_walk_rw_db(i_dladm_aggr_modify_db_fn,
	    &state, root)) != DLADM_STATUS_OK) {
		return (status);
	}

	if (!state.us_found)
		return (DLADM_STATUS_NOTFOUND);

	return (DLADM_STATUS_OK);
}

/*
 * Add ports to an existing group in the DB.
 */
static int
i_dladm_aggr_add_db_fn(void *arg, dladm_aggr_grp_attr_db_t *grp)
{
	add_db_state_t *state = arg;
	dladm_aggr_grp_attr_db_t *attr = state->as_attr;
	void *ports;
	int i, j;

	if (grp->lt_key != attr->lt_key)
		return (0);

	state->as_found = B_TRUE;

	/* are any of the ports to be added already members of the group? */
	for (i = 0; i < grp->lt_nports; i++) {
		for (j = 0; j < attr->lt_nports; j++) {
			if (strcmp(grp->lt_ports[i].lp_devname,
			    attr->lt_ports[j].lp_devname) == 0) {
				errno = EEXIST;
				return (-1);
			}
		}
	}

	/* add groups specified by attr to grp */
	ports = realloc(grp->lt_ports, (grp->lt_nports +
	    attr->lt_nports) * sizeof (dladm_aggr_port_attr_db_t));
	if (ports == NULL)
		return (-1);
	grp->lt_ports = ports;

	for (i = 0; i < attr->lt_nports; i++) {
		if (strlcpy(grp->lt_ports[grp->lt_nports + i].lp_devname,
		    attr->lt_ports[i].lp_devname, MAXNAMELEN + 1) >=
		    MAXNAMELEN + 1)
			return (-1);
	}

	grp->lt_nports += attr->lt_nports;

	/* save modified group */
	return (0);
}

static dladm_status_t
i_dladm_aggr_add_db(dladm_aggr_grp_attr_db_t *attr, const char *root)
{
	add_db_state_t state;
	dladm_status_t status;

	state.as_attr = attr;
	state.as_found = B_FALSE;

	status = i_dladm_aggr_walk_rw_db(i_dladm_aggr_add_db_fn, &state, root);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (!state.as_found)
		return (DLADM_STATUS_NOTFOUND);

	return (DLADM_STATUS_OK);
}

/*
 * Remove ports from an existing group in the DB.
 */

typedef struct remove_db_state {
	dladm_aggr_grp_attr_db_t *rs_attr;
	boolean_t	rs_found;
} remove_db_state_t;

static int
i_dladm_aggr_remove_db_fn(void *arg, dladm_aggr_grp_attr_db_t *grp)
{
	remove_db_state_t *state = (remove_db_state_t *)arg;
	dladm_aggr_grp_attr_db_t *attr = state->rs_attr;
	int i, j, k, nremoved;
	boolean_t match;

	if (grp->lt_key != attr->lt_key)
		return (0);

	state->rs_found = B_TRUE;

	/* remove the ports specified by attr from the group */
	nremoved = 0;
	k = 0;
	for (i = 0; i < grp->lt_nports; i++) {
		match = B_FALSE;
		for (j = 0; j < attr->lt_nports && !match; j++) {
			match = (strcmp(grp->lt_ports[i].lp_devname,
			    attr->lt_ports[j].lp_devname) == 0);
		}
		if (match)
			nremoved++;
		else
			grp->lt_ports[k++] = grp->lt_ports[i];
	}

	if (nremoved != attr->lt_nports) {
		errno = ENOENT;
		return (-1);
	}

	grp->lt_nports -= nremoved;

	/* save modified group */
	return (0);
}

static dladm_status_t
i_dladm_aggr_remove_db(dladm_aggr_grp_attr_db_t *attr, const char *root)
{
	remove_db_state_t state;
	dladm_status_t status;

	state.rs_attr = attr;
	state.rs_found = B_FALSE;

	status = i_dladm_aggr_walk_rw_db(i_dladm_aggr_remove_db_fn,
	    &state, root);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (!state.rs_found)
		return (DLADM_STATUS_NOTFOUND);

	return (DLADM_STATUS_OK);
}

/*
 * Given a policy string, return a policy mask. Returns B_TRUE on
 * success, or B_FALSE if an error occured during parsing.
 */
boolean_t
dladm_aggr_str2policy(const char *str, uint32_t *policy)
{
	int i;
	policy_t *pol;
	char *token = NULL;
	char *lasts;

	*policy = 0;

	while ((token = strtok_r((token == NULL) ? (char *)str : NULL, ",",
	    &lasts)) != NULL) {
		for (i = 0; i < NPOLICIES; i++) {
			pol = &policies[i];
			if (strcasecmp(token, pol->pol_name) == 0) {
				*policy |= pol->policy;
				break;
			}
		}
		if (i == NPOLICIES)
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Given a policy mask, returns a printable string, or NULL if the
 * policy mask is invalid. It is the responsibility of the caller to
 * free the returned string after use.
 */
char *
dladm_aggr_policy2str(uint32_t policy, char *str)
{
	int i, npolicies = 0;
	policy_t *pol;

	str[0] = '\0';

	for (i = 0; i < NPOLICIES; i++) {
		pol = &policies[i];
		if ((policy & pol->policy) != 0) {
			npolicies++;
			if (npolicies > 1)
				(void) strcat(str, ",");
			(void) strcat(str, pol->pol_name);
		}
	}

	return (str);
}

/*
 * Given a MAC address string, return the MAC address in the mac_addr
 * array. If the MAC address was not explicitly specified, i.e. is
 * equal to 'auto', zero out mac-addr and set mac_fixed to B_TRUE.
 * Return B_FALSE if a syntax error was encountered, B_FALSE otherwise.
 */
boolean_t
dladm_aggr_str2macaddr(const char *str, boolean_t *mac_fixed, uchar_t *mac_addr)
{
	uchar_t *conv_str;
	int mac_len;

	*mac_fixed = (strcmp(str, "auto") != 0);
	if (!*mac_fixed) {
		bzero(mac_addr, ETHERADDRL);
		return (B_TRUE);
	}

	conv_str = _link_aton(str, &mac_len);
	if (conv_str == NULL)
		return (B_FALSE);

	if (mac_len != ETHERADDRL) {
		free(conv_str);
		return (B_FALSE);
	}

	if ((bcmp(zero_mac, conv_str, ETHERADDRL) == 0) ||
	    (conv_str[0] & 0x01)) {
		free(conv_str);
		return (B_FALSE);
	}

	bcopy(conv_str, mac_addr, ETHERADDRL);
	free(conv_str);

	return (B_TRUE);
}

/*
 * Returns a string containing a printable representation of a MAC address.
 */
const char *
dladm_aggr_macaddr2str(unsigned char *mac, char *buf)
{
	static char unknown_mac[] = {0, 0, 0, 0, 0, 0};

	if (buf == NULL)
		return (NULL);

	if (bcmp(unknown_mac, mac, ETHERADDRL) == 0)
		return (gettext("<unknown>"));
	else
		return (_link_ntoa(mac, buf, ETHERADDRL, IFT_OTHER));
}

/*
 * Given a LACP mode string, find the corresponding LACP mode number. Returns
 * B_TRUE if a match was found, B_FALSE otherwise.
 */
boolean_t
dladm_aggr_str2lacpmode(const char *str, aggr_lacp_mode_t *lacp_mode)
{
	int i;
	dladm_aggr_lacpmode_t *mode;

	for (i = 0; i < NLACP_MODES; i++) {
		mode = &lacp_modes[i];
		if (strncasecmp(str, mode->mode_str,
		    strlen(mode->mode_str)) == 0) {
			*lacp_mode = mode->mode_id;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Given a LACP mode number, returns a printable string, or NULL if the
 * LACP mode number is invalid.
 */
const char *
dladm_aggr_lacpmode2str(aggr_lacp_mode_t mode_id, char *buf)
{
	int i;
	dladm_aggr_lacpmode_t *mode;

	for (i = 0; i < NLACP_MODES; i++) {
		mode = &lacp_modes[i];
		if (mode->mode_id == mode_id) {
			(void) snprintf(buf, DLADM_STRSIZE, "%s",
			    mode->mode_str);
			return (buf);
		}
	}

	(void) strlcpy(buf, "unknown", DLADM_STRSIZE);
	return (buf);
}

/*
 * Given a LACP timer string, find the corresponding LACP timer number. Returns
 * B_TRUE if a match was found, B_FALSE otherwise.
 */
boolean_t
dladm_aggr_str2lacptimer(const char *str, aggr_lacp_timer_t *lacp_timer)
{
	int i;
	dladm_aggr_lacptimer_t *timer;

	for (i = 0; i < NLACP_TIMERS; i++) {
		timer = &lacp_timers[i];
		if (strncasecmp(str, timer->lt_str,
		    strlen(timer->lt_str)) == 0) {
			*lacp_timer = timer->lt_id;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Given a LACP timer, returns a printable string, or NULL if the
 * LACP timer number is invalid.
 */
const char *
dladm_aggr_lacptimer2str(aggr_lacp_timer_t timer_id, char *buf)
{
	int i;
	dladm_aggr_lacptimer_t *timer;

	for (i = 0; i < NLACP_TIMERS; i++) {
		timer = &lacp_timers[i];
		if (timer->lt_id == timer_id) {
			(void) snprintf(buf, DLADM_STRSIZE, "%s",
			    timer->lt_str);
			return (buf);
		}
	}

	(void) strlcpy(buf, "unknown", DLADM_STRSIZE);
	return (buf);
}

const char *
dladm_aggr_portstate2str(aggr_port_state_t state_id, char *buf)
{
	int			i;
	dladm_aggr_port_state_t	*state;

	for (i = 0; i < NPORT_STATES; i++) {
		state = &port_states[i];
		if (state->state_id == state_id) {
			(void) snprintf(buf, DLADM_STRSIZE, "%s",
			    state->state_str);
			return (buf);
		}
	}

	(void) strlcpy(buf, "unknown", DLADM_STRSIZE);
	return (buf);
}

#define	FPRINTF_ERR(fcall) if ((fcall) < 0) return (-1);

/*
 * Write the attribute of a group to the specified file. Returns 0 on
 * success, -1 on failure.
 */
static int
i_dladm_aggr_fput_grp(FILE *fp, dladm_aggr_grp_attr_db_t *attr)
{
	int i;
	char addr_str[ETHERADDRL * 3];
	char buf[DLADM_STRSIZE];

	/* key, policy */
	FPRINTF_ERR(fprintf(fp, "%d\t%s\t", attr->lt_key,
	    dladm_aggr_policy2str(attr->lt_policy, buf)));

	/* number of ports, ports */
	FPRINTF_ERR(fprintf(fp, "%d\t", attr->lt_nports));
	for (i = 0; i < attr->lt_nports; i++) {
		if (i > 0)
			FPRINTF_ERR(fprintf(fp, ","));
		FPRINTF_ERR(fprintf(fp, "%s", attr->lt_ports[i].lp_devname));
	}
	FPRINTF_ERR(fprintf(fp, "\t"));

	/* MAC address */
	if (!attr->lt_mac_fixed) {
		FPRINTF_ERR(fprintf(fp, "auto"));
	} else {
		FPRINTF_ERR(fprintf(fp, "%s",
		    dladm_aggr_macaddr2str(attr->lt_mac, addr_str)));
	}
	FPRINTF_ERR(fprintf(fp, "\t"));

	FPRINTF_ERR(fprintf(fp, "%s\t",
	    dladm_aggr_lacpmode2str(attr->lt_lacp_mode, buf)));

	FPRINTF_ERR(fprintf(fp, "%s\n",
	    dladm_aggr_lacptimer2str(attr->lt_lacp_timer, buf)));

	return (0);
}

static dladm_status_t
i_dladm_aggr_create_db(dladm_aggr_grp_attr_db_t *attr, const char *root)
{
	FILE		*fp;
	char		line[MAXLINELEN];
	uint32_t	key;
	int 		lock_fd;
	char 		*db_file;
	char 		db_file_buf[MAXPATHLEN];
	char 		*endp = NULL;
	dladm_status_t	status;

	if (root == NULL) {
		db_file = DLADM_AGGR_DB;
	} else {
		(void) snprintf(db_file_buf, MAXPATHLEN, "%s%s", root,
		    DLADM_AGGR_DB);
		db_file = db_file_buf;
	}

	if ((lock_fd = i_dladm_aggr_lock_db(F_WRLCK)) < 0)
		return (dladm_errno2status(errno));

	if ((fp = fopen(db_file, "r+")) == NULL &&
	    (fp = fopen(db_file, "w")) == NULL) {
		status = dladm_errno2status(errno);
		i_dladm_aggr_unlock_db(lock_fd);
		return (status);
	}

	/* look for existing group with same key */
	while (fgets(line, MAXLINELEN, fp) != NULL) {
		char *holder, *lasts;

		/* skip comments */
		if (BLANK_LINE(line))
			continue;

		/* ignore corrupted lines */
		holder = strtok_r(line, " \t", &lasts);
		if (holder == NULL)
			continue;

		/* port number */
		errno = 0;
		key = (int)strtol(holder, &endp, 10);
		if (errno != 0 || *endp != '\0') {
			status = DLADM_STATUS_REPOSITORYINVAL;
			goto done;
		}

		if (key == attr->lt_key) {
			/* group with key already exists */
			status = DLADM_STATUS_EXIST;
			goto done;
		}
	}

	/*
	 * If we get here, we've verified that no existing group with
	 * the same key already exists. It's now time to add the
	 * new group to the DB.
	 */
	if (i_dladm_aggr_fput_grp(fp, attr) != 0) {
		status = dladm_errno2status(errno);
		goto done;
	}

	status = DLADM_STATUS_OK;

done:
	(void) fclose(fp);
	i_dladm_aggr_unlock_db(lock_fd);
	return (status);
}

/*
 * Create a new link aggregation group. Update the configuration
 * file and bring it up.
 */
dladm_status_t
dladm_aggr_create(uint32_t key, uint32_t nports,
    dladm_aggr_port_attr_db_t *ports, uint32_t policy, boolean_t mac_addr_fixed,
    uchar_t *mac_addr, aggr_lacp_mode_t lacp_mode, aggr_lacp_timer_t lacp_timer,
    boolean_t tempop, const char *root)
{
	dladm_aggr_grp_attr_db_t attr;
	dladm_status_t status;

	if (key == 0 || key > DLADM_AGGR_MAX_KEY)
		return (DLADM_STATUS_KEYINVAL);

	attr.lt_key = key;
	attr.lt_nports = nports;
	attr.lt_ports = ports;
	attr.lt_policy = policy;
	attr.lt_mac_fixed = mac_addr_fixed;
	if (attr.lt_mac_fixed)
		bcopy(mac_addr, attr.lt_mac, ETHERADDRL);
	else
		bzero(attr.lt_mac, ETHERADDRL);
	attr.lt_lacp_mode = lacp_mode;
	attr.lt_lacp_timer = lacp_timer;

	/* add the link aggregation group to the DB */
	if (!tempop) {
		status = i_dladm_aggr_create_db(&attr, root);
		if (status != DLADM_STATUS_OK)
			return (status);
	} else {
		dladm_aggr_up_t up;

		up.lu_key = key;
		up.lu_found = B_FALSE;
		up.lu_fd = open(DLADM_AGGR_DEV, O_RDWR);
		if (up.lu_fd < 0)
			return (dladm_errno2status(errno));

		status = i_dladm_aggr_up((void *)&up, &attr);
		(void) close(up.lu_fd);
		return (status);
	}

	/* bring up the link aggregation group */
	status = dladm_aggr_up(key, root);
	/*
	 * If the operation fails because the aggregation already exists,
	 * then only update the persistent configuration repository and
	 * return success.
	 */
	if (status == DLADM_STATUS_EXIST)
		status = DLADM_STATUS_OK;

	if (status != DLADM_STATUS_OK && !tempop)
		(void) i_dladm_aggr_del_db(&attr, root);

	return (status);
}

/*
 * Modify the parameters of an existing link aggregation group. Update
 * the configuration file and pass the changes to the kernel.
 */
dladm_status_t
dladm_aggr_modify(uint32_t key, uint32_t modify_mask, uint32_t policy,
    boolean_t mac_fixed, uchar_t *mac_addr, aggr_lacp_mode_t lacp_mode,
    aggr_lacp_timer_t lacp_timer, boolean_t tempop, const char *root)
{
	dladm_aggr_modify_attr_t new_attr, old_attr;
	dladm_status_t status;

	if (key == 0)
		return (DLADM_STATUS_KEYINVAL);

	if (modify_mask & DLADM_AGGR_MODIFY_POLICY)
		new_attr.ld_policy = policy;

	if (modify_mask & DLADM_AGGR_MODIFY_MAC) {
		new_attr.ld_mac_fixed = mac_fixed;
		bcopy(mac_addr, new_attr.ld_mac, ETHERADDRL);
	}

	if (modify_mask & DLADM_AGGR_MODIFY_LACP_MODE)
		new_attr.ld_lacp_mode = lacp_mode;

	if (modify_mask & DLADM_AGGR_MODIFY_LACP_TIMER)
		new_attr.ld_lacp_timer = lacp_timer;

	/* update the DB */
	if (!tempop && ((status = i_dladm_aggr_modify_db(key, modify_mask,
	    &new_attr, &old_attr, root)) != DLADM_STATUS_OK)) {
		return (status);
	}

	status = i_dladm_aggr_modify_sys(key, modify_mask, &new_attr);
	if (status != DLADM_STATUS_OK && !tempop) {
		(void) i_dladm_aggr_modify_db(key, modify_mask, &old_attr,
		    NULL, root);
	}

	return (status);
}

/*
 * Delete a previously created link aggregation group.
 */
dladm_status_t
dladm_aggr_delete(uint32_t key, boolean_t tempop, const char *root)
{
	dladm_aggr_grp_attr_db_t db_attr;
	dladm_status_t status;

	if (key == 0)
		return (DLADM_STATUS_KEYINVAL);

	if (tempop) {
		dladm_aggr_down_t down;
		dladm_aggr_grp_attr_t sys_attr;

		down.ld_key = key;
		down.ld_found = B_FALSE;
		sys_attr.lg_key = key;
		if (i_dladm_aggr_down((void *)&down, &sys_attr) < 0)
			return (dladm_errno2status(errno));
		else
			return (DLADM_STATUS_OK);
	} else {
		status = dladm_aggr_down(key);

		/*
		 * Only continue to delete the configuration repository
		 * either if we successfully delete the active aggregation
		 * or if the aggregation is not found.
		 */
		if (status != DLADM_STATUS_OK &&
		    status != DLADM_STATUS_NOTFOUND) {
			return (status);
		}
	}

	if (tempop)
		return (DLADM_STATUS_OK);

	db_attr.lt_key = key;
	return (i_dladm_aggr_del_db(&db_attr, root));
}

/*
 * Add one or more ports to an existing link aggregation.
 */
dladm_status_t
dladm_aggr_add(uint32_t key, uint32_t nports, dladm_aggr_port_attr_db_t *ports,
    boolean_t tempop, const char *root)
{
	dladm_aggr_grp_attr_db_t attr;
	dladm_status_t status;

	if (key == 0)
		return (DLADM_STATUS_KEYINVAL);

	bzero(&attr, sizeof (attr));
	attr.lt_key = key;
	attr.lt_nports = nports;
	attr.lt_ports = ports;

	if (!tempop &&
	    ((status = i_dladm_aggr_add_db(&attr, root)) != DLADM_STATUS_OK)) {
		return (status);
	}

	status = i_dladm_aggr_add_rem_sys(&attr, LAIOC_ADD);
	if (status != DLADM_STATUS_OK && !tempop)
		(void) i_dladm_aggr_remove_db(&attr, root);

	return (status);
}

/*
 * Remove one or more ports from an existing link aggregation.
 */
dladm_status_t
dladm_aggr_remove(uint32_t key, uint32_t nports,
    dladm_aggr_port_attr_db_t *ports, boolean_t tempop, const char *root)
{
	dladm_aggr_grp_attr_db_t attr;
	dladm_status_t status;

	if (key == 0)
		return (DLADM_STATUS_KEYINVAL);

	bzero(&attr, sizeof (attr));
	attr.lt_key = key;
	attr.lt_nports = nports;
	attr.lt_ports = ports;

	if (!tempop &&
	    ((status = i_dladm_aggr_remove_db(&attr, root)) !=
	    DLADM_STATUS_OK)) {
		return (status);
	}

	status = i_dladm_aggr_add_rem_sys(&attr, LAIOC_REMOVE);
	if (status != DLADM_STATUS_OK && !tempop)
		(void) i_dladm_aggr_add_db(&attr, root);

	return (status);
}
