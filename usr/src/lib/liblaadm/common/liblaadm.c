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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
#include <liblaadm.h>

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
 * <sep>		::= ' ' | '\t'
 * <key>		::= <number>
 * <nports>	::= <number>
 * <ports>	::= <port> <m-port>*
 * <m-port>	::= ',' <port>
 * <port>		::= <devname>
 * <devname>	::= <string>
 * <port-num>	::= <number>
 * <policy>	::= <pol-level> <m-pol>*
 * <m-pol>	::= ',' <pol-level>
 * <pol-level>	::= 'L2' | 'L3' | 'L4'
 * <mac>		::= 'auto' | <mac-addr>
 * <mac-addr>	::= <hex> ':' <hex> ':' <hex> ':' <hex> ':' <hex> ':' <hex>
 * <lacp-mode>	::= 'off' | 'active' | 'passive'
 * <lacp-timer>	::= 'short' | 'long'
 */

#define	LAADM_DEV	"/devices/pseudo/aggr@0:" AGGR_DEVNAME_CTL
#define	LAADM_DB	"/etc/aggregation.conf"
#define	LAADM_DB_TMP	"/etc/aggregation.conf.new"
#define	LAADM_DB_LOCK	"/tmp/aggregation.conf.lock"

#define	LAADM_DB_PERMS	S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH
#define	LAADM_DB_OWNER	0
#define	LAADM_DB_GROUP	1

/*
 * The largest configurable aggregation key.  Because by default the key is
 * used as the DLPI device PPA and default VLAN PPA's are calculated as
 * ((1000 * vid) + PPA), the largest key can't be > 999.
 */
#define	LAADM_MAX_KEY	999

#define	BLANK_LINE(s)	((s[0] == '\0') || (s[0] == '#') || (s[0] == '\n'))

#define	MAXLINELEN	1024

/* Limits on buffer size for LAIOC_INFO request */
#define	MIN_INFO_SIZE (4*1024)
#define	MAX_INFO_SIZE (128*1024)

#define	MAXPATHLEN	1024

static uchar_t	zero_mac[] = {0, 0, 0, 0, 0, 0};

/* configuration database entry */
typedef struct laadm_grp_attr_db {
	uint32_t	lt_key;
	uint32_t	lt_policy;
	uint32_t	lt_nports;
	laadm_port_attr_db_t *lt_ports;
	boolean_t	lt_mac_fixed;
	uchar_t		lt_mac[ETHERADDRL];
	aggr_lacp_mode_t lt_lacp_mode;
	aggr_lacp_timer_t lt_lacp_timer;
} laadm_grp_attr_db_t;

typedef struct laadm_up {
	uint32_t	lu_key;
	boolean_t	lu_found;
	int		lu_fd;
} laadm_up_t;

typedef struct laadm_down {
	uint32_t	ld_key;
	boolean_t	ld_found;
} laadm_down_t;

typedef struct laadm_modify_attr {
	uint32_t	ld_policy;
	boolean_t	ld_mac_fixed;
	uchar_t		ld_mac[ETHERADDRL];
	aggr_lacp_mode_t ld_lacp_mode;
	aggr_lacp_timer_t ld_lacp_timer;
} laadm_modify_attr_t;

typedef struct policy_s {
	char		*pol_name;
	uint32_t	policy;
} policy_t;

static policy_t policies[] = {
	{"L2",		AGGR_POLICY_L2},
	{"L3",		AGGR_POLICY_L3},
	{"L4",		AGGR_POLICY_L4}};

#define	NPOLICIES	(sizeof (policies) / sizeof (policy_t))

typedef struct laadm_lacp_mode_s {
	char		*mode_str;
	aggr_lacp_mode_t mode_id;
} laadm_lacp_mode_t;

static laadm_lacp_mode_t lacp_modes[] = {
	{"off", AGGR_LACP_OFF},
	{"active", AGGR_LACP_ACTIVE},
	{"passive", AGGR_LACP_PASSIVE}};

#define	NLACP_MODES	(sizeof (lacp_modes) / sizeof (laadm_lacp_mode_t))

typedef struct laadm_lacp_timer_s {
	char		*lt_str;
	aggr_lacp_timer_t lt_id;
} laadm_lacp_timer_t;

static laadm_lacp_timer_t lacp_timers[] = {
	{"short", AGGR_LACP_TIMER_SHORT},
	{"long", AGGR_LACP_TIMER_LONG}};

#define	NLACP_TIMERS	(sizeof (lacp_timers) / sizeof (laadm_lacp_timer_t))

typedef struct delete_db_state {
	uint32_t	ds_key;
	boolean_t	ds_found;
} delete_db_state_t;


typedef struct modify_db_state {
	uint32_t	us_key;
	uint32_t		us_mask;
	laadm_modify_attr_t *us_attr_new;
	laadm_modify_attr_t *us_attr_old;
	boolean_t	us_found;
} modify_db_state_t;

typedef struct add_db_state {
	laadm_grp_attr_db_t *as_attr;
	boolean_t	as_found;
} add_db_state_t;

static int i_laadm_fput_grp(FILE *, laadm_grp_attr_db_t *);

static int
i_laadm_strioctl(int fd, int cmd, void *ptr, int ilen)
{
	struct strioctl str;

	str.ic_cmd = cmd;
	str.ic_timout = 0;
	str.ic_len = ilen;
	str.ic_dp = ptr;

	return (ioctl(fd, I_STR, &str));
}

/*
 * Open and lock the aggregation configuration file lock. The lock is
 * acquired as a reader (F_RDLCK) or writer (F_WRLCK).
 */
static int
i_laadm_lock_db(short type)
{
	int lock_fd;
	struct flock lock;

	if ((lock_fd = open(LAADM_DB_LOCK, O_RDWR | O_CREAT | O_TRUNC,
	    LAADM_DB_PERMS)) < 0)
		return (-1);

	lock.l_type = type;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(lock_fd, F_SETLKW, &lock) < 0) {
		(void) close(lock_fd);
		(void) unlink(LAADM_DB_LOCK);
		return (-1);
	}
	return (lock_fd);
}

/*
 * Unlock and close the specified file.
 */
static void
i_laadm_unlock_db(int fd)
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
	(void) unlink(LAADM_DB_LOCK);
}

/*
 * Walk through the groups defined on the system and for each group <grp>,
 * invoke <fn>(<arg>, <grp>);
 * Terminate the walk if at any time <fn> returns non-NULL value
 */
int
laadm_walk_sys(int (*fn)(void *, laadm_grp_attr_sys_t *), void *arg)
{
	laioc_info_t *ioc;
	laioc_info_group_t *grp;
	laioc_info_port_t *port;
	laadm_grp_attr_sys_t attr;
	int rc, i, j, bufsize, fd;
	char *where;

	if ((fd = open(LAADM_DEV, O_RDWR)) == -1)
		return (-1);

	bufsize = MIN_INFO_SIZE;
	ioc = (laioc_info_t *)calloc(1, bufsize);
	if (ioc == NULL) {
		(void) close(fd);
		errno = ENOMEM;
		return (-1);
	}

tryagain:
	rc = i_laadm_strioctl(fd, LAIOC_INFO, ioc, bufsize);

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
		    sizeof (laadm_port_attr_sys_t));
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
i_laadm_parse_db(char *line, laadm_grp_attr_db_t *attr)
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
	    !laadm_str_to_policy(token, &attr->lt_policy))
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
	    sizeof (laadm_port_attr_db_t))) == NULL)
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
	    !laadm_str_to_mac_addr(token, &attr->lt_mac_fixed,
	    attr->lt_mac))
		goto failed;

	/* LACP mode */
	if ((token = strtok_r(NULL, " \t\n", &lasts)) == NULL ||
	    !laadm_str_to_lacp_mode(token, &attr->lt_lacp_mode))
		attr->lt_lacp_mode = AGGR_LACP_OFF;

	/* LACP timer */
	if ((token = strtok_r(NULL, " \t\n", &lasts)) == NULL ||
	    !laadm_str_to_lacp_timer(token, &attr->lt_lacp_timer))
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
static int
i_laadm_walk_db(int (*fn)(void *, laadm_grp_attr_db_t *, laadm_diag_t *),
    void *arg, const char *root, laadm_diag_t *diag)
{
	FILE *fp;
	char line[MAXLINELEN];
	laadm_grp_attr_db_t attr;
	char *db_file;
	char db_file_buf[MAXPATHLEN];
	int lock_fd, retval = -1;

	if (root == NULL) {
		db_file = LAADM_DB;
	} else {
		(void) snprintf(db_file_buf, MAXPATHLEN, "%s%s", root,
		    LAADM_DB);
		db_file = db_file_buf;
	}

	lock_fd = i_laadm_lock_db(F_RDLCK);

	if ((fp = fopen(db_file, "r")) == NULL) {
		i_laadm_unlock_db(lock_fd);
		*diag = LAADM_DIAG_REPOSITORY_OPENFAIL;
		return (-1);
	}

	bzero(&attr, sizeof (attr));

	while (fgets(line, MAXLINELEN, fp) != NULL) {
		/* skip comments */
		if (BLANK_LINE(line))
			continue;

		if (i_laadm_parse_db(line, &attr) != 0) {
			errno = EFAULT;
			*diag = LAADM_DIAG_REPOSITORY_PARSEFAIL;
			goto failed;
		}

		if (fn(arg, &attr, diag) != 0)
			goto failed;

		free(attr.lt_ports);
		attr.lt_ports = NULL;
	}
	retval = 0;

failed:
	free(attr.lt_ports);
	(void) fclose(fp);
	i_laadm_unlock_db(lock_fd);
	return (retval);
}

/*
 * Send an add or remove command to the link aggregation driver.
 */
static int
i_laadm_add_rem_sys(laadm_grp_attr_db_t *attr, int cmd, laadm_diag_t *diag)
{
	int i, rc, fd, len;
	laioc_add_rem_t *iocp;
	laioc_port_t *ports;

	len = sizeof (*iocp) + attr->lt_nports * sizeof (laioc_port_t);
	iocp = malloc(len);
	if (iocp == NULL)
		goto failed;

	iocp->la_key = attr->lt_key;
	iocp->la_nports = attr->lt_nports;
	ports = (laioc_port_t *)(iocp + 1);

	for (i = 0; i < attr->lt_nports; i++) {
		if (strlcpy(ports[i].lp_devname,
		    attr->lt_ports[i].lp_devname,
		    MAXNAMELEN) >= MAXNAMELEN)
			goto failed;
	}

	if ((fd = open(LAADM_DEV, O_RDWR)) < 0) {
		*diag = LAADM_DIAG_REPOSITORY_OPENFAIL;
		goto failed;
	}

	rc = i_laadm_strioctl(fd, cmd, iocp, len);
	if ((rc < 0) && (errno == EINVAL))
		*diag = LAADM_DIAG_INVALID_INTFNAME;

	(void) close(fd);

	free(iocp);
	return (rc);

failed:
	free(iocp);
	return (-1);
}

/*
 * Send a modify command to the link aggregation driver.
 */
static int
i_laadm_modify_sys(uint32_t key, uint32_t mask, laadm_modify_attr_t *attr,
    laadm_diag_t *diag)
{
	int rc, fd;
	laioc_modify_t ioc;

	ioc.lu_key = key;

	ioc.lu_modify_mask = 0;
	if (mask & LAADM_MODIFY_POLICY)
		ioc.lu_modify_mask |= LAIOC_MODIFY_POLICY;
	if (mask & LAADM_MODIFY_MAC)
		ioc.lu_modify_mask |= LAIOC_MODIFY_MAC;
	if (mask & LAADM_MODIFY_LACP_MODE)
		ioc.lu_modify_mask |= LAIOC_MODIFY_LACP_MODE;
	if (mask & LAADM_MODIFY_LACP_TIMER)
		ioc.lu_modify_mask |= LAIOC_MODIFY_LACP_TIMER;

	ioc.lu_policy = attr->ld_policy;
	ioc.lu_mac_fixed = attr->ld_mac_fixed;
	bcopy(attr->ld_mac, ioc.lu_mac, ETHERADDRL);
	ioc.lu_lacp_mode = attr->ld_lacp_mode;
	ioc.lu_lacp_timer = attr->ld_lacp_timer;

	if ((fd = open(LAADM_DEV, O_RDWR)) < 0) {
		*diag = LAADM_DIAG_REPOSITORY_OPENFAIL;
		return (-1);
	}

	rc = i_laadm_strioctl(fd, LAIOC_MODIFY, &ioc, sizeof (ioc));
	if ((rc < 0) && (errno == EINVAL))
		*diag = LAADM_DIAG_INVALID_MACADDR;

	(void) close(fd);

	return (rc);
}

/*
 * Send a create command to the link aggregation driver.
 */
static int
i_laadm_create_sys(int fd, laadm_grp_attr_db_t *attr, laadm_diag_t *diag)
{
	int i, rc, len;
	laioc_create_t *iocp;
	laioc_port_t *ports;

	len = sizeof (*iocp) + attr->lt_nports * sizeof (laioc_port_t);
	iocp = malloc(len);
	if (iocp == NULL)
		return (-1);

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
			errno = EINVAL;
			free(iocp);
			return (-1);
		}
	}

	if (attr->lt_mac_fixed &&
	    ((bcmp(zero_mac, attr->lt_mac, ETHERADDRL) == 0) ||
	    (attr->lt_mac[0] & 0x01))) {
		errno = EINVAL;
		*diag = LAADM_DIAG_INVALID_MACADDR;
		free(iocp);
		return (-1);
	}

	bcopy(attr->lt_mac, iocp->lc_mac, ETHERADDRL);
	iocp->lc_mac_fixed = attr->lt_mac_fixed;

	rc = i_laadm_strioctl(fd, LAIOC_CREATE, iocp, len);
	if (rc < 0)
		*diag = LAADM_DIAG_INVALID_INTFNAME;

	free(iocp);
	return (rc);
}

/*
 * Invoked to bring up a link aggregation group.
 */
static int
i_laadm_up(void *arg, laadm_grp_attr_db_t *attr, laadm_diag_t *diag)
{
	laadm_up_t *up = (laadm_up_t *)arg;

	if (up->lu_key != 0 && up->lu_key != attr->lt_key)
		return (0);

	up->lu_found = B_TRUE;

	if (i_laadm_create_sys(up->lu_fd, attr, diag) < 0 &&
	    up->lu_key != 0) {
		return (-1);
	}

	return (0);
}

/*
 * Bring up a link aggregation group or all of them if the key is zero.
 * If key is 0, walk may terminate early if any of the links fail
 */
int
laadm_up(uint32_t key, const char *root, laadm_diag_t *diag)
{
	laadm_up_t up;

	if ((up.lu_fd = open(LAADM_DEV, O_RDWR)) < 0)
		return (-1);

	up.lu_key = key;
	up.lu_found = B_FALSE;

	if (i_laadm_walk_db(i_laadm_up, &up, root, diag) < 0) {
		(void) close(up.lu_fd);
		return (-1);
	}
	(void) close(up.lu_fd);

	/*
	 * only return error if user specified key and key was
	 * not found
	 */
	if (!up.lu_found && key != 0) {
		errno = ENOENT;
		return (-1);
	}

	return (0);
}
/*
 * Send a delete command to the link aggregation driver.
 */
static int
i_laadm_delete_sys(int fd, laadm_grp_attr_sys_t *attr)
{
	laioc_delete_t ioc;

	ioc.ld_key = attr->lg_key;

	return (i_laadm_strioctl(fd, LAIOC_DELETE, &ioc, sizeof (ioc)));
}

/*
 * Invoked to bring down a link aggregation group.
 */
static int
i_laadm_down(void *arg, laadm_grp_attr_sys_t *attr)
{
	laadm_down_t *down = (laadm_down_t *)arg;
	int fd;

	if (down->ld_key != 0 && down->ld_key != attr->lg_key)
		return (0);

	down->ld_found = B_TRUE;

	if ((fd = open(LAADM_DEV, O_RDWR)) < 0)
		return (-1);

	if (i_laadm_delete_sys(fd, attr) < 0 && down->ld_key != 0) {
		(void) close(fd);
		return (-1);
	}

	(void) close(fd);
	return (0);
}

/*
 * Bring down a link aggregation group or all of them if the key is zero.
 * If key is 0, walk may terminate early if any of the links fail
 */
int
laadm_down(uint32_t key)
{
	laadm_down_t down;

	down.ld_key = key;
	down.ld_found = B_FALSE;

	if (laadm_walk_sys(i_laadm_down, &down) < 0)
		return (-1);

	/*
	 * only return error if user specified key and key was
	 * not found
	 */
	if (!down.ld_found && key != 0) {
		errno = ENOENT;
		return (-1);
	}

	return (0);
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
static int
i_laadm_walk_rw_db(int (*fn)(void *, laadm_grp_attr_db_t *),
    void *arg,
    const char *root,
    laadm_diag_t *diag)
{
	FILE *fp, *nfp;
	int nfd, fn_rc, lock_fd;
	char line[MAXLINELEN];
	laadm_grp_attr_db_t attr;
	char *db_file, *tmp_db_file;
	char db_file_buf[MAXPATHLEN];
	char tmp_db_file_buf[MAXPATHLEN];

	if (root == NULL) {
		db_file = LAADM_DB;
		tmp_db_file = LAADM_DB_TMP;
	} else {
		(void) snprintf(db_file_buf, MAXPATHLEN, "%s%s", root,
		    LAADM_DB);
		(void) snprintf(tmp_db_file_buf, MAXPATHLEN, "%s%s", root,
		    LAADM_DB_TMP);
		db_file = db_file_buf;
		tmp_db_file = tmp_db_file_buf;
	}

	if ((lock_fd = i_laadm_lock_db(F_WRLCK)) < 0)
		return (-1);

	if ((fp = fopen(db_file, "r")) == NULL) {
		i_laadm_unlock_db(lock_fd);
		*diag = LAADM_DIAG_REPOSITORY_OPENFAIL;
		return (-1);
	}

	if ((nfd = open(tmp_db_file, O_WRONLY|O_CREAT|O_TRUNC,
	    LAADM_DB_PERMS)) == -1) {
		(void) fclose(fp);
		i_laadm_unlock_db(lock_fd);
		return (-1);
	}

	if ((nfp = fdopen(nfd, "w")) == NULL) {
		(void) close(nfd);
		(void) fclose(fp);
		(void) unlink(tmp_db_file);
		i_laadm_unlock_db(lock_fd);
		*diag = LAADM_DIAG_REPOSITORY_OPENFAIL;
		return (-1);
	}

	attr.lt_ports = NULL;

	while (fgets(line, MAXLINELEN, fp) != NULL) {

		/* skip comments */
		if (BLANK_LINE(line)) {
			if (fputs(line, nfp) == EOF)
				goto failed;
			continue;
		}

		if (i_laadm_parse_db(line, &attr) != 0) {
			errno = EFAULT;
			*diag = LAADM_DIAG_REPOSITORY_PARSEFAIL;
			goto failed;
		}

		fn_rc = fn(arg, &attr);

		switch (fn_rc) {
		case -1:
			/* failure, stop walking */
			goto failed;
		case 0:
			/*
			 * Success, write group attributes, which could
			 * have been modified by fn().
			 */
			if (i_laadm_fput_grp(nfp, &attr) != 0)
				goto failed;
			break;
		case 1:
			/* skip current group */
			break;
		}

		free(attr.lt_ports);
		attr.lt_ports = NULL;
	}

	if (fchmod(nfd, LAADM_DB_PERMS) == -1)
		goto failed;

	if (fchown(nfd, LAADM_DB_OWNER, LAADM_DB_GROUP) == -1)
		goto failed;

	if (fflush(nfp) == EOF)
		goto failed;

	(void) fclose(fp);
	(void) fclose(nfp);

	if (rename(tmp_db_file, db_file) == -1) {
		(void) unlink(tmp_db_file);
		i_laadm_unlock_db(lock_fd);
		return (-1);
	}

	i_laadm_unlock_db(lock_fd);
	return (0);

failed:
	free(attr.lt_ports);
	(void) fclose(fp);
	(void) fclose(nfp);
	(void) unlink(tmp_db_file);
	i_laadm_unlock_db(lock_fd);

	return (-1);
}

/*
 * Remove an entry from the DB.
 */
static int
i_laadm_delete_db_fn(void *arg, laadm_grp_attr_db_t *grp)
{
	delete_db_state_t *state = arg;

	if (grp->lt_key != state->ds_key)
		return (0);

	state->ds_found = B_TRUE;

	/* don't save matching group */
	return (1);
}

static int
i_laadm_delete_db(laadm_grp_attr_db_t *attr, const char *root,
    laadm_diag_t *diag)
{
	delete_db_state_t state;

	state.ds_key = attr->lt_key;
	state.ds_found = B_FALSE;

	if (i_laadm_walk_rw_db(i_laadm_delete_db_fn, &state, root,
	    diag) != 0)
		return (-1);

	if (!state.ds_found) {
		errno = ENOENT;
		return (-1);
	}

	return (0);
}

/*
 * Modify the properties of an existing group in the DB.
 */
static int
i_laadm_modify_db_fn(void *arg, laadm_grp_attr_db_t *grp)
{
	modify_db_state_t *state = arg;
	laadm_modify_attr_t *new_attr = state->us_attr_new;
	laadm_modify_attr_t *old_attr = state->us_attr_old;

	if (grp->lt_key != state->us_key)
		return (0);

	state->us_found = B_TRUE;

	if (state->us_mask & LAADM_MODIFY_POLICY) {
		if (old_attr != NULL)
			old_attr->ld_policy = grp->lt_policy;
		grp->lt_policy = new_attr->ld_policy;
	}

	if (state->us_mask & LAADM_MODIFY_MAC) {
		if (old_attr != NULL) {
			old_attr->ld_mac_fixed = grp->lt_mac_fixed;
			bcopy(grp->lt_mac, old_attr->ld_mac, ETHERADDRL);
		}
		grp->lt_mac_fixed = new_attr->ld_mac_fixed;
		bcopy(new_attr->ld_mac, grp->lt_mac, ETHERADDRL);
	}

	if (state->us_mask & LAADM_MODIFY_LACP_MODE) {
		if (old_attr != NULL)
			old_attr->ld_lacp_mode = grp->lt_lacp_mode;
		grp->lt_lacp_mode = new_attr->ld_lacp_mode;
	}

	if (state->us_mask & LAADM_MODIFY_LACP_TIMER) {
		if (old_attr != NULL)
			old_attr->ld_lacp_timer = grp->lt_lacp_timer;
		grp->lt_lacp_timer = new_attr->ld_lacp_timer;
	}

	/* save modified group */
	return (0);
}

static int
i_laadm_modify_db(uint32_t key, uint32_t mask, laadm_modify_attr_t *new,
    laadm_modify_attr_t *old, const char *root, laadm_diag_t *diag)
{
	modify_db_state_t state;

	state.us_key = key;
	state.us_mask = mask;
	state.us_attr_new = new;
	state.us_attr_old = old;
	state.us_found = B_FALSE;

	if (i_laadm_walk_rw_db(i_laadm_modify_db_fn, &state, root,
	    diag) != 0)
		return (-1);

	if (!state.us_found) {
		errno = ENOENT;
		return (-1);
	}

	return (0);
}

/*
 * Add ports to an existing group in the DB.
 */
static int
i_laadm_add_db_fn(void *arg, laadm_grp_attr_db_t *grp)
{
	add_db_state_t *state = arg;
	laadm_grp_attr_db_t *attr = state->as_attr;
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
	    attr->lt_nports) * sizeof (laadm_port_attr_db_t));
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

static int
i_laadm_add_db(laadm_grp_attr_db_t *attr, const char *root,
    laadm_diag_t *diag)
{
	add_db_state_t state;

	state.as_attr = attr;
	state.as_found = B_FALSE;

	if (i_laadm_walk_rw_db(i_laadm_add_db_fn, &state, root,
	    diag) != 0)
		return (-1);

	if (!state.as_found) {
		errno = ENOENT;
		return (-1);
	}

	return (0);
}

/*
 * Remove ports from an existing group in the DB.
 */

typedef struct remove_db_state {
	laadm_grp_attr_db_t *rs_attr;
	boolean_t	rs_found;
} remove_db_state_t;

static int
i_laadm_remove_db_fn(void *arg, laadm_grp_attr_db_t *grp)
{
	remove_db_state_t *state = (remove_db_state_t *)arg;
	laadm_grp_attr_db_t *attr = state->rs_attr;
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

static int
i_laadm_remove_db(laadm_grp_attr_db_t *attr, const char *root,
    laadm_diag_t *diag)
{
	remove_db_state_t state;

	state.rs_attr = attr;
	state.rs_found = B_FALSE;

	if (i_laadm_walk_rw_db(i_laadm_remove_db_fn, &state, root,
	    diag) != 0)
		return (-1);

	if (!state.rs_found) {
		errno = ENOENT;
		return (-1);
	}

	return (0);
}

/*
 * Given a policy string, return a policy mask. Returns B_TRUE on
 * success, or B_FALSE if an error occured during parsing.
 */
boolean_t
laadm_str_to_policy(const char *str, uint32_t *policy)
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
laadm_policy_to_str(uint32_t policy, char *str)
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
laadm_str_to_mac_addr(const char *str, boolean_t *mac_fixed, uchar_t *mac_addr)
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
laadm_mac_addr_to_str(unsigned char *mac, char *buf)
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
laadm_str_to_lacp_mode(const char *str, aggr_lacp_mode_t *lacp_mode)
{
	int i;
	laadm_lacp_mode_t *mode;

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
laadm_lacp_mode_to_str(aggr_lacp_mode_t mode_id)
{
	int i;
	laadm_lacp_mode_t *mode;

	for (i = 0; i < NLACP_MODES; i++) {
		mode = &lacp_modes[i];
		if (mode->mode_id == mode_id)
			return (mode->mode_str);
	}

	return (NULL);
}

/*
 * Given a LACP timer string, find the corresponding LACP timer number. Returns
 * B_TRUE if a match was found, B_FALSE otherwise.
 */
boolean_t
laadm_str_to_lacp_timer(const char *str, aggr_lacp_timer_t *lacp_timer)
{
	int i;
	laadm_lacp_timer_t *timer;

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
laadm_lacp_timer_to_str(aggr_lacp_timer_t timer_id)
{
	int i;
	laadm_lacp_timer_t *timer;

	for (i = 0; i < NLACP_TIMERS; i++) {
		timer = &lacp_timers[i];
		if (timer->lt_id == timer_id)
			return (timer->lt_str);
	}

	return (NULL);
}

#define	FPRINTF_ERR(fcall) if ((fcall) < 0) return (-1);

/*
 * Write the attribute of a group to the specified file. Returns 0 on
 * success, -1 on failure.
 */
static int
i_laadm_fput_grp(FILE *fp, laadm_grp_attr_db_t *attr)
{
	int i;
	char addr_str[ETHERADDRL * 3];
	char policy_str[LAADM_POLICY_STR_LEN];

	/* key, policy */
	FPRINTF_ERR(fprintf(fp, "%d\t%s\t", attr->lt_key,
	    laadm_policy_to_str(attr->lt_policy, policy_str)));

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
		    laadm_mac_addr_to_str(attr->lt_mac, addr_str)));
	}
	FPRINTF_ERR(fprintf(fp, "\t"));

	FPRINTF_ERR(fprintf(fp, "%s\t",
	    laadm_lacp_mode_to_str(attr->lt_lacp_mode)));

	FPRINTF_ERR(fprintf(fp, "%s\n",
	    laadm_lacp_timer_to_str(attr->lt_lacp_timer)));

	return (0);
}

static int
i_laadm_create_db(laadm_grp_attr_db_t *attr, const char *root,
    laadm_diag_t *diag)
{
	FILE *fp;
	char line[MAXLINELEN];
	uint32_t key;
	int 		lock_fd, retval = -1;
	char 		*db_file;
	char 		db_file_buf[MAXPATHLEN];
	char 		*endp = NULL;

	if (root == NULL) {
		db_file = LAADM_DB;
	} else {
		(void) snprintf(db_file_buf, MAXPATHLEN, "%s%s", root,
		    LAADM_DB);
		db_file = db_file_buf;
	}

	if ((lock_fd = i_laadm_lock_db(F_WRLCK)) < 0)
		return (-1);

	if ((fp = fopen(db_file, "r+")) == NULL &&
	    (fp = fopen(db_file, "w")) == NULL) {
		i_laadm_unlock_db(lock_fd);
		*diag = LAADM_DIAG_REPOSITORY_OPENFAIL;
		return (-1);
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
			goto failed;
		}

		if (key == attr->lt_key) {
			/* group with key already exists */
			errno = EEXIST;
			goto failed;
		}
	}

	/*
	 * If we get here, we've verified that no existing group with
	 * the same key already exists. It's now time to add the
	 * new group to the DB.
	 */
	if (i_laadm_fput_grp(fp, attr) != 0)
		goto failed;

	retval = 0;

failed:
	(void) fclose(fp);
	i_laadm_unlock_db(lock_fd);
	return (retval);
}

/*
 * Create a new link aggregation group. Update the configuration
 * file and bring it up.
 */
int
laadm_create(uint32_t key, uint32_t nports, laadm_port_attr_db_t *ports,
    uint32_t policy, boolean_t mac_addr_fixed, uchar_t *mac_addr,
    aggr_lacp_mode_t lacp_mode, aggr_lacp_timer_t lacp_timer, boolean_t tempop,
    const char *root, laadm_diag_t *diag)
{
	laadm_grp_attr_db_t attr;
	int errno_sav;

	if (key == 0 || key > LAADM_MAX_KEY) {
		errno = EINVAL;
		*diag = LAADM_DIAG_INVALID_KEY;
		return (-1);
	}

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
		if (i_laadm_create_db(&attr, root, diag) < 0)
			return (-1);
	} else {
		laadm_up_t up;
		int rc;

		up.lu_key = key;
		up.lu_found = B_FALSE;
		up.lu_fd = open(LAADM_DEV, O_RDWR);
		if (up.lu_fd < 0)
			return (-1);

		rc = i_laadm_up((void *)&up, &attr, diag);
		(void) close(up.lu_fd);
		return (rc);
	}

	/* bring up the link aggregation group */
	if (laadm_up(key, root, diag) < 0) {
		if (errno != EEXIST) {
			errno_sav = errno;
			if (!tempop) {
				(void) i_laadm_delete_db(&attr, root,
				    diag);
			}
			errno = errno_sav;
		}
		return (-1);
	}

	return (0);
}

/*
 * Modify the parameters of an existing link aggregation group. Update
 * the configuration file and pass the changes to the kernel.
 */
int
laadm_modify(uint32_t key, uint32_t modify_mask, uint32_t policy,
    boolean_t mac_fixed, uchar_t *mac_addr, aggr_lacp_mode_t lacp_mode,
    aggr_lacp_timer_t lacp_timer, boolean_t tempop, const char *root,
    laadm_diag_t *diag)
{
	laadm_modify_attr_t new_attr, old_attr;
	int errno_save;

	if (key == 0) {
		errno = EINVAL;
		*diag = LAADM_DIAG_INVALID_KEY;
		return (-1);
	}

	if (modify_mask & LAADM_MODIFY_POLICY)
		new_attr.ld_policy = policy;

	if (modify_mask & LAADM_MODIFY_MAC) {
		new_attr.ld_mac_fixed = mac_fixed;
		bcopy(mac_addr, new_attr.ld_mac, ETHERADDRL);
	}

	if (modify_mask & LAADM_MODIFY_LACP_MODE)
		new_attr.ld_lacp_mode = lacp_mode;

	if (modify_mask & LAADM_MODIFY_LACP_TIMER)
		new_attr.ld_lacp_timer = lacp_timer;

	/* update the DB */
	if (!tempop) {
		if (i_laadm_modify_db(key, modify_mask, &new_attr,
		    &old_attr, root, diag) < 0)
			return (-1);
	}

	if (i_laadm_modify_sys(key, modify_mask, &new_attr,
	    diag) < 0) {
		if (!tempop) {
			errno_save = errno;
			(void) i_laadm_modify_db(key, modify_mask,
			    &old_attr, NULL, root, diag);
			errno = errno_save;
		}
		return (-1);
	}

	return (0);
}

/*
 * Delete a previously created link aggregation group.
 */
int
laadm_delete(uint32_t key, boolean_t tempop, const char *root,
    laadm_diag_t *diag)
{
	laadm_grp_attr_db_t db_attr;

	if (key == 0) {
		errno = EINVAL;
		*diag = LAADM_DIAG_INVALID_KEY;
		return (-1);
	}

	if (tempop) {
		laadm_down_t down;
		laadm_grp_attr_sys_t sys_attr;

		down.ld_key = key;
		down.ld_found = B_FALSE;
		sys_attr.lg_key = key;
		return (i_laadm_down((void *)&down, &sys_attr));
	} else if ((laadm_down(key) < 0) && errno == EBUSY) {
		return (-1);
	}

	db_attr.lt_key = key;

	if (tempop)
		return (0);

	return (i_laadm_delete_db(&db_attr, root, diag));
}

/*
 * Add one or more ports to an existing link aggregation.
 */
int
laadm_add(uint32_t key, uint32_t nports, laadm_port_attr_db_t *ports,
    boolean_t tempop, const char *root, laadm_diag_t *diag)
{
	laadm_grp_attr_db_t attr;
	int errno_save;

	if (key == 0) {
		errno = EINVAL;
		*diag = LAADM_DIAG_INVALID_KEY;
		return (-1);
	}

	bzero(&attr, sizeof (attr));
	attr.lt_key = key;
	attr.lt_nports = nports;
	attr.lt_ports = ports;

	if (!tempop) {
		if (i_laadm_add_db(&attr, root, diag) < 0)
			return (-1);
	}

	if (i_laadm_add_rem_sys(&attr, LAIOC_ADD, diag) < 0) {
		if (!tempop) {
			errno_save = errno;
			(void) i_laadm_remove_db(&attr, root, diag);
			errno = errno_save;
		}
		return (-1);
	}

	return (0);
}

/*
 * Remove one or more ports from an existing link aggregation.
 */
int
laadm_remove(uint32_t key, uint32_t nports, laadm_port_attr_db_t *ports,
    boolean_t tempop, const char *root, laadm_diag_t *diag)
{
	laadm_grp_attr_db_t attr;
	int errno_save;

	if (key == 0) {
		errno = EINVAL;
		*diag = LAADM_DIAG_INVALID_KEY;
		return (-1);
	}

	bzero(&attr, sizeof (attr));
	attr.lt_key = key;
	attr.lt_nports = nports;
	attr.lt_ports = ports;

	if (!tempop) {
		if (i_laadm_remove_db(&attr, root, diag) < 0)
			return (-1);
	}

	if (i_laadm_add_rem_sys(&attr, LAIOC_REMOVE, diag) < 0) {
		if (!tempop) {
			errno_save = errno;
			(void) i_laadm_add_db(&attr, root, diag);
			errno = errno_save;
		}
		return (-1);
	}

	return (0);
}

const char *
laadm_diag(laadm_diag_t diag) {
	switch (diag) {
	case LAADM_DIAG_REPOSITORY_OPENFAIL:
		return (gettext("configuration repository open failed"));
	case LAADM_DIAG_REPOSITORY_PARSEFAIL:
		return (gettext("parsing of configuration repository failed"));
	case LAADM_DIAG_REPOSITORY_CLOSEFAIL:
		return (gettext("configuration repository close failed"));
	case LAADM_DIAG_INVALID_INTFNAME:
		return (gettext("invalid interface name"));
	case LAADM_DIAG_INVALID_MACADDR:
		return (gettext("invalid MAC address"));
	case LAADM_DIAG_INVALID_KEY:
		return (gettext("invalid key"));
	default:
		return (gettext("unknown diagnostic"));
	}
}
