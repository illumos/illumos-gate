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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/dld_ioc.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <libintl.h>
#include <netdb.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <libdlflow.h>
#include <libdlflow_impl.h>
#include <libdladm_impl.h>

/* minimum buffer size for DLDIOCWALKFLOW */
#define	MIN_INFO_SIZE	(4 * 1024)

#define	DLADM_FLOW_DB		"/etc/dladm/flowadm.conf"
#define	DLADM_FLOW_DB_TMP	"/etc/dladm/flowadm.conf.new"
#define	DLADM_FLOW_DB_LOCK	"/tmp/flowadm.conf.lock"

#define	DLADM_FLOW_DB_PERMS	S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH
#define	DLADM_FLOW_DB_OWNER	UID_DLADM
#define	DLADM_FLOW_DB_GROUP	GID_NETADM

#define	BLANK_LINE(s)	((s[0] == '\0') || (s[0] == '#') || (s[0] == '\n'))
#define	MAXLINELEN	1024
#define	MAXPATHLEN	1024

/* database file parameters */
static const char *BW_LIMIT = "bw_limit";
static const char *PRIORITY = "priority";
static const char *LOCAL_IP_ADDR = "local_ip";
static const char *REMOTE_IP_ADDR = "remote_ip";
static const char *TRANSPORT = "transport";
static const char *LOCAL_PORT = "local_port";
static const char *REMOTE_PORT = "remote_port";
static const char *DSFIELD = "dsfield";

/*
 * Open and lock the flowadm configuration file lock. The lock is
 * acquired as a reader (F_RDLCK) or writer (F_WRLCK).
 */
static int
i_dladm_flow_lock_db(short type)
{
	int lock_fd;
	struct flock lock;

	if ((lock_fd = open(DLADM_FLOW_DB_LOCK, O_RDWR | O_CREAT | O_TRUNC,
	    DLADM_FLOW_DB_PERMS)) < 0)
		return (-1);

	lock.l_type = type;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(lock_fd, F_SETLKW, &lock) < 0) {
		(void) close(lock_fd);
		(void) unlink(DLADM_FLOW_DB_LOCK);
		return (-1);
	}
	return (lock_fd);
}

/*
 * Unlock and close the specified file.
 */
static void
i_dladm_flow_unlock_db(int fd)
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
	(void) unlink(DLADM_FLOW_DB_LOCK);
}

/*
 * Parse one line of the link flowadm DB
 * Returns -1 on failure, 0 on success.
 */
dladm_status_t
dladm_flow_parse_db(char *line, dld_flowinfo_t *attr)
{
	char		*token;
	char		*value, *name = NULL;
	char		*lasts = NULL;
	dladm_status_t	status = DLADM_STATUS_FLOW_DB_PARSE_ERR;

	bzero(attr, sizeof (*attr));

	/* flow name */
	if ((token = strtok_r(line, " \t", &lasts)) == NULL)
		goto done;

	if (strlcpy(attr->fi_flowname, token, MAXFLOWNAMELEN) >= MAXFLOWNAMELEN)
		goto done;

	/* resource control and flow descriptor parameters */
	while ((token = strtok_r(NULL, " \t", &lasts)) != NULL) {
		if ((name = strdup(token)) == NULL)
			goto done;

		(void) strtok(name, "=");
		value = strtok(NULL, "=");
		if (value == NULL)
			goto done;

		if (strcmp(name, "linkid") == 0) {
			if ((attr->fi_linkid =
			    (uint32_t)strtol(value, NULL, 10)) ==
			    DATALINK_INVALID_LINKID)
				goto done;

		} else if (strcmp(name, BW_LIMIT) == 0) {
			attr->fi_resource_props.mrp_mask |=
			    MRP_MAXBW;
			attr->fi_resource_props.mrp_maxbw =
			    (uint64_t)strtol(value, NULL, 0);

		} else if (strcmp(name, PRIORITY) == 0) {
			attr->fi_resource_props.mrp_mask |= MRP_PRIORITY;
			status = dladm_str2pri(value,
			    &attr->fi_resource_props.mrp_priority);
			if (status != DLADM_STATUS_OK)
				goto done;

		} else if (strcmp(name, DSFIELD) == 0) {
			status = do_check_dsfield(value,
			    &attr->fi_flow_desc);
			if (status != DLADM_STATUS_OK)
				goto done;

		} else if (strcmp(name, LOCAL_IP_ADDR) == 0) {
			status = do_check_ip_addr(value, B_TRUE,
			    &attr->fi_flow_desc);
			if (status != DLADM_STATUS_OK)
				goto done;

		} else if (strcmp(name, REMOTE_IP_ADDR) == 0) {
			status = do_check_ip_addr(value, B_FALSE,
			    &attr->fi_flow_desc);
			if (status != DLADM_STATUS_OK)
				goto done;

		} else if (strcmp(name, TRANSPORT) == 0) {
			attr->fi_flow_desc.fd_mask |= FLOW_IP_PROTOCOL;
			attr->fi_flow_desc.fd_protocol =
			    (uint8_t)strtol(value, NULL, 0);

		} else if (strcmp(name, LOCAL_PORT) == 0) {
			attr->fi_flow_desc.fd_mask |= FLOW_ULP_PORT_LOCAL;
			attr->fi_flow_desc.fd_local_port =
			    (uint16_t)strtol(value, NULL, 10);
			attr->fi_flow_desc.fd_local_port =
			    htons(attr->fi_flow_desc.fd_local_port);
		} else if (strcmp(name, REMOTE_PORT) == 0) {
			attr->fi_flow_desc.fd_mask |= FLOW_ULP_PORT_REMOTE;
			attr->fi_flow_desc.fd_remote_port =
			    (uint16_t)strtol(value, NULL, 10);
			attr->fi_flow_desc.fd_remote_port =
			    htons(attr->fi_flow_desc.fd_remote_port);
		}
		free(name);
		name = NULL;
	}
	if (attr->fi_linkid != DATALINK_INVALID_LINKID)
		status = DLADM_STATUS_OK;
done:
	free(name);
	return (status);
}

#define	FPRINTF_ERR(fcall) if ((fcall) < 0) return (-1);

/*
 * Write the attribute of a group to the specified file. Returns 0 on
 * success, -1 on failure.
 */
static int
i_dladm_flow_fput_grp(FILE *fp, dld_flowinfo_t *attr)
{

	FPRINTF_ERR(fprintf(fp, "%s\tlinkid=%d\t",
	    attr->fi_flowname, attr->fi_linkid));

	/* flow policy */
	if (attr->fi_resource_props.mrp_mask & MRP_MAXBW)
		FPRINTF_ERR(fprintf(fp, "%s=%" PRIu64 "\t", BW_LIMIT,
		    attr->fi_resource_props.mrp_maxbw));

	if (attr->fi_resource_props.mrp_mask & MRP_PRIORITY)
		FPRINTF_ERR(fprintf(fp, "%s=%d\t", PRIORITY,
		    attr->fi_resource_props.mrp_priority));

	/* flow descriptor */
	if (attr->fi_flow_desc.fd_mask & FLOW_IP_DSFIELD)
		FPRINTF_ERR(fprintf(fp, "%s=%x:%x\t", DSFIELD,
		    attr->fi_flow_desc.fd_dsfield,
		    attr->fi_flow_desc.fd_dsfield_mask));

	if (attr->fi_flow_desc.fd_mask & FLOW_IP_LOCAL) {
		char abuf[INET6_ADDRSTRLEN], *ap;
		struct in_addr ipaddr;
		int prefix_len, prefix_max;

		if (attr->fi_flow_desc.fd_ipversion != 6) {
			ipaddr.s_addr =
			    attr->fi_flow_desc.
			    fd_local_addr._S6_un._S6_u32[3];

			ap = inet_ntoa(ipaddr);
			prefix_max = IP_ABITS;
		} else {
			(void) inet_ntop(AF_INET6,
			    &attr->fi_flow_desc.fd_local_addr,
			    abuf, INET6_ADDRSTRLEN);

			ap = abuf;
			prefix_max = IPV6_ABITS;
		}
		(void) dladm_mask2prefixlen(
		    &attr->fi_flow_desc.fd_local_netmask, prefix_max,
		    &prefix_len);

		FPRINTF_ERR(fprintf(fp, "%s=%s/%d\t", LOCAL_IP_ADDR,
		    ap, prefix_len));
	}
	if (attr->fi_flow_desc.fd_mask & FLOW_IP_REMOTE) {
		char abuf[INET6_ADDRSTRLEN], *ap;
		struct in_addr ipaddr;
		int prefix_len, prefix_max;

		if (attr->fi_flow_desc.fd_ipversion != 6) {
			ipaddr.s_addr =
			    attr->fi_flow_desc.
			    fd_remote_addr._S6_un._S6_u32[3];

			ap = inet_ntoa(ipaddr);
			prefix_max = IP_ABITS;
		} else {
			(void) inet_ntop(AF_INET6,
			    &(attr->fi_flow_desc.fd_remote_addr),
			    abuf, INET6_ADDRSTRLEN);

			ap = abuf;
			prefix_max = IPV6_ABITS;
		}
		(void) dladm_mask2prefixlen(
		    &attr->fi_flow_desc.fd_remote_netmask, prefix_max,
		    &prefix_len);

		FPRINTF_ERR(fprintf(fp, "%s=%s/%d\t", REMOTE_IP_ADDR,
		    ap, prefix_len));
	}
	if (attr->fi_flow_desc.fd_mask & FLOW_IP_PROTOCOL)
		FPRINTF_ERR(fprintf(fp, "%s=%d\t", TRANSPORT,
		    attr->fi_flow_desc.fd_protocol));

	if (attr->fi_flow_desc.fd_mask & FLOW_ULP_PORT_LOCAL)
		FPRINTF_ERR(fprintf(fp, "%s=%d\t", LOCAL_PORT,
		    ntohs(attr->fi_flow_desc.fd_local_port)));

	if (attr->fi_flow_desc.fd_mask & FLOW_ULP_PORT_REMOTE)
		FPRINTF_ERR(fprintf(fp, "%s=%d\t", REMOTE_PORT,
		    ntohs(attr->fi_flow_desc.fd_remote_port)));

	FPRINTF_ERR(fprintf(fp, "\n"));

	return (0);

}

static dladm_status_t
i_dladm_flow_walk_rw_db(int (*fn)(void *, dld_flowinfo_t *),
    void *arg,
    const char *root)
{
	FILE *fp, *nfp;
	int nfd, fn_rc, lock_fd;
	char line[MAXLINELEN];
	dld_flowinfo_t attr;
	char *db_file, *tmp_db_file;
	char db_file_buf[MAXPATHLEN];
	char tmp_db_file_buf[MAXPATHLEN];
	dladm_status_t	status = DLADM_STATUS_FLOW_DB_ERR;

	if (root == NULL) {
		db_file = DLADM_FLOW_DB;
		tmp_db_file = DLADM_FLOW_DB_TMP;
	} else {
		(void) snprintf(db_file_buf, MAXPATHLEN, "%s%s", root,
		    DLADM_FLOW_DB);
		(void) snprintf(tmp_db_file_buf, MAXPATHLEN, "%s%s", root,
		    DLADM_FLOW_DB_TMP);
		db_file = db_file_buf;
		tmp_db_file = tmp_db_file_buf;
	}

	if ((lock_fd = i_dladm_flow_lock_db(F_WRLCK)) < 0)
		return (DLADM_STATUS_FLOW_DB_ERR);

	if ((fp = fopen(db_file, "r")) == NULL) {
		i_dladm_flow_unlock_db(lock_fd);
		return (DLADM_STATUS_FLOW_DB_OPEN_ERR);
	}

	if ((nfd = open(tmp_db_file, O_WRONLY|O_CREAT|O_TRUNC,
	    DLADM_FLOW_DB_PERMS)) == -1) {
		(void) fclose(fp);
		i_dladm_flow_unlock_db(lock_fd);
		return (DLADM_STATUS_FLOW_DB_OPEN_ERR);
	}

	if ((nfp = fdopen(nfd, "w")) == NULL) {
		(void) close(nfd);
		(void) fclose(fp);
		(void) unlink(tmp_db_file);
		i_dladm_flow_unlock_db(lock_fd);
		return (DLADM_STATUS_FLOW_DB_OPEN_ERR);
	}

	while (fgets(line, MAXLINELEN, fp) != NULL) {

		/* skip comments */
		if (BLANK_LINE(line)) {
			if (fputs(line, nfp) == EOF)
				goto failed;
			continue;
		}
		(void) strtok(line, " \n");

		if ((status = dladm_flow_parse_db(line, &attr)) !=
		    DLADM_STATUS_OK)
			goto failed;

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
			if (i_dladm_flow_fput_grp(nfp, &attr) != 0)
				goto failed;
			break;
		case 1:
			/* skip current group */
			break;
		}
	}
	if (fchmod(nfd, DLADM_FLOW_DB_PERMS) == -1)
		goto failed;

	if (fchown(nfd, DLADM_FLOW_DB_OWNER, DLADM_FLOW_DB_GROUP) == -1)
		goto failed;

	if (fflush(nfp) == EOF)
		goto failed;

	(void) fclose(fp);
	(void) fclose(nfp);

	if (rename(tmp_db_file, db_file) == -1) {
		(void) unlink(tmp_db_file);
		i_dladm_flow_unlock_db(lock_fd);
		return (DLADM_STATUS_FLOW_DB_ERR);
	}
	i_dladm_flow_unlock_db(lock_fd);
	return (DLADM_STATUS_OK);

failed:
	(void) fclose(fp);
	(void) fclose(nfp);
	(void) unlink(tmp_db_file);
	i_dladm_flow_unlock_db(lock_fd);

	return (status);
}

/*
 * Remove existing flow from DB.
 */

typedef struct remove_db_state {
	dld_flowinfo_t	rs_newattr;
	dld_flowinfo_t	rs_oldattr;
	boolean_t	rs_found;
} remove_db_state_t;

static int
i_dladm_flow_remove_db_fn(void *arg, dld_flowinfo_t *grp)
{
	remove_db_state_t *state = (remove_db_state_t *)arg;
	dld_flowinfo_t *attr = &state->rs_newattr;

	if ((strcmp(grp->fi_flowname, attr->fi_flowname)) != 0)
		return (0);
	else {
		bcopy(grp, &state->rs_oldattr,
		    sizeof (dld_flowinfo_t));
		state->rs_found = B_TRUE;
		return (1);
	}
}

/* ARGSUSED */
static int
i_dladm_flow_remove_db(remove_db_state_t *state, const char *root)
{
	if (i_dladm_flow_walk_rw_db(i_dladm_flow_remove_db_fn, state, root)
	    != 0)
		return (-1);

	if (!state->rs_found) {
		errno = ENOENT;
		return (-1);
	}

	return (0);
}

/*
 * Create a flow in the DB.
 */

typedef struct modify_db_state {
	dld_flowinfo_t	ms_newattr;
	dld_flowinfo_t	ms_oldattr;
	boolean_t	ms_found;
} modify_db_state_t;

static dladm_status_t
i_dladm_flow_create_db(dld_flowinfo_t *attr, const char *root)
{
	FILE	*fp;
	char	line[MAXLINELEN];
	char	*db_file;
	char	db_file_buf[MAXPATHLEN];
	int	lock_fd;
	dladm_status_t	status = DLADM_STATUS_OK;

	if (root == NULL) {
		db_file = DLADM_FLOW_DB;
	} else {
		(void) snprintf(db_file_buf, MAXPATHLEN, "%s%s", root,
		    DLADM_FLOW_DB);
		db_file = db_file_buf;
	}

	if ((lock_fd = i_dladm_flow_lock_db(F_WRLCK)) < 0)
		return (DLADM_STATUS_FLOW_DB_ERR);

	if ((fp = fopen(db_file, "r+")) == NULL &&
	    (fp = fopen(db_file, "w")) == NULL) {
		i_dladm_flow_unlock_db(lock_fd);
		return (DLADM_STATUS_FLOW_DB_OPEN_ERR);
	}

	/* look for existing group with same flowname */
	while (fgets(line, MAXLINELEN, fp) != NULL) {
		char *holder, *lasts;

		/* skip comments */
		if (BLANK_LINE(line))
			continue;

		/* ignore corrupted lines */
		holder = strtok_r(line, " \t", &lasts);
		if (holder == NULL)
			continue;

		/* flow id */
		if (strcmp(holder, attr->fi_flowname) == 0) {
			/* group with flow id already exists */
			status = DLADM_STATUS_PERSIST_FLOW_EXISTS;
			goto failed;
		}
	}
	/*
	 * If we get here, we've verified that no existing group with
	 * the same flow id already exists. Its now time to add the new
	 * group to the DB.
	 */
	if (i_dladm_flow_fput_grp(fp, attr) != 0)
		status = DLADM_STATUS_FLOW_DB_PARSE_ERR;

failed:
	(void) fclose(fp);
	i_dladm_flow_unlock_db(lock_fd);
	return (status);
}

static dladm_status_t
i_dladm_flow_add(dladm_handle_t handle, char *flowname, datalink_id_t linkid,
    flow_desc_t *flowdesc, mac_resource_props_t *mrp)
{
	dld_ioc_addflow_t	attr;

	/* create flow */
	bzero(&attr, sizeof (attr));
	bcopy(flowdesc, &attr.af_flow_desc, sizeof (flow_desc_t));
	if (mrp != NULL) {
		bcopy(mrp, &attr.af_resource_props,
		    sizeof (mac_resource_props_t));
	}

	(void) strlcpy(attr.af_name, flowname, sizeof (attr.af_name));
	attr.af_linkid = linkid;

	if (ioctl(dladm_dld_fd(handle), DLDIOC_ADDFLOW, &attr) < 0)
		return (dladm_errno2status(errno));

	return (DLADM_STATUS_OK);
}

static dladm_status_t
i_dladm_flow_remove(dladm_handle_t handle, char *flowname)
{
	dld_ioc_removeflow_t	attr;
	dladm_status_t		status = DLADM_STATUS_OK;

	(void) strlcpy(attr.rf_name, flowname,
	    sizeof (attr.rf_name));

	if (ioctl(dladm_dld_fd(handle), DLDIOC_REMOVEFLOW, &attr) < 0)
		status = dladm_errno2status(errno);

	return (status);
}


/* ARGSUSED */
dladm_status_t
dladm_flow_add(dladm_handle_t handle, datalink_id_t linkid,
    dladm_arg_list_t *attrlist, dladm_arg_list_t *proplist, char *flowname,
    boolean_t tempop, const char *root)
{
	dld_flowinfo_t		db_attr;
	flow_desc_t		flowdesc;
	mac_resource_props_t	mrp;
	dladm_status_t		status;

	/* Extract flow attributes from attrlist */
	bzero(&flowdesc, sizeof (flow_desc_t));
	if (attrlist != NULL && (status = dladm_flow_attrlist_extract(attrlist,
	    &flowdesc)) != DLADM_STATUS_OK) {
		return (status);
	}

	/* Extract resource_ctl and cpu_list from proplist */
	bzero(&mrp, sizeof (mac_resource_props_t));
	if (proplist != NULL && (status = dladm_flow_proplist_extract(proplist,
	    &mrp)) != DLADM_STATUS_OK) {
		return (status);
	}

	/* Add flow in kernel */
	status = i_dladm_flow_add(handle, flowname, linkid, &flowdesc, &mrp);
	if (status != DLADM_STATUS_OK)
		return (status);

	/* Add flow to DB */
	if (!tempop) {
		bzero(&db_attr, sizeof (db_attr));
		bcopy(&flowdesc, &db_attr.fi_flow_desc, sizeof (flow_desc_t));
		(void) strlcpy(db_attr.fi_flowname, flowname,
		    sizeof (db_attr.fi_flowname));
		db_attr.fi_linkid = linkid;

		if ((status = i_dladm_flow_create_db(&db_attr, root)) !=
		    DLADM_STATUS_OK) {
			(void) i_dladm_flow_remove(handle, flowname);
			return (status);
		}
		/* set flow properties */
		if (proplist != NULL) {
			status = i_dladm_set_flow_proplist_db(handle, flowname,
			    proplist);
			if (status != DLADM_STATUS_OK) {
				(void) i_dladm_flow_remove(handle, flowname);
				return (status);
			}
		}
	}
	return (status);
}

/*
 * Remove a flow.
 */
/* ARGSUSED */
dladm_status_t
dladm_flow_remove(dladm_handle_t handle, char *flowname, boolean_t tempop,
    const char *root)
{
	remove_db_state_t		state;
	dladm_status_t			status = DLADM_STATUS_OK;
	dladm_status_t			s = DLADM_STATUS_OK;

	/* remove flow */
	status = i_dladm_flow_remove(handle, flowname);
	if ((status != DLADM_STATUS_OK) &&
	    (tempop || status != DLADM_STATUS_NOTFOUND))
		goto done;

	/* remove flow from DB */
	if (!tempop) {
		bzero(&state, sizeof (state));
		(void) strlcpy(state.rs_newattr.fi_flowname, flowname,
		    sizeof (state.rs_newattr.fi_flowname));
		state.rs_found = B_FALSE;

		/* flow DB */
		if (i_dladm_flow_remove_db(&state, root) < 0) {
			s = dladm_errno2status(errno);
			goto done;
		}

		/* flow prop DB */
		s = dladm_set_flowprop(handle, flowname, NULL, NULL, 0,
		    DLADM_OPT_PERSIST, NULL);
	}

done:
	if (!tempop) {
		if (s == DLADM_STATUS_OK) {
			if (status == DLADM_STATUS_NOTFOUND)
				status = s;
		} else {
			if (s != DLADM_STATUS_NOTFOUND)
				status = s;
		}
	}
	return (status);
}

/*
 * Get an existing flow in the DB.
 */

typedef struct get_db_state {
	int		(*gs_fn)(dladm_handle_t, dladm_flow_attr_t *, void *);
	void		*gs_arg;
	datalink_id_t	gs_linkid;
} get_db_state_t;

/*
 * For each flow which matches the linkid, copy all flow information
 * to a new dladm_flow_attr_t structure and call the provided
 * function.  This is used to display perisistent flows from
 * the database.
 */

static int
i_dladm_flow_get_db_fn(void *arg, dld_flowinfo_t *grp)
{
	get_db_state_t		*state = (get_db_state_t *)arg;
	dladm_flow_attr_t	attr;
	dladm_handle_t		handle = NULL;

	if (grp->fi_linkid == state->gs_linkid) {
		attr.fa_linkid = state->gs_linkid;
		bcopy(grp->fi_flowname, &attr.fa_flowname,
		    sizeof (attr.fa_flowname));
		bcopy(&grp->fi_flow_desc, &attr.fa_flow_desc,
		    sizeof (attr.fa_flow_desc));
		bcopy(&grp->fi_resource_props, &attr.fa_resource_props,
		    sizeof (attr.fa_resource_props));
		(void) state->gs_fn(handle, &attr, state->gs_arg);
	}
	return (0);
}

/*
 * Walk through the flows defined on the system and for each flow
 * invoke <fn>(<arg>, <flow>);
 * Currently used for show-flow.
 */
/* ARGSUSED */
dladm_status_t
dladm_walk_flow(int (*fn)(dladm_handle_t, dladm_flow_attr_t *, void *),
    dladm_handle_t handle, datalink_id_t linkid, void *arg, boolean_t persist)
{
	dld_flowinfo_t		*flow;
	uint_t			i, bufsize;
	dld_ioc_walkflow_t	*ioc = NULL;
	dladm_flow_attr_t	attr;
	dladm_status_t		status = DLADM_STATUS_OK;

	if (fn == NULL)
		return (DLADM_STATUS_BADARG);

	if (persist) {
		get_db_state_t state;

		bzero(&state, sizeof (state));

		state.gs_linkid = linkid;
		state.gs_fn = fn;
		state.gs_arg = arg;
		status = i_dladm_flow_walk_rw_db(i_dladm_flow_get_db_fn,
		    &state, NULL);
		if (status != DLADM_STATUS_OK)
			return (status);
	} else {
		bufsize = MIN_INFO_SIZE;
		if ((ioc = calloc(1, bufsize)) == NULL) {
			status = dladm_errno2status(errno);
			return (status);
		}

		ioc->wf_linkid = linkid;
		ioc->wf_len = bufsize - sizeof (*ioc);

		while (ioctl(dladm_dld_fd(handle), DLDIOC_WALKFLOW, ioc) < 0) {
			if (errno == ENOSPC) {
				bufsize *= 2;
				ioc = realloc(ioc, bufsize);
				if (ioc != NULL) {
					ioc->wf_linkid = linkid;
					ioc->wf_len = bufsize - sizeof (*ioc);
					continue;
				}
			}
			goto bail;
		}

		flow = (dld_flowinfo_t *)(void *)(ioc + 1);
		for (i = 0; i < ioc->wf_nflows; i++, flow++) {
			bzero(&attr, sizeof (attr));

			attr.fa_linkid = flow->fi_linkid;
			bcopy(&flow->fi_flowname, &attr.fa_flowname,
			    sizeof (attr.fa_flowname));
			bcopy(&flow->fi_flow_desc, &attr.fa_flow_desc,
			    sizeof (attr.fa_flow_desc));
			bcopy(&flow->fi_resource_props, &attr.fa_resource_props,
			    sizeof (attr.fa_resource_props));

			if (fn(handle, &attr, arg) == DLADM_WALK_TERMINATE)
				break;
		}
	}

bail:
	free(ioc);
	return (status);
}

dladm_status_t
dladm_flow_init(dladm_handle_t handle)
{
	flow_desc_t		flowdesc;
	datalink_id_t		linkid;
	dladm_status_t		s, status = DLADM_STATUS_OK;
	char			name[MAXFLOWNAMELEN];
	char			line[MAXLINELEN];
	dld_flowinfo_t		attr;
	FILE			*fp;

	if ((fp = fopen(DLADM_FLOW_DB, "r")) == NULL)
		return (DLADM_STATUS_DB_NOTFOUND);

	while (fgets(line, MAXLINELEN, fp) != NULL) {
		/* skip comments */
		if (BLANK_LINE(line))
			continue;

		(void) strtok(line, " \n");

		s = dladm_flow_parse_db(line, &attr);
		if (s != DLADM_STATUS_OK) {
			status = s;
			continue;
		}
		bzero(&flowdesc, sizeof (flowdesc));
		bcopy(&attr.fi_flow_desc, &flowdesc, sizeof (flow_desc_t));
		(void) strlcpy(name, attr.fi_flowname,
		    sizeof (attr.fi_flowname));
		linkid = attr.fi_linkid;

		s = i_dladm_flow_add(handle, name, linkid, &flowdesc, NULL);
		if (s != DLADM_STATUS_OK)
			status = s;
	}
	s = i_dladm_init_flowprop_db(handle);
	if (s != DLADM_STATUS_OK)
		status = s;

	(void) fclose(fp);
	return (status);
}

dladm_status_t
dladm_prefixlen2mask(int prefixlen, int maxlen, uchar_t *mask)
{
	if (prefixlen < 0 || prefixlen > maxlen)
		return (DLADM_STATUS_BADARG);

	while (prefixlen > 0) {
		if (prefixlen >= 8) {
			*mask++ = 0xFF;
			prefixlen -= 8;
			continue;
		}
		*mask |= 1 << (8 - prefixlen);
		prefixlen--;
	}
	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_mask2prefixlen(in6_addr_t *mask, int plen, int *prefixlen)
{
	int		bits;
	int		i, end;

	switch (plen) {
	case IP_ABITS:
		end = 3;
		break;
	case IPV6_ABITS:
		end = 0;
		break;
	default:
		return (DLADM_STATUS_BADARG);
	}

	for (i = 3; i >= end; i--) {
		if (mask->_S6_un._S6_u32[i] == 0) {
			plen -= 32;
			continue;
		}
		bits = ffs(ntohl(mask->_S6_un._S6_u32[i])) - 1;
		if (bits == 0)
			break;
		plen -= bits;
	}
	*prefixlen = plen;
	return (DLADM_STATUS_OK);
}
