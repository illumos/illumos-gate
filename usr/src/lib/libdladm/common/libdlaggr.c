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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <strings.h>
#include <libintl.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <sys/dld.h>
#include <libdllink.h>
#include <libdlvlan.h>
#include <libdlaggr.h>
#include <libdladm_impl.h>

/*
 * Link Aggregation Administration Library.
 *
 * This library is used by administration tools such as dladm(8) to
 * configure link aggregations.
 */

/* Limits on buffer size for LAIOC_INFO request */
#define	MIN_INFO_SIZE (4*1024)
#define	MAX_INFO_SIZE (128*1024)

static uchar_t	zero_mac[] = {0, 0, 0, 0, 0, 0};
#define	VALID_PORT_MAC(mac)						\
	(((mac) != NULL) && (bcmp(zero_mac, (mac), ETHERADDRL) != 0) &&	\
	(!((mac)[0] & 0x01)))

#define	PORT_DELIMITER	":"

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

static dladm_status_t
write_port(dladm_handle_t handle, char *portstr, datalink_id_t portid,
    size_t portstrsize)
{
	char		pname[MAXLINKNAMELEN + 1];
	dladm_status_t	status;

	if ((status = dladm_datalink_id2info(handle, portid, NULL, NULL, NULL,
	    pname, sizeof (pname))) != DLADM_STATUS_OK)
		return (status);
	(void) strlcat(pname, PORT_DELIMITER, sizeof (pname));
	if (strlcat(portstr, pname, portstrsize) >= portstrsize)
		status = DLADM_STATUS_TOOSMALL;
	return (status);
}

static dladm_status_t
read_port(dladm_handle_t handle, char **portstr, datalink_id_t *portid)
{
	dladm_status_t	status;
	char		*pname;

	if ((pname = strtok(*portstr, PORT_DELIMITER)) == NULL)
		return (DLADM_STATUS_REPOSITORYINVAL);
	*portstr += (strlen(pname) + 1);
	status = dladm_name2info(handle, pname, portid, NULL, NULL, NULL);
	return (status);
}

static int
i_dladm_aggr_ioctl(dladm_handle_t handle, int cmd, void *ptr)
{
	return (ioctl(dladm_dld_fd(handle), cmd, ptr));
}

/*
 * Caller must free attr.lg_ports. The ptr pointer is advanced while convert
 * the laioc_info_t to the dladm_aggr_grp_attr_t structure.
 */
static int
i_dladm_aggr_iocp2grpattr(void **ptr, dladm_aggr_grp_attr_t *attrp)
{
	laioc_info_group_t	*grp;
	laioc_info_port_t	*port;
	int			i;
	void			*where = (*ptr);

	grp = (laioc_info_group_t *)where;

	attrp->lg_linkid = grp->lg_linkid;
	attrp->lg_key = grp->lg_key;
	attrp->lg_nports = grp->lg_nports;
	attrp->lg_policy = grp->lg_policy;
	attrp->lg_lacp_mode = grp->lg_lacp_mode;
	attrp->lg_lacp_timer = grp->lg_lacp_timer;
	attrp->lg_force = grp->lg_force;

	bcopy(grp->lg_mac, attrp->lg_mac, ETHERADDRL);
	attrp->lg_mac_fixed = grp->lg_mac_fixed;

	if ((attrp->lg_ports = malloc(grp->lg_nports *
	    sizeof (dladm_aggr_port_attr_t))) == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	where = (grp + 1);

	/*
	 * Go through each port that is part of the group.
	 */
	for (i = 0; i < grp->lg_nports; i++) {
		port = (laioc_info_port_t *)where;

		attrp->lg_ports[i].lp_linkid = port->lp_linkid;
		bcopy(port->lp_mac, attrp->lg_ports[i].lp_mac, ETHERADDRL);
		attrp->lg_ports[i].lp_state = port->lp_state;
		attrp->lg_ports[i].lp_lacp_state = port->lp_lacp_state;

		where = (port + 1);
	}
	*ptr = where;
	return (0);
fail:
	return (-1);
}

/*
 * Get active configuration of a specific aggregation.
 * Caller must free attrp->la_ports.
 */
static dladm_status_t
i_dladm_aggr_info_active(dladm_handle_t handle, datalink_id_t linkid,
    dladm_aggr_grp_attr_t *attrp)
{
	laioc_info_t *ioc;
	int bufsize;
	void *where;
	dladm_status_t status = DLADM_STATUS_OK;

	bufsize = MIN_INFO_SIZE;
	ioc = (laioc_info_t *)calloc(1, bufsize);
	if (ioc == NULL)
		return (DLADM_STATUS_NOMEM);

	ioc->li_group_linkid = linkid;

tryagain:
	ioc->li_bufsize = bufsize;
	if (i_dladm_aggr_ioctl(handle, LAIOC_INFO, ioc) != 0) {
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
		status = dladm_errno2status(errno);
		goto bail;
	}

	/*
	 * Go through each group returned by the aggregation driver.
	 */
	where = (char *)(ioc + 1);
	if (i_dladm_aggr_iocp2grpattr(&where, attrp) != 0) {
		status = dladm_errno2status(errno);
		goto bail;
	}

bail:
	free(ioc);
	return (status);
}

/*
 * Get configuration information of a specific aggregation.
 * Caller must free attrp->la_ports.
 */
static dladm_status_t
i_dladm_aggr_info_persist(dladm_handle_t handle, datalink_id_t linkid,
    dladm_aggr_grp_attr_t *attrp)
{
	dladm_conf_t	conf;
	uint32_t	nports, i;
	char		*portstr = NULL, *next;
	dladm_status_t	status;
	uint64_t	u64;
	int		size;
	char		macstr[ETHERADDRL * 3];

	attrp->lg_linkid = linkid;
	if ((status = dladm_getsnap_conf(handle, linkid, &conf)) !=
	    DLADM_STATUS_OK)
		return (status);

	status = dladm_get_conf_field(handle, conf, FKEY, &u64, sizeof (u64));
	if (status != DLADM_STATUS_OK)
		goto done;
	attrp->lg_key = (uint16_t)u64;

	status = dladm_get_conf_field(handle, conf, FPOLICY, &u64,
	    sizeof (u64));
	if (status != DLADM_STATUS_OK)
		goto done;
	attrp->lg_policy = (uint32_t)u64;

	status = dladm_get_conf_field(handle, conf, FFIXMACADDR,
	    &attrp->lg_mac_fixed, sizeof (boolean_t));
	if (status != DLADM_STATUS_OK)
		goto done;

	if (attrp->lg_mac_fixed) {
		boolean_t fixed;

		if ((status = dladm_get_conf_field(handle, conf, FMACADDR,
		    macstr, sizeof (macstr))) != DLADM_STATUS_OK) {
			goto done;
		}
		if (!dladm_aggr_str2macaddr(macstr, &fixed, attrp->lg_mac)) {
			status = DLADM_STATUS_REPOSITORYINVAL;
			goto done;
		}
	}

	status = dladm_get_conf_field(handle, conf, FFORCE, &attrp->lg_force,
	    sizeof (boolean_t));
	if (status != DLADM_STATUS_OK)
		goto done;

	status = dladm_get_conf_field(handle, conf, FLACPMODE, &u64,
	    sizeof (u64));
	if (status != DLADM_STATUS_OK)
		goto done;
	attrp->lg_lacp_mode = (aggr_lacp_mode_t)u64;

	status = dladm_get_conf_field(handle, conf, FLACPTIMER, &u64,
	    sizeof (u64));
	if (status != DLADM_STATUS_OK)
		goto done;
	attrp->lg_lacp_timer = (aggr_lacp_timer_t)u64;

	status = dladm_get_conf_field(handle, conf, FNPORTS, &u64,
	    sizeof (u64));
	if (status != DLADM_STATUS_OK)
		goto done;
	nports = (uint32_t)u64;
	attrp->lg_nports = nports;

	size = nports * (MAXLINKNAMELEN + 1) + 1;
	if ((portstr = calloc(1, size)) == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	status = dladm_get_conf_field(handle, conf, FPORTS, portstr, size);
	if (status != DLADM_STATUS_OK)
		goto done;

	if ((attrp->lg_ports = malloc(nports *
	    sizeof (dladm_aggr_port_attr_t))) == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	for (next = portstr, i = 0; i < nports; i++) {
		if ((status = read_port(handle, &next,
		    &attrp->lg_ports[i].lp_linkid)) != DLADM_STATUS_OK)
			free(attrp->lg_ports);
	}

done:
	free(portstr);
	dladm_destroy_conf(handle, conf);
	return (status);
}

dladm_status_t
dladm_aggr_info(dladm_handle_t handle, datalink_id_t linkid,
    dladm_aggr_grp_attr_t *attrp, uint32_t flags)
{
	assert(flags == DLADM_OPT_ACTIVE || flags == DLADM_OPT_PERSIST);
	if (flags == DLADM_OPT_ACTIVE)
		return (i_dladm_aggr_info_active(handle, linkid, attrp));
	else
		return (i_dladm_aggr_info_persist(handle, linkid, attrp));
}

/*
 * Add or remove one or more ports to/from an existing link aggregation.
 */
static dladm_status_t
i_dladm_aggr_add_rmv(dladm_handle_t handle, datalink_id_t linkid,
    uint32_t nports, dladm_aggr_port_attr_db_t *ports, uint32_t flags, int cmd)
{
	char *orig_portstr = NULL, *portstr = NULL;
	laioc_add_rem_t *iocp = NULL;
	laioc_port_t *ioc_ports;
	uint32_t orig_nports, result_nports, len, i, j;
	dladm_conf_t conf;
	datalink_class_t class;
	dladm_status_t status = DLADM_STATUS_OK;
	int size;
	uint64_t u64;
	uint32_t media;

	if (nports == 0)
		return (DLADM_STATUS_BADARG);

	/*
	 * Sanity check - aggregations can only be created over Ethernet
	 * physical links and simnets.
	 */
	for (i = 0; i < nports; i++) {
		if ((dladm_datalink_id2info(handle, ports[i].lp_linkid, NULL,
		    &class, &media, NULL, 0) != DLADM_STATUS_OK) ||
		    !((class == DATALINK_CLASS_PHYS) ||
		    (class == DATALINK_CLASS_SIMNET)) || (media != DL_ETHER)) {
			return (DLADM_STATUS_BADARG);
		}
	}

	/*
	 * First, update the persistent configuration if requested.  We only
	 * need to update the FPORTS and FNPORTS fields of this aggregation.
	 * Note that FPORTS is a list of port linkids separated by
	 * PORT_DELIMITER (':').
	 */
	if (flags & DLADM_OPT_PERSIST) {
		status = dladm_open_conf(handle, linkid, &conf);
		if (status != DLADM_STATUS_OK)
			return (status);

		/*
		 * Get the original configuration of FNPORTS and FPORTS.
		 */
		status = dladm_get_conf_field(handle, conf, FNPORTS, &u64,
		    sizeof (u64));
		if (status != DLADM_STATUS_OK)
			goto destroyconf;
		orig_nports = (uint32_t)u64;

		/*
		 * At least one port needs to be in the aggregation.
		 */
		if ((cmd == LAIOC_REMOVE) && (orig_nports <= nports)) {
			status = DLADM_STATUS_BADARG;
			goto destroyconf;
		}

		size = orig_nports * (MAXLINKNAMELEN + 1) + 1;
		if ((orig_portstr = calloc(1, size)) == NULL) {
			status = dladm_errno2status(errno);
			goto destroyconf;
		}

		status = dladm_get_conf_field(handle, conf, FPORTS,
		    orig_portstr, size);
		if (status != DLADM_STATUS_OK)
			goto destroyconf;

		result_nports = (cmd == LAIOC_ADD) ? orig_nports + nports :
		    orig_nports;

		size = result_nports * (MAXLINKNAMELEN + 1) + 1;
		if ((portstr = calloc(1, size)) == NULL) {
			status = dladm_errno2status(errno);
			goto destroyconf;
		}

		/*
		 * get the new configuration and set to result_nports and
		 * portstr.
		 */
		if (cmd == LAIOC_ADD) {
			(void) strlcpy(portstr, orig_portstr, size);
			for (i = 0; i < nports; i++) {
				status = write_port(handle, portstr,
				    ports[i].lp_linkid, size);
				if (status != DLADM_STATUS_OK) {
					free(portstr);
					goto destroyconf;
				}
			}
		} else {
			char *next;
			datalink_id_t portid;
			uint32_t remove = 0;

			for (next = orig_portstr, j = 0; j < orig_nports; j++) {
				/*
				 * Read the portids from the old configuration
				 * one by one.
				 */
				status = read_port(handle, &next, &portid);
				if (status != DLADM_STATUS_OK) {
					free(portstr);
					goto destroyconf;
				}

				/*
				 * See whether this port is in the removal
				 * list.  If not, copy to the new config.
				 */
				for (i = 0; i < nports; i++) {
					if (ports[i].lp_linkid == portid)
						break;
				}
				if (i == nports) {
					status = write_port(handle, portstr,
					    portid, size);
					if (status != DLADM_STATUS_OK) {
						free(portstr);
						goto destroyconf;
					}
				} else {
					remove++;
				}
			}
			if (remove != nports) {
				status = DLADM_STATUS_LINKINVAL;
				free(portstr);
				goto destroyconf;
			}
			result_nports -= nports;
		}

		u64 = result_nports;
		if ((status = dladm_set_conf_field(handle, conf, FNPORTS,
		    DLADM_TYPE_UINT64, &u64)) != DLADM_STATUS_OK) {
			free(portstr);
			goto destroyconf;
		}

		status = dladm_set_conf_field(handle, conf, FPORTS,
		    DLADM_TYPE_STR, portstr);
		free(portstr);
		if (status != DLADM_STATUS_OK)
			goto destroyconf;

		/*
		 * Write the new configuration to the persistent repository.
		 */
		status = dladm_write_conf(handle, conf);

destroyconf:
		dladm_destroy_conf(handle, conf);
		if (status != DLADM_STATUS_OK) {
			free(orig_portstr);
			return (status);
		}
	}

	/*
	 * If the caller only requested to update the persistent
	 * configuration, we are done.
	 */
	if (!(flags & DLADM_OPT_ACTIVE))
		goto done;

	/*
	 * Update the active configuration.
	 */
	len = sizeof (*iocp) + nports * sizeof (laioc_port_t);
	if ((iocp = malloc(len)) == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	iocp->la_linkid = linkid;
	iocp->la_nports = nports;
	if (cmd == LAIOC_ADD)
		iocp->la_force = (flags & DLADM_OPT_FORCE);

	ioc_ports = (laioc_port_t *)(iocp + 1);
	for (i = 0; i < nports; i++)
		ioc_ports[i].lp_linkid = ports[i].lp_linkid;

	if (i_dladm_aggr_ioctl(handle, cmd, iocp) < 0)
		status = dladm_errno2status(errno);

done:
	free(iocp);

	/*
	 * If the active configuration update fails, restore the old
	 * persistent configuration if we've changed that.
	 */
	if ((status != DLADM_STATUS_OK) && (flags & DLADM_OPT_PERSIST)) {
		if (dladm_open_conf(handle, linkid, &conf) == DLADM_STATUS_OK) {
			u64 = orig_nports;
			if ((dladm_set_conf_field(handle, conf, FNPORTS,
			    DLADM_TYPE_UINT64, &u64) == DLADM_STATUS_OK) &&
			    (dladm_set_conf_field(handle, conf, FPORTS,
			    DLADM_TYPE_STR, orig_portstr) == DLADM_STATUS_OK)) {
				(void) dladm_write_conf(handle, conf);
			}
			(void) dladm_destroy_conf(handle, conf);
		}
	}
	free(orig_portstr);
	return (status);
}

/*
 * Send a modify command to the link aggregation driver.
 */
static dladm_status_t
i_dladm_aggr_modify_sys(dladm_handle_t handle, datalink_id_t linkid,
    uint32_t mask, dladm_aggr_modify_attr_t *attr)
{
	laioc_modify_t ioc;

	ioc.lu_linkid = linkid;

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

	if (i_dladm_aggr_ioctl(handle, LAIOC_MODIFY, &ioc) < 0) {
		if (errno == EINVAL)
			return (DLADM_STATUS_MACADDRINVAL);
		else
			return (dladm_errno2status(errno));
	} else {
		return (DLADM_STATUS_OK);
	}
}

/*
 * Send a create command to the link aggregation driver.
 */
static dladm_status_t
i_dladm_aggr_create_sys(dladm_handle_t handle, datalink_id_t linkid,
    uint16_t key, uint32_t nports, dladm_aggr_port_attr_db_t *ports,
    uint32_t policy, boolean_t mac_addr_fixed, const uchar_t *mac_addr,
    aggr_lacp_mode_t lacp_mode, aggr_lacp_timer_t lacp_timer, boolean_t force)
{
	int i, len;
	laioc_create_t *iocp = NULL;
	laioc_port_t *ioc_ports;
	dladm_status_t status = DLADM_STATUS_OK;

	len = sizeof (*iocp) + nports * sizeof (laioc_port_t);
	iocp = malloc(len);
	if (iocp == NULL)
		return (DLADM_STATUS_NOMEM);

	iocp->lc_key = key;
	iocp->lc_linkid = linkid;
	iocp->lc_nports = nports;
	iocp->lc_policy = policy;
	iocp->lc_lacp_mode = lacp_mode;
	iocp->lc_lacp_timer = lacp_timer;
	ioc_ports = (laioc_port_t *)(iocp + 1);
	iocp->lc_force = force;

	for (i = 0; i < nports; i++)
		ioc_ports[i].lp_linkid = ports[i].lp_linkid;

	if (mac_addr_fixed && !VALID_PORT_MAC(mac_addr)) {
		status = DLADM_STATUS_MACADDRINVAL;
		goto done;
	}

	bcopy(mac_addr, iocp->lc_mac, ETHERADDRL);
	iocp->lc_mac_fixed = mac_addr_fixed;

	if (i_dladm_aggr_ioctl(handle, LAIOC_CREATE, iocp) < 0)
		status = dladm_errno2status(errno);

done:
	free(iocp);
	return (status);
}

/*
 * Invoked to bring up a link aggregation group.
 */
static int
i_dladm_aggr_up(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	dladm_status_t *statusp = (dladm_status_t *)arg;
	dladm_aggr_grp_attr_t attr;
	dladm_aggr_port_attr_db_t *ports = NULL;
	uint16_t key = 0;
	int i, j;
	dladm_status_t status;

	status = dladm_aggr_info(handle, linkid, &attr, DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK) {
		*statusp = status;
		return (DLADM_WALK_CONTINUE);
	}

	if (attr.lg_key <= AGGR_MAX_KEY)
		key = attr.lg_key;

	ports = malloc(attr.lg_nports * sizeof (dladm_aggr_port_attr_db_t));
	if (ports == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	/*
	 * Validate (and purge) each physical link associated with this
	 * aggregation, if the specific hardware has been removed during
	 * the system shutdown.
	 */
	for (i = 0, j = 0; i < attr.lg_nports; i++) {
		datalink_id_t	portid = attr.lg_ports[i].lp_linkid;
		uint32_t	flags;
		dladm_status_t	s;

		s = dladm_datalink_id2info(handle, portid, &flags, NULL, NULL,
		    NULL, 0);
		if (s != DLADM_STATUS_OK || !(flags & DLADM_OPT_ACTIVE))
			continue;

		ports[j++].lp_linkid = portid;
	}

	if (j == 0) {
		/*
		 * All of the physical links are removed.
		 */
		status = DLADM_STATUS_BADARG;
		goto done;
	}

	/*
	 * Create active aggregation.
	 */
	if ((status = i_dladm_aggr_create_sys(handle, linkid,
	    key, j, ports, attr.lg_policy, attr.lg_mac_fixed,
	    (const uchar_t *)attr.lg_mac, attr.lg_lacp_mode,
	    attr.lg_lacp_timer, attr.lg_force)) != DLADM_STATUS_OK) {
		goto done;
	}

	if ((status = dladm_up_datalink_id(handle, linkid)) !=
	    DLADM_STATUS_OK) {
		laioc_delete_t ioc;

		ioc.ld_linkid = linkid;
		(void) i_dladm_aggr_ioctl(handle, LAIOC_DELETE, &ioc);
	}
done:
	free(attr.lg_ports);
	free(ports);

	*statusp = status;
	return (DLADM_WALK_CONTINUE);
}

/*
 * Bring up one aggregation, or all persistent aggregations.  In the latter
 * case, the walk may terminate early if bringup of an aggregation fails.
 */
dladm_status_t
dladm_aggr_up(dladm_handle_t handle, datalink_id_t linkid)
{
	dladm_status_t status;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(i_dladm_aggr_up, handle, &status,
		    DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
		return (DLADM_STATUS_OK);
	} else {
		(void) i_dladm_aggr_up(handle, linkid, &status);
		return (status);
	}
}

/*
 * Given a policy string, return a policy mask. Returns B_TRUE on
 * success, or B_FALSE if an error occurred during parsing.
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

	if (str == NULL)
		return (NULL);

	str[0] = '\0';

	for (i = 0; i < NPOLICIES; i++) {
		pol = &policies[i];
		if ((policy & pol->policy) != 0) {
			npolicies++;
			if (npolicies > 1)
				(void) strlcat(str, ",", DLADM_STRSIZE);
			(void) strlcat(str, pol->pol_name, DLADM_STRSIZE);
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
dladm_aggr_macaddr2str(const unsigned char *mac, char *buf)
{
	static char unknown_mac[] = {0, 0, 0, 0, 0, 0};

	if (buf == NULL)
		return (NULL);

	if (bcmp(unknown_mac, mac, ETHERADDRL) == 0)
		(void) strlcpy(buf, "unknown", DLADM_STRSIZE);
	else
		return (_link_ntoa(mac, buf, ETHERADDRL, IFT_OTHER));

	return (buf);
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

	if (buf == NULL)
		return (NULL);

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

	if (buf == NULL)
		return (NULL);

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
	dladm_aggr_port_state_t *state;

	if (buf == NULL)
		return (NULL);

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

static dladm_status_t
dladm_aggr_persist_aggr_conf(dladm_handle_t handle, const char *link,
    datalink_id_t linkid, uint16_t key, uint32_t nports,
    dladm_aggr_port_attr_db_t *ports, uint32_t policy, boolean_t mac_addr_fixed,
    const uchar_t *mac_addr, aggr_lacp_mode_t lacp_mode,
    aggr_lacp_timer_t lacp_timer, boolean_t force)
{
	dladm_conf_t conf;
	char *portstr = NULL;
	char macstr[ETHERADDRL * 3];
	dladm_status_t status;
	int i, size;
	uint64_t u64;

	if ((status = dladm_create_conf(handle, link, linkid,
	    DATALINK_CLASS_AGGR, DL_ETHER, &conf)) != DLADM_STATUS_OK) {
		return (status);
	}

	u64 = key;
	status = dladm_set_conf_field(handle, conf, FKEY, DLADM_TYPE_UINT64,
	    &u64);
	if (status != DLADM_STATUS_OK)
		goto done;

	u64 = nports;
	status = dladm_set_conf_field(handle, conf, FNPORTS, DLADM_TYPE_UINT64,
	    &u64);
	if (status != DLADM_STATUS_OK)
		goto done;

	size = nports * MAXLINKNAMELEN + 1;
	if ((portstr = calloc(1, size)) == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	for (i = 0; i < nports; i++) {
		status = write_port(handle, portstr, ports[i].lp_linkid, size);
		if (status != DLADM_STATUS_OK) {
			free(portstr);
			goto done;
		}
	}
	status = dladm_set_conf_field(handle, conf, FPORTS, DLADM_TYPE_STR,
	    portstr);
	free(portstr);

	if (status != DLADM_STATUS_OK)
		goto done;

	u64 = policy;
	status = dladm_set_conf_field(handle, conf, FPOLICY, DLADM_TYPE_UINT64,
	    &u64);
	if (status != DLADM_STATUS_OK)
		goto done;

	status = dladm_set_conf_field(handle, conf, FFIXMACADDR,
	    DLADM_TYPE_BOOLEAN, &mac_addr_fixed);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (mac_addr_fixed) {
		if (!VALID_PORT_MAC(mac_addr)) {
			status = DLADM_STATUS_MACADDRINVAL;
			goto done;
		}

		(void) dladm_aggr_macaddr2str(mac_addr, macstr);
		status = dladm_set_conf_field(handle, conf, FMACADDR,
		    DLADM_TYPE_STR, macstr);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	status = dladm_set_conf_field(handle, conf, FFORCE, DLADM_TYPE_BOOLEAN,
	    &force);
	if (status != DLADM_STATUS_OK)
		goto done;

	u64 = lacp_mode;
	status = dladm_set_conf_field(handle, conf, FLACPMODE,
	    DLADM_TYPE_UINT64, &u64);
	if (status != DLADM_STATUS_OK)
		goto done;

	u64 = lacp_timer;
	status = dladm_set_conf_field(handle, conf, FLACPTIMER,
	    DLADM_TYPE_UINT64, &u64);
	if (status != DLADM_STATUS_OK)
		goto done;

	/*
	 * Commit the link aggregation configuration.
	 */
	status = dladm_write_conf(handle, conf);

done:
	dladm_destroy_conf(handle, conf);
	return (status);
}

/*
 * Create a new link aggregation group. Update the configuration
 * file and bring it up.
 */
dladm_status_t
dladm_aggr_create(dladm_handle_t handle, const char *name, uint16_t key,
    uint32_t nports, dladm_aggr_port_attr_db_t *ports, uint32_t policy,
    boolean_t mac_addr_fixed, const uchar_t *mac_addr,
    aggr_lacp_mode_t lacp_mode, aggr_lacp_timer_t lacp_timer, uint32_t flags)
{
	datalink_id_t linkid = DATALINK_INVALID_LINKID;
	uint32_t media;
	uint32_t i;
	datalink_class_t class;
	dladm_status_t status;
	boolean_t force = (flags & DLADM_OPT_FORCE) ? B_TRUE : B_FALSE;

	if (key != 0 && key > AGGR_MAX_KEY)
		return (DLADM_STATUS_KEYINVAL);

	if (nports == 0)
		return (DLADM_STATUS_BADARG);

	for (i = 0; i < nports; i++) {
		if ((dladm_datalink_id2info(handle, ports[i].lp_linkid, NULL,
		    &class, &media, NULL, 0) != DLADM_STATUS_OK) ||
		    !((class == DATALINK_CLASS_PHYS || class ==
		    DATALINK_CLASS_SIMNET) && (media == DL_ETHER))) {
			return (DLADM_STATUS_BADARG);
		}
	}

	flags &= (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST);
	if ((status = dladm_create_datalink_id(handle, name,
	    DATALINK_CLASS_AGGR, DL_ETHER, flags, &linkid)) !=
	    DLADM_STATUS_OK) {
		goto fail;
	}

	if ((flags & DLADM_OPT_PERSIST) &&
	    (status = dladm_aggr_persist_aggr_conf(handle, name, linkid, key,
	    nports, ports, policy, mac_addr_fixed, mac_addr, lacp_mode,
	    lacp_timer, force)) != DLADM_STATUS_OK) {
		goto fail;
	}

	if (!(flags & DLADM_OPT_ACTIVE))
		return (DLADM_STATUS_OK);

	status = i_dladm_aggr_create_sys(handle, linkid, key, nports, ports,
	    policy, mac_addr_fixed, mac_addr, lacp_mode, lacp_timer, force);

	if (status != DLADM_STATUS_OK) {
		if (flags & DLADM_OPT_PERSIST)
			(void) dladm_remove_conf(handle, linkid);
		goto fail;
	}

	return (DLADM_STATUS_OK);

fail:
	if (linkid != DATALINK_INVALID_LINKID)
		(void) dladm_destroy_datalink_id(handle, linkid, flags);

	return (status);
}

static dladm_status_t
i_dladm_aggr_get_aggr_attr(dladm_handle_t handle, dladm_conf_t conf,
    uint32_t mask, dladm_aggr_modify_attr_t *attrp)
{
	dladm_status_t status = DLADM_STATUS_OK;
	char macstr[ETHERADDRL * 3];
	uint64_t u64;

	if (mask & DLADM_AGGR_MODIFY_POLICY) {
		status = dladm_get_conf_field(handle, conf, FPOLICY, &u64,
		    sizeof (u64));
		if (status != DLADM_STATUS_OK)
			return (status);
		attrp->ld_policy = (uint32_t)u64;
	}

	if (mask & DLADM_AGGR_MODIFY_MAC) {
		status = dladm_get_conf_field(handle, conf, FFIXMACADDR,
		    &attrp->ld_mac_fixed, sizeof (boolean_t));
		if (status != DLADM_STATUS_OK)
			return (status);

		if (attrp->ld_mac_fixed) {
			boolean_t fixed;

			status = dladm_get_conf_field(handle, conf, FMACADDR,
			    macstr, sizeof (macstr));
			if (status != DLADM_STATUS_OK)
				return (status);

			if (!dladm_aggr_str2macaddr(macstr, &fixed,
			    attrp->ld_mac)) {
				return (DLADM_STATUS_REPOSITORYINVAL);
			}
		}
	}

	if (mask & DLADM_AGGR_MODIFY_LACP_MODE) {
		status = dladm_get_conf_field(handle, conf, FLACPMODE, &u64,
		    sizeof (u64));
		if (status != DLADM_STATUS_OK)
			return (status);
		attrp->ld_lacp_mode = (aggr_lacp_mode_t)u64;
	}

	if (mask & DLADM_AGGR_MODIFY_LACP_TIMER) {
		status = dladm_get_conf_field(handle, conf, FLACPTIMER, &u64,
		    sizeof (u64));
		if (status != DLADM_STATUS_OK)
			return (status);
		attrp->ld_lacp_timer = (aggr_lacp_timer_t)u64;
	}

	return (status);
}

static dladm_status_t
i_dladm_aggr_set_aggr_attr(dladm_handle_t handle, dladm_conf_t conf,
    uint32_t mask, dladm_aggr_modify_attr_t *attrp)
{
	dladm_status_t status = DLADM_STATUS_OK;
	char macstr[ETHERADDRL * 3];
	uint64_t u64;

	if (mask & DLADM_AGGR_MODIFY_POLICY) {
		u64 = attrp->ld_policy;
		status = dladm_set_conf_field(handle, conf, FPOLICY,
		    DLADM_TYPE_UINT64, &u64);
		if (status != DLADM_STATUS_OK)
			return (status);
	}

	if (mask & DLADM_AGGR_MODIFY_MAC) {
		status = dladm_set_conf_field(handle, conf, FFIXMACADDR,
		    DLADM_TYPE_BOOLEAN, &attrp->ld_mac_fixed);
		if (status != DLADM_STATUS_OK)
			return (status);

		if (attrp->ld_mac_fixed) {
			(void) dladm_aggr_macaddr2str(attrp->ld_mac, macstr);
			status = dladm_set_conf_field(handle, conf, FMACADDR,
			    DLADM_TYPE_STR, macstr);
			if (status != DLADM_STATUS_OK)
				return (status);
		}
	}

	if (mask & DLADM_AGGR_MODIFY_LACP_MODE) {
		u64 = attrp->ld_lacp_mode;
		status = dladm_set_conf_field(handle, conf, FLACPMODE,
		    DLADM_TYPE_UINT64, &u64);
		if (status != DLADM_STATUS_OK)
			return (status);
	}

	if (mask & DLADM_AGGR_MODIFY_LACP_TIMER) {
		u64 = attrp->ld_lacp_timer;
		status = dladm_set_conf_field(handle, conf, FLACPTIMER,
		    DLADM_TYPE_UINT64, &u64);
		if (status != DLADM_STATUS_OK)
			return (status);
	}

	return (status);
}

/*
 * Modify the parameters of an existing link aggregation group. Update
 * the configuration file and pass the changes to the kernel.
 */
dladm_status_t
dladm_aggr_modify(dladm_handle_t handle, datalink_id_t linkid,
    uint32_t modify_mask, uint32_t policy, boolean_t mac_fixed,
    const uchar_t *mac_addr, aggr_lacp_mode_t lacp_mode,
    aggr_lacp_timer_t lacp_timer, uint32_t flags)
{
	dladm_aggr_modify_attr_t new_attr, old_attr;
	dladm_conf_t conf;
	dladm_status_t status;

	new_attr.ld_policy = policy;
	new_attr.ld_mac_fixed = mac_fixed;
	new_attr.ld_lacp_mode = lacp_mode;
	new_attr.ld_lacp_timer = lacp_timer;
	bcopy(mac_addr, new_attr.ld_mac, ETHERADDRL);

	if (flags & DLADM_OPT_PERSIST) {
		status = dladm_open_conf(handle, linkid, &conf);
		if (status != DLADM_STATUS_OK)
			return (status);

		if ((status = i_dladm_aggr_get_aggr_attr(handle, conf,
		    modify_mask, &old_attr)) != DLADM_STATUS_OK) {
			goto done;
		}

		if ((status = i_dladm_aggr_set_aggr_attr(handle, conf,
		    modify_mask, &new_attr)) != DLADM_STATUS_OK) {
			goto done;
		}

		status = dladm_write_conf(handle, conf);

done:
		dladm_destroy_conf(handle, conf);
		if (status != DLADM_STATUS_OK)
			return (status);
	}

	if (!(flags & DLADM_OPT_ACTIVE))
		return (DLADM_STATUS_OK);

	status = i_dladm_aggr_modify_sys(handle, linkid, modify_mask,
	    &new_attr);
	if ((status != DLADM_STATUS_OK) && (flags & DLADM_OPT_PERSIST)) {
		if (dladm_open_conf(handle, linkid, &conf) == DLADM_STATUS_OK) {
			if (i_dladm_aggr_set_aggr_attr(handle, conf,
			    modify_mask, &old_attr) == DLADM_STATUS_OK) {
				(void) dladm_write_conf(handle, conf);
			}
			dladm_destroy_conf(handle, conf);
		}
	}

	return (status);
}

typedef struct aggr_held_arg_s {
	datalink_id_t	aggrid;
	boolean_t	isheld;
} aggr_held_arg_t;

static int
i_dladm_aggr_is_held(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	aggr_held_arg_t		*aggr_held_arg = arg;
	dladm_vlan_attr_t	dva;

	if (dladm_vlan_info(handle, linkid, &dva, DLADM_OPT_PERSIST) !=
	    DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	if (dva.dv_linkid == aggr_held_arg->aggrid) {
		/*
		 * This VLAN is created over the given aggregation.
		 */
		aggr_held_arg->isheld = B_TRUE;
		return (DLADM_WALK_TERMINATE);
	}
	return (DLADM_WALK_CONTINUE);
}

/*
 * Delete a previously created link aggregation group. Either the name "aggr"
 * or the "key" is specified.
 */
dladm_status_t
dladm_aggr_delete(dladm_handle_t handle, datalink_id_t linkid, uint32_t flags)
{
	laioc_delete_t ioc;
	datalink_class_t class;
	dladm_status_t status;

	if ((dladm_datalink_id2info(handle, linkid, NULL, &class, NULL, NULL,
	    0) != DLADM_STATUS_OK) || (class != DATALINK_CLASS_AGGR)) {
		return (DLADM_STATUS_BADARG);
	}

	if (flags & DLADM_OPT_ACTIVE) {
		ioc.ld_linkid = linkid;
		if ((i_dladm_aggr_ioctl(handle, LAIOC_DELETE, &ioc) < 0) &&
		    ((errno != ENOENT) || !(flags & DLADM_OPT_PERSIST))) {
			status = dladm_errno2status(errno);
			return (status);
		}

		/*
		 * Delete ACTIVE linkprop first.
		 */
		(void) dladm_set_linkprop(handle, linkid, NULL, NULL, 0,
		    DLADM_OPT_ACTIVE);
		(void) dladm_destroy_datalink_id(handle, linkid,
		    DLADM_OPT_ACTIVE);
	}

	/*
	 * If we reach here, it means that the active aggregation has already
	 * been deleted, and there is no active VLANs holding this aggregation.
	 * Now we see whether there is any persistent VLANs holding this
	 * aggregation. If so, we fail the operation.
	 */
	if (flags & DLADM_OPT_PERSIST) {
		aggr_held_arg_t arg;

		arg.aggrid = linkid;
		arg.isheld = B_FALSE;

		(void) dladm_walk_datalink_id(i_dladm_aggr_is_held, handle,
		    &arg, DATALINK_CLASS_VLAN, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
		if (arg.isheld)
			return (DLADM_STATUS_LINKBUSY);

		(void) dladm_remove_conf(handle, linkid);
		(void) dladm_destroy_datalink_id(handle, linkid,
		    DLADM_OPT_PERSIST);
	}

	return (DLADM_STATUS_OK);
}

/*
 * Add one or more ports to an existing link aggregation.
 */
dladm_status_t
dladm_aggr_add(dladm_handle_t handle, datalink_id_t linkid, uint32_t nports,
    dladm_aggr_port_attr_db_t *ports, uint32_t flags)
{
	return (i_dladm_aggr_add_rmv(handle, linkid, nports, ports, flags,
	    LAIOC_ADD));
}

/*
 * Remove one or more ports from an existing link aggregation.
 */
dladm_status_t
dladm_aggr_remove(dladm_handle_t handle, datalink_id_t linkid, uint32_t nports,
    dladm_aggr_port_attr_db_t *ports, uint32_t flags)
{
	return (i_dladm_aggr_add_rmv(handle, linkid, nports, ports, flags,
	    LAIOC_REMOVE));
}

typedef struct i_walk_key_state_s {
	uint16_t key;
	datalink_id_t linkid;
	boolean_t found;
} i_walk_key_state_t;

static int
i_dladm_walk_key2linkid(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	dladm_conf_t conf;
	uint16_t key;
	dladm_status_t status;
	i_walk_key_state_t *statep = (i_walk_key_state_t *)arg;
	uint64_t u64;

	if (dladm_getsnap_conf(handle, linkid, &conf) != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	status = dladm_get_conf_field(handle, conf, FKEY, &u64, sizeof (u64));
	key = (uint16_t)u64;
	dladm_destroy_conf(handle, conf);

	if ((status == DLADM_STATUS_OK) && (key == statep->key)) {
		statep->found = B_TRUE;
		statep->linkid = linkid;
		return (DLADM_WALK_TERMINATE);
	}

	return (DLADM_WALK_CONTINUE);
}

dladm_status_t
dladm_key2linkid(dladm_handle_t handle, uint16_t key, datalink_id_t *linkidp,
    uint32_t flags)
{
	i_walk_key_state_t state;

	if (key > AGGR_MAX_KEY)
		return (DLADM_STATUS_NOTFOUND);

	state.found = B_FALSE;
	state.key = key;

	(void) dladm_walk_datalink_id(i_dladm_walk_key2linkid, handle, &state,
	    DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE, flags);
	if (state.found == B_TRUE) {
		*linkidp = state.linkid;
		return (DLADM_STATUS_OK);
	} else {
		return (DLADM_STATUS_NOTFOUND);
	}
}
