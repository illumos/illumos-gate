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

/*
 * Logical Domains System Agent
 */

#include <errno.h>
#include <fcntl.h>
#include <libds.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <synch.h>
#include <thread.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/mdesc.h>
#include <sys/mdesc_impl.h>

#include "ldma.h"
#include "pri.h"

#define	LDMA_MODULE	LDMA_NAME_SYSTEM

#define	LDMA_NVERSIONS	(sizeof (ldma_versions) / sizeof (ds_ver_t))
#define	LDMA_NHANDLERS	(sizeof (ldma_handlers) / sizeof (ldma_msg_handler_t))

static ldm_msg_func_t ldma_sys_get_sysinfo;
static ldm_msg_func_t ldma_sys_get_chassisno;

/* ptr to cached value of chassisno */
static char *ldma_sys_chassisno = NULL;
mutex_t ldma_chassisno_lock = DEFAULTMUTEX;

static ds_ver_t ldma_versions[] = { { 1, 0 } };

static ldma_msg_handler_t ldma_handlers[] = {
	{ LDMA_MSGSYS_GET_SYSINFO,   LDMA_MSGFLG_ACCESS_ANY,
	    ldma_sys_get_sysinfo },
	{ LDMA_MSGSYS_GET_CHASSISNO, LDMA_MSGFLG_ACCESS_ANY,
	    ldma_sys_get_chassisno }
};

ldma_agent_info_t ldma_system_info = {
	LDMA_NAME_SYSTEM,
	ldma_versions, LDMA_NVERSIONS,
	ldma_handlers, LDMA_NHANDLERS
};

/*ARGSUSED*/
static ldma_request_status_t
ldma_sys_get_sysinfo(ds_ver_t *ver, ldma_message_header_t *request,
    size_t request_dlen, ldma_message_header_t **replyp, size_t *reply_dlenp)
{
	ldma_message_header_t *reply;
	struct utsname name;
	size_t syslen, nodlen, rellen, maclen, verlen;
	size_t rlen;
	char *data;
	int status;

	LDMA_DBG("GET_SYSINFO");

	if (request->msg_info != 0 || request_dlen != 0) {
		status = LDMA_REQ_INVALID;
		goto done;
	}

	if (uname(&name) == -1) {
		LDMA_DBG("GET_SYSINFO: uname failed with error %d", errno);
		status = LDMA_REQ_FAILED;
		goto done;
	}

	syslen = strlen(name.sysname) + 1;
	nodlen = strlen(name.nodename) + 1;
	rellen = strlen(name.release) + 1;
	verlen = strlen(name.version) + 1;
	maclen = strlen(name.machine) + 1;

	rlen = syslen + nodlen + rellen + verlen + maclen;

	reply = ldma_alloc_result_msg(request, rlen);

	if (reply == NULL) {
		status = LDMA_REQ_FAILED;
		goto done;
	}

	reply->msg_info = rlen;

	data = LDMA_HDR2DATA(reply);

	(void) strcpy(data, name.sysname);
	data += syslen;

	(void) strcpy(data, name.nodename);
	data += nodlen;

	(void) strcpy(data, name.release);
	data += rellen;

	(void) strcpy(data, name.version);
	data += verlen;

	(void) strcpy(data, name.machine);

	LDMA_DBG("GET_SYSINFO: return info=%u, {%s, %s, %s, %s, %s}", rlen,
	    name.sysname, name.nodename, name.release, name.version,
	    name.machine);

	*replyp = reply;
	*reply_dlenp = rlen;

	return (LDMA_REQ_COMPLETED);

done:
	LDMA_DBG("GET_SYSINFO: return error %d", status);
	return (status);
}

/*
 * Wrapper for MD free: need unused size argument.
 */
/* ARGSUSED */
static void
ldma_md_free(void *buf, size_t n)
{
	free(buf);
}

/*
 * Wrapper for MD init: read PRI MD and invoke md_init_intern.
 */
static md_t *
ldma_md_init()
{
	md_t *mdp;
	uint64_t *buf = NULL;
	uint64_t token;
	ssize_t status;

	if (pri_init() == -1)
		return (NULL);

	status = pri_get(PRI_GET, &token, &buf, malloc, ldma_md_free);
	pri_fini();

	if (status == (ssize_t)(-1))
		return (NULL);

	mdp = md_init_intern(buf, malloc, ldma_md_free);

	return (mdp);
}

/*
 * Wrapper for md_fini.  Allow NULL md ptr and free MD buffer.
 */
static void
ldma_md_fini(void *md)
{
	md_impl_t *mdp = (md_impl_t *)md;

	if (mdp) {
		free(mdp->caddr);
		(void) md_fini(md);
	}
}

static int
ldma_get_chassis_serialno(char **strp)
{
	md_t *mdp;
	mde_cookie_t *component_nodes, rootnode;
	int list_size, ncomponents, num_nodes, i;
	char *component_type, *serialno;
	int rv = 0;

	(void) mutex_lock(&ldma_chassisno_lock);
	if (ldma_sys_chassisno != NULL) {
		*strp = ldma_sys_chassisno;
		(void) mutex_unlock(&ldma_chassisno_lock);
		return (1);
	}

	mdp = ldma_md_init();
	if (mdp == NULL) {
		(void) mutex_unlock(&ldma_chassisno_lock);
		return (0);
	}

	num_nodes = md_node_count(mdp);
	list_size = num_nodes * sizeof (mde_cookie_t);
	component_nodes = malloc(list_size);
	if (component_nodes == NULL) {
		(void) mutex_unlock(&ldma_chassisno_lock);
		ldma_md_fini(mdp);
		return (0);
	}

	rootnode = md_root_node(mdp);

	ncomponents = md_scan_dag(mdp, rootnode, md_find_name(mdp, "component"),
	    md_find_name(mdp, "fwd"), component_nodes);

	for (i = 0; i < ncomponents; i++) {
		if (md_get_prop_str(mdp, component_nodes[i], "type",
		    &component_type))
			continue;
		if (strcmp(component_type, "chassis") != 0)
			continue;
		if (md_get_prop_str(mdp, component_nodes[i],
		    "serial_number", &serialno) == 0) {
			ldma_sys_chassisno = strdup(serialno);
			*strp = ldma_sys_chassisno;
			rv = 1;
			break;
		}
	}
	(void) mutex_unlock(&ldma_chassisno_lock);
	free(component_nodes);
	ldma_md_fini(mdp);
	return (rv);
}

/*ARGSUSED*/
static ldma_request_status_t
ldma_sys_get_chassisno(ds_ver_t *ver, ldma_message_header_t *request,
    size_t request_dlen, ldma_message_header_t **replyp, size_t *reply_dlenp)
{
	ldma_message_header_t *reply;
	char *str;
	size_t rlen;
	char *data;
	int status;

	LDMA_DBG("GET_CHASSISNO");

	if (request->msg_info != 0 || request_dlen != 0) {
		status = LDMA_REQ_INVALID;
		goto done;
	}

	if (ldma_get_chassis_serialno(&str) == 0) {
		LDMA_DBG("GET_CHASSISNO: ldma_get_chassisno failed "
		    "with error %d", errno);
		status = LDMA_REQ_FAILED;
		goto done;
	}

	rlen = strlen(str) + 1;

	reply = ldma_alloc_result_msg(request, rlen);

	if (reply == NULL) {
		status = LDMA_REQ_FAILED;
		goto done;
	}

	reply->msg_info = rlen;

	data = LDMA_HDR2DATA(reply);

	(void) strcpy(data, str);

	LDMA_DBG("GET_CHASSISNO: return info=%u, {%s}", rlen, str);

	*replyp = reply;
	*reply_dlenp = rlen;

	return (LDMA_REQ_COMPLETED);

done:
	LDMA_DBG("GET_CHASSISNO: return error %d", status);
	return (status);
}
