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


#include <synch.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <assert.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/ndr.h>
#include <smbsrv/mlrpc.h>
#include <smbsrv/ntsid.h>


/*
 * Global list of allocated handles.  Handles are used in various
 * server-side RPC functions: typically, issued when a service is
 * opened and obsoleted when it is closed.  Clients should treat
 * handles as opaque data.
 */
static ndr_handle_t *ndr_handle_list;
static mutex_t ndr_handle_lock;

/*
 * Table of registered services.
 */
#define	NDL_MAX_SERVICES	32
static mlrpc_service_t *mlrpc_services[NDL_MAX_SERVICES];


struct mlrpc_stub_table *
mlrpc_find_stub_in_svc(mlrpc_service_t *msvc, int opnum)
{
	struct mlrpc_stub_table *ste;

	for (ste = msvc->stub_table; ste->func; ste++) {
		if (ste->opnum == opnum)
			return (ste);
	}

	return (NULL);
}

mlrpc_service_t *
mlrpc_find_service_by_name(const char *name)
{
	mlrpc_service_t 	*msvc;
	int			i;

	for (i = 0; i < NDL_MAX_SERVICES; i++) {
		if ((msvc = mlrpc_services[i]) == NULL)
			continue;

		if (strcasecmp(name, msvc->name) != 0)
			continue;

		mlndo_printf(0, 0, "%s %s", msvc->name, msvc->desc);
		return (msvc);
	}

	return (NULL);
}

mlrpc_service_t *
mlrpc_find_service_by_uuids(ndr_uuid_t *as_uuid, int as_vers,
    ndr_uuid_t *ts_uuid, int ts_vers)
{
	mlrpc_service_t *msvc;
	char abstract_syntax[128];
	char transfer_syntax[128];
	int i;

	if (as_uuid)
		mlrpc_uuid_to_str(as_uuid, abstract_syntax);

	if (ts_uuid)
		mlrpc_uuid_to_str(ts_uuid, transfer_syntax);

	for (i = 0; i < NDL_MAX_SERVICES; i++) {
		if ((msvc = mlrpc_services[i]) == NULL)
			continue;

		if (as_uuid) {
			if (msvc->abstract_syntax_uuid == 0)
				continue;

			if (msvc->abstract_syntax_version != as_vers)
				continue;

			if (strcasecmp(abstract_syntax,
			    msvc->abstract_syntax_uuid))
				continue;
		}

		if (ts_uuid) {
			if (msvc->transfer_syntax_uuid == 0)
				continue;

			if (msvc->transfer_syntax_version != ts_vers)
				continue;

			if (strcasecmp(transfer_syntax,
			    msvc->transfer_syntax_uuid))
				continue;
		}

		mlndo_printf(0, 0, "%s %s", msvc->name, msvc->desc);
		return (msvc);
	}

	return (NULL);
}

/*
 * Register a service.
 *
 * Returns:
 *	0	Success
 *	-1	Duplicate service
 *	-2	Duplicate name
 *	-3	Table overflow
 */
int
mlrpc_register_service(mlrpc_service_t *msvc)
{
	mlrpc_service_t 	*p;
	int			free_slot = -1;
	int			i;

	for (i = 0; i < NDL_MAX_SERVICES; i++) {
		if ((p = mlrpc_services[i]) == NULL) {
			if (free_slot < 0)
				free_slot = i;
			continue;
		}

		if (p == msvc)
			return (-1);

		if (strcasecmp(p->name, msvc->name) == 0)
			return (-2);
	}

	if (free_slot < 0)
		return (-3);

	mlrpc_services[free_slot] = msvc;
	return (0);
}

void
mlrpc_unregister_service(mlrpc_service_t *msvc)
{
	int i;

	for (i = 0; i < NDL_MAX_SERVICES; i++) {
		if (mlrpc_services[i] == msvc)
			mlrpc_services[i] = NULL;
	}
}

int
mlrpc_list_services(char *buffer, int bufsize)
{
	mlrpc_service_t *msvc;
	smb_ctxbuf_t ctx;
	int i;

	(void) smb_ctxbuf_init(&ctx, (uint8_t *)buffer, bufsize);

	for (i = 0; i < NDL_MAX_SERVICES; i++) {
		if ((msvc = mlrpc_services[i]) != 0) {
			(void) smb_ctxbuf_printf(&ctx, "%-16s %s\n",
			    msvc->name, msvc->desc);
		}
	}

	return (smb_ctxbuf_len(&ctx));
}

/*
 * Allocate a handle for use with the server-side RPC functions.
 * The handle contains the machine SID and an incrementing counter,
 * which should make each handle unique.
 *
 * An arbitrary caller context can be associated with the handle
 * via data; it will not be dereferenced by the handle API.
 *
 * The uuid for the new handle is returned after it has been added
 * to the global handle list.
 */
ndr_hdid_t *
ndr_hdalloc(const ndr_xa_t *xa, const void *data)
{
	static ndr_hdid_t uuid;
	ndr_handle_t *hd;
	nt_sid_t *sid;

	if ((hd = malloc(sizeof (ndr_handle_t))) == NULL)
		return (NULL);

	if (uuid.data[1] == 0) {
		if ((sid = nt_domain_local_sid()) == NULL)
			return (NULL);

		uuid.data[0] = 0;
		uuid.data[1] = 0;
		uuid.data[2] = sid->SubAuthority[1];
		uuid.data[3] = sid->SubAuthority[2];
		uuid.data[4] = sid->SubAuthority[3];
	}

	++uuid.data[1];

	bcopy(&uuid, &hd->nh_id, sizeof (ndr_hdid_t));
	hd->nh_fid = xa->fid;
	hd->nh_svc = xa->binding->service;
	hd->nh_data = (void *)data;

	(void) mutex_lock(&ndr_handle_lock);
	hd->nh_next = ndr_handle_list;
	ndr_handle_list = hd;
	(void) mutex_unlock(&ndr_handle_lock);

	return (&hd->nh_id);
}

/*
 * Remove a handle from the global list and free it.
 */
void
ndr_hdfree(const ndr_xa_t *xa, const ndr_hdid_t *id)
{
	mlrpc_service_t *svc = xa->binding->service;
	ndr_handle_t *hd;
	ndr_handle_t **pphd;

	assert(id);

	(void) mutex_lock(&ndr_handle_lock);
	pphd = &ndr_handle_list;

	while (*pphd) {
		hd = *pphd;

		if (bcmp(&hd->nh_id, id, sizeof (ndr_hdid_t)) == 0) {
			if (hd->nh_svc == svc) {
				*pphd = hd->nh_next;
				free(hd);
			}
			break;
		}

		pphd = &(*pphd)->nh_next;
	}

	(void) mutex_unlock(&ndr_handle_lock);
}

/*
 * Lookup a handle by id.  If the handle is in the list and it matches
 * the specified service, a pointer to it is returned.  Otherwise a null
 * pointer is returned.
 */
ndr_handle_t *
ndr_hdlookup(const ndr_xa_t *xa, const ndr_hdid_t *id)
{
	mlrpc_service_t *svc = xa->binding->service;
	ndr_handle_t *hd;

	assert(id);
	(void) mutex_lock(&ndr_handle_lock);
	hd = ndr_handle_list;

	while (hd) {
		if (bcmp(&hd->nh_id, id, sizeof (ndr_hdid_t)) == 0) {
			if (hd->nh_svc != svc)
				break;
			(void) mutex_unlock(&ndr_handle_lock);
			return (hd);
		}

		hd = hd->nh_next;
	}

	(void) mutex_unlock(&ndr_handle_lock);
	return (NULL);
}

/*
 * Called when a pipe is closed to release any associated handles.
 */
void
ndr_hdclose(int fid)
{
	ndr_handle_t *hd;
	ndr_handle_t **pphd;

	(void) mutex_lock(&ndr_handle_lock);
	pphd = &ndr_handle_list;

	while (*pphd) {
		hd = *pphd;

		if (hd->nh_fid == fid) {
			*pphd = hd->nh_next;
			free(hd);
			continue;
		}

		pphd = &(*pphd)->nh_next;
	}

	(void) mutex_unlock(&ndr_handle_lock);
}

void
mlrpc_uuid_to_str(ndr_uuid_t *uuid, char *str)
{
	(void) sprintf(str, "%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x",
	    uuid->data1, uuid->data2, uuid->data3,
	    uuid->data4[0], uuid->data4[1],
	    uuid->data4[2], uuid->data4[3],
	    uuid->data4[4], uuid->data4[5],
	    uuid->data4[6], uuid->data4[7]);
}

int
mlrpc_str_to_uuid(char *str, ndr_uuid_t *uuid)
{
	char 		*p = str;
	char 		*q;
	char		buf[4];
	int		i;

	uuid->data1 = strtoul(p, &p, 16);
	if (*p != '-')
		return (0);
	p++;

	uuid->data2 = strtol(p, &p, 16);
	if (*p != '-')
		return (0);
	p++;

	uuid->data3 = strtol(p, &p, 16);
	if (*p != '-')
		return (0);
	p++;

	for (i = 0; i < 8; i++) {
		if (p[0] == 0 || p[1] == 0)
			return (0);

		buf[0] = *p++;
		buf[1] = *p++;
		buf[2] = 0;
		uuid->data4[i] = strtol(buf, &q, 16);
		if (*q != 0)
			return (0);
	}

	if (*p != 0)
		return (0);

	return (1);
}

void
mlrpc_binding_pool_initialize(struct mlrpc_binding **headpp,
    struct mlrpc_binding pool[], unsigned n_pool)
{
	struct mlrpc_binding	*head = NULL;
	int			ix;

	for (ix = n_pool - 1; ix >= 0; ix--) {
		pool[ix].next = head;
		pool[ix].service = NULL;
		pool[ix].p_cont_id = 0xffff;
		pool[ix].instance_specific = 0;
		head = &pool[ix];
	}

	*headpp = head;
}

struct mlrpc_binding *
mlrpc_find_binding(struct mlrpc_xaction *mxa, mlrpc_p_context_id_t p_cont_id)
{
	struct mlrpc_binding *mbind;

	for (mbind = mxa->binding_list; mbind; mbind = mbind->next) {
		if (mbind->service != NULL &&
		    mbind->which_side == MLRPC_BIND_SIDE_SERVER &&
		    mbind->p_cont_id == p_cont_id)
			break;
	}

	return (mbind);
}

struct mlrpc_binding *
mlrpc_new_binding(struct mlrpc_xaction *mxa)
{
	struct mlrpc_binding *mbind;

	for (mbind = mxa->binding_list; mbind; mbind = mbind->next) {
		if (mbind->service == NULL)
			break;
	}

	return (mbind);
}
