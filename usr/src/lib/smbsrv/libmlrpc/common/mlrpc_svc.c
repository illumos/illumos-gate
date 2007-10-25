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
#include <string.h>
#include <strings.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/ndr.h>
#include <smbsrv/mlrpc.h>

#define	NDL_MAX_SERVICES	32
static struct mlrpc_service *mlrpc_services[NDL_MAX_SERVICES];

struct mlrpc_stub_table *
mlrpc_find_stub_in_svc(struct mlrpc_service *msvc, int opnum)
{
	struct mlrpc_stub_table *ste;

	for (ste = msvc->stub_table; ste->func; ste++) {
		if (ste->opnum == opnum)
			return (ste);
	}

	return (NULL);
}

struct mlrpc_service *
mlrpc_find_service_by_name(const char *name)
{
	struct mlrpc_service 	*msvc;
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

struct mlrpc_service *
mlrpc_find_service_by_uuids(mlrpc_uuid_t *as_uuid, int as_vers,
    mlrpc_uuid_t *ts_uuid, int ts_vers)
{
	struct mlrpc_service *msvc;
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
mlrpc_register_service(struct mlrpc_service *msvc)
{
	struct mlrpc_service 	*p;
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
mlrpc_unregister_service(struct mlrpc_service *msvc)
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
	struct mlrpc_service *msvc;
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

void
mlrpc_uuid_to_str(mlrpc_uuid_t *uuid, char *str)
{
	(void) sprintf(str, "%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x",
	    uuid->data1, uuid->data2, uuid->data3,
	    uuid->data4[0], uuid->data4[1],
	    uuid->data4[2], uuid->data4[3],
	    uuid->data4[4], uuid->data4[5],
	    uuid->data4[6], uuid->data4[7]);
}

int
mlrpc_str_to_uuid(char *str, mlrpc_uuid_t *uuid)
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
