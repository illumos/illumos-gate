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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <uuid/uuid.h>
#include <ctype.h>
#include <synch.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <assert.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>


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
#define	NDR_MAX_SERVICES	32
static ndr_service_t *ndr_services[NDR_MAX_SERVICES];

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
ndr_svc_register(ndr_service_t *svc)
{
	ndr_service_t 	*p;
	int		free_slot = -1;
	int		i;

	for (i = 0; i < NDR_MAX_SERVICES; i++) {
		if ((p = ndr_services[i]) == NULL) {
			if (free_slot < 0)
				free_slot = i;
			continue;
		}

		if (p == svc)
			return (-1);

		if (strcasecmp(p->name, svc->name) == 0)
			return (-2);
	}

	if (free_slot < 0)
		return (-3);

	ndr_services[free_slot] = svc;
	return (0);
}

void
ndr_svc_unregister(ndr_service_t *svc)
{
	int i;

	for (i = 0; i < NDR_MAX_SERVICES; i++) {
		if (ndr_services[i] == svc)
			ndr_services[i] = NULL;
	}
}

ndr_stub_table_t *
ndr_svc_find_stub(ndr_service_t *svc, int opnum)
{
	ndr_stub_table_t *ste;

	for (ste = svc->stub_table; ste->func; ste++) {
		if (ste->opnum == opnum)
			return (ste);
	}

	return (NULL);
}

ndr_service_t *
ndr_svc_lookup_name(const char *name)
{
	ndr_service_t 	*svc;
	int			i;

	for (i = 0; i < NDR_MAX_SERVICES; i++) {
		if ((svc = ndr_services[i]) == NULL)
			continue;

		if (strcasecmp(name, svc->name) != 0)
			continue;

		ndo_printf(0, 0, "%s %s", svc->name, svc->desc);
		return (svc);
	}

	return (NULL);
}

ndr_service_t *
ndr_svc_lookup_uuid(ndr_uuid_t *as_uuid, int as_vers,
    ndr_uuid_t *ts_uuid, int ts_vers)
{
	ndr_service_t *svc;
	char abstract_syntax[UUID_PRINTABLE_STRING_LENGTH];
	char transfer_syntax[UUID_PRINTABLE_STRING_LENGTH];
	int i;

	if (as_uuid)
		ndr_uuid_unparse(as_uuid, abstract_syntax);

	if (ts_uuid)
		ndr_uuid_unparse(ts_uuid, transfer_syntax);

	for (i = 0; i < NDR_MAX_SERVICES; i++) {
		if ((svc = ndr_services[i]) == NULL)
			continue;

		if (as_uuid) {
			if (svc->abstract_syntax_uuid == 0)
				continue;

			if (svc->abstract_syntax_version != as_vers)
				continue;

			if (strcasecmp(abstract_syntax,
			    svc->abstract_syntax_uuid))
				continue;
		}

		if (ts_uuid) {
			if (svc->transfer_syntax_uuid == 0)
				continue;

			if (svc->transfer_syntax_version != ts_vers)
				continue;

			if (strcasecmp(transfer_syntax,
			    svc->transfer_syntax_uuid))
				continue;
		}

		ndo_printf(0, 0, "%s %s", svc->name, svc->desc);
		return (svc);
	}

	ndo_printf(0, 0, "ndr_svc_lookup_uuid: unknown service");
	ndo_printf(0, 0, "abstract=%s v%d, transfer=%s v%d",
	    abstract_syntax, as_vers, transfer_syntax, ts_vers);
	return (NULL);
}

/*
 * Allocate a handle for use with the server-side RPC functions.
 *
 * An arbitrary caller context can be associated with the handle
 * via data; it will not be dereferenced by the handle API.
 */
ndr_hdid_t *
ndr_hdalloc(const ndr_xa_t *xa, const void *data)
{
	static ndr_hdid_t id;
	ndr_handle_t *hd;
	uuid_t uu;

	if ((hd = malloc(sizeof (ndr_handle_t))) == NULL)
		return (NULL);

	if (id.data2 == 0) {
		uuid_generate_random(uu);
		bcopy(uu, &id.data2, sizeof (uuid_t));
		id.data1 = 0;
		id.data2 = 0;
	}

	++id.data2;

	bcopy(&id, &hd->nh_id, sizeof (ndr_hdid_t));
	hd->nh_pipe = xa->pipe;
	hd->nh_svc = xa->binding->service;
	hd->nh_data = (void *)data;
	hd->nh_data_free = NULL;

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
	ndr_service_t *svc = xa->binding->service;
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
	ndr_service_t *svc = xa->binding->service;
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
ndr_hdclose(ndr_pipe_t *pipe)
{
	ndr_handle_t *hd;
	ndr_handle_t **pphd;

	(void) mutex_lock(&ndr_handle_lock);
	pphd = &ndr_handle_list;

	while (*pphd) {
		hd = *pphd;

		if (hd->nh_pipe == pipe) {
			*pphd = hd->nh_next;

			if (hd->nh_data_free)
				(*hd->nh_data_free)(hd->nh_data);

			free(hd);
			continue;
		}

		pphd = &(*pphd)->nh_next;
	}

	(void) mutex_unlock(&ndr_handle_lock);
}

/*
 * Convert a UUID to a string.
 */
void
ndr_uuid_unparse(ndr_uuid_t *uuid, char *out)
{
	(void) sprintf(out, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	    uuid->data1, uuid->data2, uuid->data3,
	    uuid->data4[0], uuid->data4[1],
	    uuid->data4[2], uuid->data4[3],
	    uuid->data4[4], uuid->data4[5],
	    uuid->data4[6], uuid->data4[7]);
}

/*
 * Convert a string to a UUID.
 */
int
ndr_uuid_parse(char *in, ndr_uuid_t *uuid)
{
	char 		*p = in;
	char 		*q;
	char		buf[4];
	int		i;

	if (strlen(in) != UUID_PRINTABLE_STRING_LENGTH - 1)
		return (-1);

	uuid->data1 = strtoul(p, &p, 16);
	if (*p != '-')
		return (-1);
	p++;

	uuid->data2 = strtol(p, &p, 16);
	if (*p != '-')
		return (-1);
	p++;

	uuid->data3 = strtol(p, &p, 16);
	if (*p != '-')
		return (-1);
	p++;

	for (i = 0; i < 8; i++) {
		if (*p ==  '-')
			p++;

		if (p[0] == 0 || p[1] == 0)
			return (-1);

		buf[0] = *p++;
		buf[1] = *p++;
		buf[2] = 0;
		uuid->data4[i] = strtol(buf, &q, 16);
		if (*q != 0)
			return (-1);
	}

	if (*p != 0)
		return (-1);

	return (0);
}

void
ndr_svc_binding_pool_init(ndr_binding_t **headpp, ndr_binding_t pool[],
    int n_pool)
{
	ndr_binding_t	*head = NULL;
	int		ix;

	for (ix = n_pool - 1; ix >= 0; ix--) {
		pool[ix].next = head;
		pool[ix].service = NULL;
		pool[ix].p_cont_id = 0xffff;
		pool[ix].instance_specific = 0;
		head = &pool[ix];
	}

	*headpp = head;
}

ndr_binding_t *
ndr_svc_find_binding(ndr_xa_t *mxa, ndr_p_context_id_t p_cont_id)
{
	ndr_binding_t *mbind;

	for (mbind = mxa->binding_list; mbind; mbind = mbind->next) {
		if (mbind->service != NULL &&
		    mbind->which_side == NDR_BIND_SIDE_SERVER &&
		    mbind->p_cont_id == p_cont_id)
			break;
	}

	return (mbind);
}

ndr_binding_t *
ndr_svc_new_binding(ndr_xa_t *mxa)
{
	ndr_binding_t *mbind;

	for (mbind = mxa->binding_list; mbind; mbind = mbind->next) {
		if (mbind->service == NULL)
			break;
	}

	return (mbind);
}

/*
 * Move bytes between a buffer and a uio structure.
 * The transfer direction is controlled by rw:
 *	UIO_READ:  transfer from buf to uio
 *	UIO_WRITE: transfer from uio to buf
 *
 * Returns the number of bytes moved.
 */
ssize_t
ndr_uiomove(caddr_t buf, size_t buflen, enum uio_rw rw, struct uio *uio)
{
	struct iovec *iov;
	int reading = (rw == UIO_READ);
	size_t nbytes;
	size_t nxfer = 0;

	assert(rw == UIO_READ || rw == UIO_WRITE);

	while (buflen && uio->uio_resid && uio->uio_iovcnt) {
		iov = uio->uio_iov;
		if ((nbytes = iov->iov_len) == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}

		if (nbytes > buflen)
			nbytes = buflen;

		if (reading)
			bcopy(buf, iov->iov_base, nbytes);
		else
			bcopy(iov->iov_base, buf, nbytes);

		iov->iov_base += nbytes;
		iov->iov_len -= nbytes;
		uio->uio_resid -= nbytes;
		uio->uio_offset += nbytes;
		buf += nbytes;
		buflen -= nbytes;
		nxfer += nbytes;
	}

	return (nxfer);
}
