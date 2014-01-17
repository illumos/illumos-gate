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
 * Copyright 2000 by Cisco Systems, Inc.  All rights reserved.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * iSCSI Software Initiator
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/pathname.h>
#include <sys/door.h>
#include <sys/kmem.h>
#include <sys/socket.h>
#include <sys/fs/snode.h>
#include <netinet/in.h>

#include <sys/scsi/adapters/iscsi_door.h>
#include "iscsi.h"

#define	ISCSI_DOOR_MAX_SEMA_VALUE	16

static boolean_t	iscsi_door_init = B_FALSE;
static ksema_t		iscsi_door_sema;
static krwlock_t	iscsi_door_lock;
static door_handle_t	iscsi_door_handle;

typedef struct _mybuffer {
	size_t		signature;
	size_t		size;
} mybuffer_t;

/*
 * iscsi_door_ini
 *
 * This function initializes the variables needed to handle the door upcall.
 */
boolean_t
iscsi_door_ini(void)
{
	ASSERT(!iscsi_door_init);
	if (!iscsi_door_init) {
		rw_init(
		    &iscsi_door_lock,
		    NULL,
		    RW_DRIVER,
		    NULL);

		sema_init(
		    &iscsi_door_sema,
		    ISCSI_DOOR_MAX_SEMA_VALUE,
		    NULL,
		    SEMA_DRIVER,
		    NULL);

		iscsi_door_handle = NULL;
		iscsi_door_init = B_TRUE;
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * iscsi_door_term
 *
 * This function releases the resources allocated to handle the door
 * upcall.  It disconnects from the door if currently connected.
 */
boolean_t
iscsi_door_term(void)
{
	ASSERT(iscsi_door_init);
	if (iscsi_door_init) {
		iscsi_door_init = B_FALSE;
		iscsi_door_unbind();
		rw_destroy(&iscsi_door_lock);
		sema_destroy(&iscsi_door_sema);
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * iscsi_door_bind
 *
 * This function tries to connect the iscsi_door.  If it succeeds
 * it keeps the vnode.
 */
boolean_t
iscsi_door_bind(
	int		did
)
{
	door_handle_t	new_handle;

	new_handle = door_ki_lookup(did);
	if (new_handle == NULL) {
		/* The lookup failed. */
		return (B_FALSE);
	}

	/* The new handle is stored.  If we had one, it is released. */
	rw_enter(&iscsi_door_lock, RW_WRITER);
	if (iscsi_door_handle != NULL) {
		door_ki_rele(iscsi_door_handle);
	}
	iscsi_door_handle = new_handle;
	rw_exit(&iscsi_door_lock);

	return (B_TRUE);
}

/*
 * iscsi_door_unbind
 *
 * This function releases the current door handle.
 */
void
iscsi_door_unbind(void)
{
	rw_enter(&iscsi_door_lock, RW_WRITER);
	if (iscsi_door_handle != NULL) {
		door_ki_rele(iscsi_door_handle);
		iscsi_door_handle = NULL;
	}
	rw_exit(&iscsi_door_lock);
}

/*
 * iscsi_door_upcall
 *
 * This function tries to call the iscsi_door.
 */
static
boolean_t
iscsi_door_upcall(door_arg_t *arg)
{
	int	error;

	/*
	 * This semaphore limits the number of simultaneous calls
	 * to the door.
	 */
	sema_p(&iscsi_door_sema);
	/*
	 * The mutex protecting the iscsi_door_handle is entered.
	 */
	rw_enter(&iscsi_door_lock, RW_READER);

	if (iscsi_door_handle == NULL) {
		/* There's no door handle. */
		rw_exit(&iscsi_door_lock);
		sema_v(&iscsi_door_sema);
		return (B_FALSE);
	}
	error = door_ki_upcall(iscsi_door_handle, arg);

	rw_exit(&iscsi_door_lock);
	sema_v(&iscsi_door_sema);

	if (error != 0) {
		return (B_FALSE);
	} else {
		return (B_TRUE);
	}
}

/*
 * kfreehostent
 *
 * This function frees the memory returned by kgetipnodebyname.
 */
void
kfreehostent(
	struct hostent		*hptr
)
{
	mybuffer_t		*buffer;

	ASSERT(hptr != NULL);
	if (hptr) {
		buffer = (mybuffer_t *)((char *)hptr - sizeof (mybuffer_t));
		ASSERT(buffer->signature == ISCSI_DOOR_REQ_SIGNATURE);
		if (buffer->signature == ISCSI_DOOR_REQ_SIGNATURE) {
			kmem_free((void *)buffer, buffer->size);
			return;
		}
	}
	/* A message should be logged here. */
}

/*
 * kgetipnodebyname
 *
 * This function builds a request that will be sent to the iscsi_door.
 * The iSCSI door after receiving the request calls getipnodebyaddr().
 * for more information on the input, output parameter and return value,
 * consult the man page for getipnodebyname().
 *
 * Before calling the iscsi door this function tries to do the conversion
 * locally.  If a name resolution is needed the iscsi door is called.
 *
 * There's some limitations to the information returned by this function.
 * Only one address of the address list returned by getipnodebyname() is
 * returned.  The other parameters of the structure should be ignored.
 */
struct hostent *
kgetipnodebyname(
	const char	*name,
	int		af,
	int		flags,
	int		*error_num
)
{
	door_arg_t		arg;
	mybuffer_t		*buffer;
	size_t			msg_size = ISCSI_DOOR_MAX_DATA_SIZE;
	size_t			hostent_size = ISCSI_DOOR_MAX_DATA_SIZE;
	size_t			buffer_size;
	getipnodebyname_req_t	*req;
	getipnodebyname_cnf_t	*cnf;
	struct hostent		*hptr;


	buffer_size = msg_size + hostent_size + sizeof (mybuffer_t);
	buffer = (mybuffer_t *)kmem_zalloc(buffer_size, KM_SLEEP);

	if (buffer) {

		/*
		 * The buffer was successfully allocated.
		 *
		 *	  Buffer
		 *
		 * +--------------------+ <--- buffer
		 * |	mybuffer_t	|
		 * +--------------------+ <--- hptr
		 * |			|
		 * |			|
		 * |	hostent_size	|
		 * |			|
		 * |			|
		 * |			|
		 * +--------------------+ <--- req, cnf
		 * |			|
		 * |			|
		 * |			|
		 * |	msg_size	|
		 * |			|
		 * |			|
		 * |			|
		 * +--------------------+
		 */
		buffer->signature = ISCSI_DOOR_REQ_SIGNATURE;
		buffer->size = buffer_size;

		hptr = (struct hostent *)((char *)buffer + sizeof (mybuffer_t));
		req = (getipnodebyname_req_t *)((char *)hptr + hostent_size);
		cnf = (getipnodebyname_cnf_t *)((char *)hptr + hostent_size);

		hostent_size -= sizeof (struct hostent);

		/*
		 * We try first locally.  If the conversion cannot be done
		 * by inet_pton the door is called.
		 * The cnf address is used as output buffer.
		 * inet_pton returns '1' if the conversion was successful.
		 */
		switch (af) {
		case AF_INET:
			hptr->h_length = sizeof (struct in_addr);
			break;
		case AF_INET6:
			hptr->h_length = sizeof (struct in6_addr);
			break;
		default:
			kfreehostent(hptr);
			*error_num = NO_RECOVERY;
			return (NULL);
		}
		if ((msg_size < hptr->h_length) ||
		    (hostent_size < sizeof (char *))) {
			kfreehostent(hptr);
			*error_num = NO_RECOVERY;
			return (NULL);
		}
		if (inet_pton(af, (char *)name, cnf) == 1) {
			/*
			 * inet_pton converted the string successfully.
			 */
			hptr->h_addrtype = af;
			hptr->h_addr_list = (char **)((char *)hptr +
			    sizeof (struct hostent));
			*hptr->h_addr_list = (char *)cnf;
			return (hptr);
		}

		/*
		 * The name couldn't ne converted by inet_pton.  The door is
		 * called.
		 */

		/* Header initialization. */
		req->hdr.signature = ISCSI_DOOR_REQ_SIGNATURE;
		req->hdr.version = ISCSI_DOOR_REQ_VERSION_1;
		req->hdr.opcode = ISCSI_DOOR_GETIPNODEBYNAME_REQ;

		/* Body initialization. */
		req->name_length = strlen(name);
		if (req->name_length >
		    (msg_size - sizeof (getipnodebyname_req_t) - 1)) {
			kfreehostent(hptr);
			*error_num = NO_RECOVERY;
			return (NULL);
		}

		req->name_offset = sizeof (getipnodebyname_req_t);
		req->af = af;
		req->flags = flags;
		bcopy(
		    name,
		    ((char *)req + req->name_offset),
		    req->name_length);

		/* Door argument initialization. */
		arg.data_ptr = (char *)req;
		arg.data_size = msg_size;
		arg.desc_num = 0;
		arg.desc_ptr = NULL;
		arg.rbuf = (char *)cnf;
		arg.rsize = msg_size;

		if (iscsi_door_upcall(&arg) == B_FALSE) {
			/* The door call failed */
			kfreehostent(hptr);
			*error_num = NO_RECOVERY;
			return (NULL);
		}

		/*
		 * The door call itself was successful.  The value returned
		 * in arg.rbuf should be cnf, but we never know.
		 */
		cnf = (getipnodebyname_cnf_t *)arg.rbuf;

		if ((cnf == NULL) ||
		    (arg.rsize < sizeof (getipnodebyname_cnf_t)) ||
		    (cnf->hdr.signature != ISCSI_DOOR_REQ_SIGNATURE) ||
		    (cnf->hdr.version != ISCSI_DOOR_REQ_VERSION_1) ||
		    (cnf->hdr.opcode != ISCSI_DOOR_GETIPNODEBYNAME_CNF) ||
		    ((cnf->hdr.status != ISCSI_DOOR_STATUS_SUCCESS) &&
		    (cnf->hdr.status != ISCSI_DOOR_STATUS_MORE))) {
			/* The door didn't like the request */
			kfreehostent(hptr);
			*error_num = NO_RECOVERY;
			return (NULL);
		}

		if (cnf->h_addr_list_length == 0) {
			kfreehostent(hptr);
			*error_num = HOST_NOT_FOUND;
			return (NULL);
		}

		hptr->h_addrtype = cnf->h_addrtype;
		hptr->h_length = cnf->h_addrlen;
		hptr->h_addr_list = (char **)((char *)hptr +
		    sizeof (struct hostent));
		*hptr->h_addr_list = ((char *)cnf + cnf->h_addr_list_offset);
		return (hptr);
	} else {
		*error_num = NO_RECOVERY;
		return (NULL);
	}
}
