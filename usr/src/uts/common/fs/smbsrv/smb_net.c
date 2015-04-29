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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cpuvar.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/time.h>
#include <sys/varargs.h>
#include <sys/modctl.h>
#include <sys/pathname.h>
#include <sys/fs/snode.h>
#include <sys/fs/dv_node.h>
#include <sys/vnode.h>
#include <sys/ksocket.h>
#undef mem_free /* XXX Remove this after we convert everything to kmem_alloc */

#include <smbsrv/smb_vops.h>
#include <smbsrv/smb.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_kstat.h>

static	kmem_cache_t	*smb_txr_cache = NULL;

/*
 * smb_net_init
 *
 *	This function initializes the resources necessary to access the
 *	network. It assumes it won't be called simultaneously by multiple
 *	threads.
 *
 * Return Value
 *
 *	0	Initialization successful
 *	ENOMEM	Initialization failed
 */
void
smb_net_init(void)
{

	if (smb_txr_cache != NULL)
		return;

	smb_txr_cache = kmem_cache_create(SMBSRV_KSTAT_TXRCACHE,
	    sizeof (smb_txreq_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
}

/*
 * smb_net_fini
 *
 *	This function releases the resources allocated by smb_net_init(). It
 *	assumes it won't be called simultaneously by multiple threads.
 *	This function can safely be called even if smb_net_init() hasn't been
 *	called previously.
 *
 * Return Value
 *
 *	None
 */
void
smb_net_fini(void)
{
	if (smb_txr_cache) {
		kmem_cache_destroy(smb_txr_cache);
		smb_txr_cache = NULL;
	}
}

/*
 * SMB Network Socket API
 *
 * smb_socreate:	Creates an socket based on domain/type.
 * smb_soshutdown:	Disconnect a socket created with smb_socreate
 * smb_sodestroy:	Release resources associated with a socket
 * smb_sosend:		Send the contents of a buffer on a socket
 * smb_sorecv:		Receive data into a buffer from a socket
 * smb_iov_sosend:	Send the contents of an iovec on a socket
 * smb_iov_sorecv:	Receive data into an iovec from a socket
 */

ksocket_t
smb_socreate(int domain, int type, int protocol)
{
	ksocket_t	sock;
	int		err = 0;

	err = ksocket_socket(&sock, domain, type, protocol, KSOCKET_SLEEP,
	    CRED());

	if (err != 0)
		return (NULL);
	else
		return (sock);
}

/*
 * smb_soshutdown will disconnect the socket and prevent subsequent PDU
 * reception and transmission.  The sonode still exists but its state
 * gets modified to indicate it is no longer connected.  Calls to
 * smb_sorecv/smb_iov_sorecv will return so smb_soshutdown can be used
 * regain control of a thread stuck in smb_sorecv.
 */
void
smb_soshutdown(ksocket_t so)
{
	(void) ksocket_shutdown(so, SHUT_RDWR, CRED());
}

/*
 * smb_sodestroy releases all resources associated with a socket previously
 * created with smb_socreate.  The socket must be shutdown using smb_soshutdown
 * before the socket is destroyed with smb_sodestroy, otherwise undefined
 * behavior will result.
 */
void
smb_sodestroy(ksocket_t so)
{
	(void) ksocket_close(so, CRED());
}

int
smb_sorecv(ksocket_t so, void *msg, size_t len)
{
	size_t recvd;
	int err;

	ASSERT(so != NULL);
	ASSERT(len != 0);

	if ((err = ksocket_recv(so, msg, len, MSG_WAITALL, &recvd,
	    CRED())) != 0) {
		return (err);
	}

	/* Successful receive */
	return ((recvd == len) ? 0 : -1);
}

/*
 * smb_net_txl_constructor
 *
 *	Transmit list constructor
 */
void
smb_net_txl_constructor(smb_txlst_t *txl)
{
	ASSERT(txl->tl_magic != SMB_TXLST_MAGIC);

	mutex_init(&txl->tl_mutex, NULL, MUTEX_DEFAULT, NULL);
	list_create(&txl->tl_list, sizeof (smb_txreq_t),
	    offsetof(smb_txreq_t, tr_lnd));
	txl->tl_active = B_FALSE;
	txl->tl_magic = SMB_TXLST_MAGIC;
}

/*
 * smb_net_txl_destructor
 *
 *	Transmit list destructor
 */
void
smb_net_txl_destructor(smb_txlst_t *txl)
{
	ASSERT(txl->tl_magic == SMB_TXLST_MAGIC);

	txl->tl_magic = 0;
	list_destroy(&txl->tl_list);
	mutex_destroy(&txl->tl_mutex);
}

/*
 * smb_net_txr_alloc
 *
 *	Transmit buffer allocator
 */
smb_txreq_t *
smb_net_txr_alloc(void)
{
	smb_txreq_t	*txr;

	txr = kmem_cache_alloc(smb_txr_cache, KM_SLEEP);
	txr->tr_len = 0;
	bzero(&txr->tr_lnd, sizeof (txr->tr_lnd));
	txr->tr_magic = SMB_TXREQ_MAGIC;
	return (txr);
}

/*
 * smb_net_txr_free
 *
 *	Transmit buffer deallocator
 */
void
smb_net_txr_free(smb_txreq_t *txr)
{
	ASSERT(txr->tr_magic == SMB_TXREQ_MAGIC);
	ASSERT(!list_link_active(&txr->tr_lnd));

	txr->tr_magic = 0;
	kmem_cache_free(smb_txr_cache, txr);
}

/*
 * smb_net_txr_send
 *
 *	This routine puts the transmit buffer passed in on the wire. If another
 *	thread is already draining the transmit list, the transmit buffer is
 *	queued and the routine returns immediately.
 */
int
smb_net_txr_send(ksocket_t so, smb_txlst_t *txl, smb_txreq_t *txr)
{
	list_t		local;
	int		rc = 0;
	size_t		sent = 0;
	size_t		len;

	ASSERT(txl->tl_magic == SMB_TXLST_MAGIC);

	mutex_enter(&txl->tl_mutex);
	list_insert_tail(&txl->tl_list, txr);
	if (txl->tl_active) {
		mutex_exit(&txl->tl_mutex);
		return (0);
	}
	txl->tl_active = B_TRUE;

	list_create(&local, sizeof (smb_txreq_t),
	    offsetof(smb_txreq_t, tr_lnd));

	while (!list_is_empty(&txl->tl_list)) {
		list_move_tail(&local, &txl->tl_list);
		mutex_exit(&txl->tl_mutex);
		while ((txr = list_head(&local)) != NULL) {
			ASSERT(txr->tr_magic == SMB_TXREQ_MAGIC);
			list_remove(&local, txr);

			len = txr->tr_len;
			rc = ksocket_send(so, txr->tr_buf, txr->tr_len,
			    MSG_WAITALL, &sent, CRED());
			smb_net_txr_free(txr);
			if ((rc == 0) && (sent == len))
				continue;

			if (rc == 0)
				rc = -1;

			while ((txr = list_head(&local)) != NULL) {
				ASSERT(txr->tr_magic == SMB_TXREQ_MAGIC);
				list_remove(&local, txr);
				smb_net_txr_free(txr);
			}
			break;
		}
		mutex_enter(&txl->tl_mutex);
		if (rc == 0)
			continue;

		while ((txr = list_head(&txl->tl_list)) != NULL) {
			ASSERT(txr->tr_magic == SMB_TXREQ_MAGIC);
			list_remove(&txl->tl_list, txr);
			smb_net_txr_free(txr);
		}
		break;
	}
	txl->tl_active = B_FALSE;
	mutex_exit(&txl->tl_mutex);
	return (rc);
}
