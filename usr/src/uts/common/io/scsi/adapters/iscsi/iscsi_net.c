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
 *
 * iSCSI Software Initiator
 */

#include <sys/socket.h>		/* networking stuff */
#include <sys/strsubr.h>	/* networking stuff */
#include <netinet/tcp.h>	/* TCP_NODELAY */
#include <sys/socketvar.h>	/* _ALLOC_SLEEP */
#include <sys/pathname.h>	/* declares:	lookupname */
#include <sys/fs/snode.h>	/* defines:	VTOS */
#include <sys/fs/dv_node.h>	/* declares:	devfs_lookupname */
#include <netinet/in.h>
#include "iscsi.h"

/*
 * This is a high level description of the default
 * iscsi_net transport interfaces.  These are used
 * to create, send, recv, and close standard TCP/IP
 * messages.  In addition there are extensions to send
 * and recv iSCSI PDU data.
 *
 * NOTE: It would be very easy for an iSCSI HBA vendor
 * to register their own functions over the top of
 * the default interfaces.  This would allow an iSCSI
 * HBA to use the same iscsiadm management interfaces
 * and the Solaris iSCSI session / connection management.
 * The current problem with this approach is we only
 * allow one one registered transport table.  This
 * would be pretty easy to correct although will require
 * additional CLI changes to manage multiple interfaces.
 * If a vendor can present compelling performance data,
 * then Sun will be willing to enhance this support for
 * multiple interface tables and better CLI management.
 *
 * The following listing describes the iscsi_net
 * entry points:
 *
 *   socket            - Creates TCP/IP socket connection.  In the
 *                       default implementation creates a sonode
 *                       via the sockfs kernel layer.
 *   bind              - Performs standard TCP/IP BSD operation.  In
 *                       the default implementation this only act
 *                       as a soft binding based on the IP and routing
 *	                 tables.  It would be preferred if this was
 *	                 a hard binding but that is currently not
 *	                 possible with Solaris's networking stack.
 *   connect           - Performs standard TCP/IP BSD operation.  This
 *                       establishes the TCP SYN to the peer IP address.
 *   listen            - Performs standard TCP/IP BSD operation.  This
 *                       listens for incoming peer connections.
 *   accept            - Performs standard TCP/IP BSD operation.  This
 *                       accepts incoming peer connections.
 *   shutdown          - This disconnects the TCP/IP connection while
 *                       maintaining the resources.
 *   close             - This disconnects the TCP/IP connection and
 *                       releases the resources.
 *
 *   getsockopt        - Gets socket option for specified socket.
 *   setsockopt        - Sets socket option for specified socket.
 *
 *      The current socket options that are used by the initiator
 *      are listed below.
 *
 *        TCP_CONN_NOTIFY_THRESHOLD
 *        TCP_CONN_ABORT_THRESHOLD
 *        TCP_ABORT_THRESHOLD
 *        TCP_NODELAY
 *        SO_RCVBUF
 *        SO_SNDBUF
 *
 *   iscsi_net_poll    - Poll socket interface for a specified amount
 *                       of data.  If data not received in timeout
 *                       period fail request.
 *   iscsi_net_sendmsg - Send message on socket connection
 *   iscsi_net_recvmsg - Receive message on socket connection
 *
 *   iscsi_net_sendpdu - Send iSCSI PDU on socket connection
 *   iscsi_net_recvhdr - Receive iSCSI header on socket connection
 *   iscsi_net_recvdata - Receive iSCSI data on socket connection
 *
 *     The iSCSI interfaces have the below optional flags.
 *
 *       ISCSI_NET_HEADER_DIGEST - The interface should either
 *				generate or validate the iSCSI
 *				header digest CRC.
 *       ISCSI_NET_DATA_DIGESt   - The interface should either
 *                              generate or validate the iSCSI
 *                              data digest CRC.
 */


/* global */
iscsi_network_t *iscsi_net;

/* consts */

/*
 * This table is used for quick validation of incoming
 * iSCSI PDU opcodes.  A value of '0' in the table below
 * indicated that the opcode is invalid for an iSCSI
 * initiator to receive.
 */
const int   is_incoming_opcode_invalid[256] = {
	/*		0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F */
	/* 0x0X */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0x1X */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0x2X */	0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0x3X */	1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
	/* 0x4X */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0x5X */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0x6X */	0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0x7X */	1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
	/* 0x8X */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0x9X */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0xAX */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0xBX */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0xCX */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0xDX */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0xEX */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0xFX */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

/* prototypes */
static void * iscsi_net_socket(int domain, int type, int protocol);
static int iscsi_net_bind(void *socket, struct sockaddr *
    name, int name_len, int backlog, int flags);
static int iscsi_net_connect(void *socket, struct sockaddr *
    name, int name_len, int fflag, int flags);
static int iscsi_net_listen(void *socket, int backlog);
static void * iscsi_net_accept(void *socket, struct sockaddr *addr,
    int *addr_len);
static int iscsi_net_getsockname(void *socket);
static int iscsi_net_getsockopt(void *socket, int level,
    int option_name, void *option_val, int *option_len, int flags);
static int iscsi_net_setsockopt(void *socket, int level,
    int option_name, void *option_val, int option_len);
static int iscsi_net_shutdown(void *socket, int how);
static void iscsi_net_close(void *socket);

static size_t iscsi_net_poll(void *socket, clock_t timeout);
static size_t iscsi_net_sendmsg(void *socket, struct msghdr *msg);
static size_t iscsi_net_recvmsg(void *socket,
    struct msghdr *msg, int timeout);

static iscsi_status_t iscsi_net_sendpdu(void *socket, iscsi_hdr_t *ihp,
    char *data, int flags);
static iscsi_status_t iscsi_net_recvdata(void *socket, iscsi_hdr_t *ihp,
    char *data, int max_data_length, int timeout, int flags);
static iscsi_status_t iscsi_net_recvhdr(void *socket, iscsi_hdr_t *ihp,
    int header_length, int timeout, int flags);

static void iscsi_net_set_preconnect_options(void *socket);
static void iscsi_net_set_postconnect_options(void *socket);

/*
 * +--------------------------------------------------------------------+
 * | network interface registration functions                           |
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_net_init - initialize network interface
 */
void
iscsi_net_init()
{
	iscsi_net = kmem_zalloc(sizeof (*iscsi_net), KM_SLEEP);

	iscsi_net->socket	= iscsi_net_socket;

	iscsi_net->bind		= iscsi_net_bind;
	iscsi_net->connect	= iscsi_net_connect;
	iscsi_net->listen	= iscsi_net_listen;
	iscsi_net->accept	= iscsi_net_accept;
	iscsi_net->shutdown	= iscsi_net_shutdown;
	iscsi_net->close	= iscsi_net_close;

	iscsi_net->getsockname	= iscsi_net_getsockname;
	iscsi_net->getsockopt	= iscsi_net_getsockopt;
	iscsi_net->setsockopt	= iscsi_net_setsockopt;

	iscsi_net->poll		= iscsi_net_poll;
	iscsi_net->sendmsg	= iscsi_net_sendmsg;
	iscsi_net->recvmsg	= iscsi_net_recvmsg;

	iscsi_net->sendpdu	= iscsi_net_sendpdu;
	iscsi_net->recvhdr	= iscsi_net_recvhdr;
	iscsi_net->recvdata	= iscsi_net_recvdata;
}

/*
 * iscsi_net_fini - release network interface
 */
void
iscsi_net_fini()
{
	kmem_free(iscsi_net, sizeof (*iscsi_net));
	iscsi_net = NULL;
}


/*
 * iscsi_net_set_preconnect_options -
 */
static void
iscsi_net_set_preconnect_options(void *socket)
{
	int ret = 0;
	ret += iscsi_net->setsockopt(socket, IPPROTO_TCP,
	    TCP_CONN_NOTIFY_THRESHOLD, (char *)&iscsi_net->tweaks.
	    conn_notify_threshold, sizeof (int));
	ret += iscsi_net->setsockopt(socket, IPPROTO_TCP,
	    TCP_CONN_ABORT_THRESHOLD, (char *)&iscsi_net->tweaks.
	    conn_abort_threshold, sizeof (int));
	ret += iscsi_net->setsockopt(socket, IPPROTO_TCP, TCP_ABORT_THRESHOLD,
	    (char *)&iscsi_net->tweaks.abort_threshold, sizeof (int));
	if (ret != 0) {
		cmn_err(CE_NOTE, "iscsi connection failed to set socket option"
		    "TCP_CONN_NOTIFY_THRESHOLD, TCP_CONN_ABORT_THRESHOLD or "
		    "TCP_ABORT_THRESHOLD");
	}
}

/*
 * iscsi_net_set_postconnect_options -
 */
static void
iscsi_net_set_postconnect_options(void *socket)
{
	int ret = 0;
	ret += iscsi_net->setsockopt(socket, IPPROTO_TCP, TCP_NODELAY,
	    (char *)&iscsi_net->tweaks.nodelay, sizeof (int));
	ret += iscsi_net->setsockopt(socket, SOL_SOCKET, SO_RCVBUF,
	    (char *)&iscsi_net->tweaks.rcvbuf, sizeof (int));
	ret += iscsi_net->setsockopt(socket, SOL_SOCKET, SO_SNDBUF,
	    (char *)&iscsi_net->tweaks.sndbuf, sizeof (int));
	if (ret != 0) {
		cmn_err(CE_NOTE, "iscsi connection failed to set socket option"
		    "TCP_NODELAY, SO_RCVBUF or SO_SNDBUF");
	}
}


/*
 * +--------------------------------------------------------------------+
 * | register network interfaces                                        |
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_net_socket - create socket
 */
static void *
iscsi_net_socket(int domain, int type, int protocol)
{
	vnode_t		*dvp		= NULL,
	    *vp		= NULL;
	struct snode	*csp		= NULL;
	int		err		= 0;
	major_t		maj;

	/* ---- solookup: start ---- */
	if ((vp = solookup(domain, type, protocol, NULL, &err)) == NULL) {

		/*
		 * solookup calls sogetvp if the vp is not found in
		 * the cache.  Since the call to sogetvp is hardwired
		 * to use USERSPACE and declared static we'll do the
		 * work here instead.
		 */
		err = lookupname(type == SOCK_STREAM ? "/dev/tcp" : "/dev/udp",
		    UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);
		if (err)
			return (NULL);

		/* ---- check that it is the correct vnode ---- */
		if (vp->v_type != VCHR) {
			VN_RELE(vp);
			return (NULL);
		}

		csp = VTOS(VTOS(vp)->s_commonvp);
		if (!(csp->s_flag & SDIPSET)) {
			char    *pathname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			err = ddi_dev_pathname(vp->v_rdev, S_IFCHR,
			    pathname);
			if (err == 0) {
				err = devfs_lookupname(pathname, NULLVPP,
				    &dvp);
			}
			VN_RELE(vp);
			kmem_free(pathname, MAXPATHLEN);
			if (err != 0) {
				return (NULL);
			}
			vp = dvp;
		}

		maj = getmajor(vp->v_rdev);
		if (!STREAMSTAB(maj)) {
			VN_RELE(vp);
			return (NULL);
		}
	}
	/* ---- solookup: end ---- */
	return (socreate(vp, domain, type, protocol, SOV_DEFAULT, NULL, &err));
}

/*
 * iscsi_net_bind - bind socket to a specific sockaddr
 */
static int
iscsi_net_bind(void *socket, struct sockaddr *name, int name_len,
	int backlog, int flags)
{
	return (sobind((struct sonode *)socket, name, name_len,
	    backlog, flags));
}

/*
 * iscsi_net_connect - connect socket to peer sockaddr
 */
static int
iscsi_net_connect(void *socket, struct sockaddr *name, int name_len,
	int fflag, int flags)
{
	int rval;

	iscsi_net_set_preconnect_options(socket);
	rval = soconnect((struct sonode *)socket, name,
	    name_len, fflag, flags);
	iscsi_net_set_postconnect_options(socket);

	return (rval);
}

/*
 * iscsi_net_listen - listen to socket for peer connections
 */
static int
iscsi_net_listen(void *socket, int backlog)
{
	return (solisten((struct sonode *)socket, backlog));
}

/*
 * iscsi_net_accept - accept peer socket connections
 */
static void *
iscsi_net_accept(void *socket, struct sockaddr *addr, int *addr_len)
{
	struct sonode *listening_socket;

	(void) soaccept((struct sonode *)socket,
	    ((struct sonode *)socket)->so_flag,
	    &listening_socket);
	if (listening_socket != NULL) {
		bcopy(listening_socket->so_faddr_sa, addr,
		    (socklen_t)listening_socket->so_faddr_len);
		*addr_len = listening_socket->so_faddr_len;
	} else {
		*addr_len = 0;
	}

	return ((void *)listening_socket);
}

/*
 * iscsi_net_getsockname -
 */
static int
iscsi_net_getsockname(void *socket)
{
	return (sogetsockname((struct sonode *)socket));
}

/*
 * iscsi_net_getsockopt - get value of option on socket
 */
static int
iscsi_net_getsockopt(void *socket, int level, int option_name,
	void *option_val, int *option_len, int flags)
{
	return (sogetsockopt((struct sonode *)socket, level,
	    option_name, option_val, (socklen_t *)option_len,
	    flags));
}

/*
 * iscsi_net_setsockopt - set value for option on socket
 */
static int
iscsi_net_setsockopt(void *socket, int level, int option_name,
	void *option_val, int option_len)
{
	return (sosetsockopt((struct sonode *)socket, level,
	    option_name, option_val, option_len));
}

/*
 * iscsi_net_shutdown - shutdown socket connection
 */
static int
iscsi_net_shutdown(void *socket, int how)
{
	return (soshutdown((struct sonode *)socket, how));
}

/*
 * iscsi_net_close - shutdown socket connection and release resources
 */
static void
iscsi_net_close(void *socket)
{
	vnode_t *vp = SOTOV((struct sonode *)socket);
	(void) soshutdown((struct sonode *)socket, 2);
	(void) VOP_CLOSE(vp, 0, 1, 0, kcred, NULL);
	VN_RELE(vp);
}

/*
 * iscsi_net_poll - poll socket for data
 */
static size_t
iscsi_net_poll(void *socket, clock_t timeout)
{
	int pflag;
	uchar_t pri;
	rval_t rval;

	pri = 0;
	pflag = MSG_ANY;
	return (kstrgetmsg(SOTOV((struct sonode *)socket), NULL, NULL,
	    &pri, &pflag, timeout, &rval));
}

/*
 * iscsi_net_sendmsg - send message on socket
 */
/* ARGSUSED */
static size_t
iscsi_net_sendmsg(void *socket, struct msghdr *msg)
{
	int i = 0;
	int total_len = 0;
	struct uio uio;

	/* Initialization of the uio structure. */
	bzero(&uio, sizeof (uio));
	uio.uio_iov = msg->msg_iov;
	uio.uio_iovcnt = msg->msg_iovlen;
	uio.uio_segflg  = UIO_SYSSPACE;

	for (i = 0; i < msg->msg_iovlen; i++) {
		total_len += (msg->msg_iov)[i].iov_len;
	}
	uio.uio_resid = total_len;

	(void) sosendmsg((struct sonode *)socket, msg, &uio);
	DTRACE_PROBE2(sosendmsg, size_t, total_len, size_t, uio.uio_resid);
	return (total_len - uio.uio_resid);
}

/*
 * iscsi_net_recvmsg - receive message on socket
 */
/* ARGSUSED */
static size_t
iscsi_net_recvmsg(void *socket, struct msghdr *msg, int timeout)
{
	int		idx;
	int		total_len   = 0;
	struct uio	uio;
	uchar_t		pri	    = 0;
	int		prflag	    = MSG_ANY;
	rval_t		rval;
	struct sonode	*sonode	    = (struct sonode *)socket;

	/* Initialization of the uio structure. */
	bzero(&uio, sizeof (uio));
	uio.uio_iov	    = msg->msg_iov;
	uio.uio_iovcnt	    = msg->msg_iovlen;
	uio.uio_segflg	    = UIO_SYSSPACE;

	for (idx = 0; idx < msg->msg_iovlen; idx++) {
		total_len += (msg->msg_iov)[idx].iov_len;
	}
	uio.uio_resid = total_len;

	/* If timeout requested on receive */
	if (timeout > 0) {
		boolean_t   loopback = B_FALSE;

		/* And this isn't a loopback connection */
		if (sonode->so_laddr.soa_sa->sa_family == AF_INET) {
			struct sockaddr_in *lin =
			    (struct sockaddr_in *)sonode->so_laddr.soa_sa;
			struct sockaddr_in *fin =
			    (struct sockaddr_in *)sonode->so_faddr.soa_sa;

			if ((lin->sin_family == fin->sin_family) &&
			    (bcmp(&lin->sin_addr, &fin->sin_addr,
			    sizeof (struct in_addr)) == 0)) {
				loopback = B_TRUE;
			}
		} else {
			struct sockaddr_in6 *lin6 =
			    (struct sockaddr_in6 *)sonode->so_laddr.soa_sa;
			struct sockaddr_in6 *fin6 =
			    (struct sockaddr_in6 *)sonode->so_faddr.soa_sa;

			if ((lin6->sin6_family == fin6->sin6_family) &&
			    (bcmp(&lin6->sin6_addr, &fin6->sin6_addr,
			    sizeof (struct in6_addr)) == 0)) {
				loopback = B_TRUE;
			}
		}

		if (loopback == B_FALSE) {
			/*
			 * Then poll device for up to the timeout
			 * period or the requested data is received.
			 */
			if (kstrgetmsg(SOTOV(sonode),
			    NULL, NULL, &pri, &prflag, timeout * 1000,
			    &rval) == ETIME) {
				return (0);
			}
		}
	}

	/*
	 * Receive the requested data.  Block until all
	 * data is received.
	 *
	 * resid occurs only when the connection is
	 * disconnected.  In that case it will return
	 * the amount of data that was not received.
	 * In general this is the total amount we
	 * requested.
	 */
	(void) sorecvmsg((struct sonode *)socket, msg, &uio);
	DTRACE_PROBE2(sorecvmsg, size_t, total_len, size_t, uio.uio_resid);
	return (total_len - uio.uio_resid);
}

/*
 * iscsi_net_sendpdu - send iscsi pdu on socket
 */
static iscsi_status_t
iscsi_net_sendpdu(void *socket, iscsi_hdr_t *ihp, char *data, int flags)
{
	uint32_t	pad;
	uint32_t	crc_hdr;
	uint32_t	crc_data;
	uint32_t	pad_len;
	uint32_t	data_len;
	iovec_t		iovec[ISCSI_MAX_IOVEC];
	int		iovlen = 0;
	size_t		total_len = 0;
	size_t		send_len;
	struct msghdr	msg;

	ASSERT(socket != NULL);
	ASSERT(ihp != NULL);

	/*
	 * Let's send the header first.  'hlength' is in 32-bit
	 * quantities, so we need to multiply by four to get bytes
	 */
	ASSERT(iovlen < ISCSI_MAX_IOVEC);
	iovec[iovlen].iov_base = (void *)ihp;
	iovec[iovlen].iov_len  = sizeof (*ihp) + ihp->hlength * 4;
	total_len += sizeof (*ihp) + ihp->hlength * 4;
	iovlen++;

	/* Let's transmit the header digest if we have to. */
	if ((flags & ISCSI_NET_HEADER_DIGEST) != 0) {
		ASSERT(iovlen < ISCSI_MAX_IOVEC);
		/*
		 * Converting the calculated CRC via htonl is not
		 * necessary because iscsi_crc32c calculates
		 * the value as it expects to be written
		 */
		crc_hdr = iscsi_crc32c((char *)ihp,
		    sizeof (iscsi_hdr_t) + ihp->hlength * 4);

		iovec[iovlen].iov_base = (void *)&crc_hdr;
		iovec[iovlen].iov_len  = sizeof (crc_hdr);
		total_len += sizeof (crc_hdr);
		iovlen++;
	}

	/* Let's transmit the data if any. */
	data_len = ntoh24(ihp->dlength);

	if (data_len) {

		ASSERT(iovlen < ISCSI_MAX_IOVEC);
		iovec[iovlen].iov_base = (void *)data;
		iovec[iovlen].iov_len  = data_len;
		total_len += data_len;
		iovlen++;

		pad_len = ((ISCSI_PAD_WORD_LEN -
		    (data_len & (ISCSI_PAD_WORD_LEN - 1))) &
		    (ISCSI_PAD_WORD_LEN - 1));

		/* Let's transmit the data pad if any. */
		if (pad_len) {

			ASSERT(iovlen < ISCSI_MAX_IOVEC);
			pad = 0;
			iovec[iovlen].iov_base = (void *)&pad;
			iovec[iovlen].iov_len  = pad_len;
			total_len += pad_len;
			iovlen++;
		}

		/* Let's transmit the data digest if we have to. */
		if ((flags & ISCSI_NET_DATA_DIGEST) != 0) {

			ASSERT(iovlen < ISCSI_MAX_IOVEC);
			/*
			 * Converting the calculated CRC via htonl is not
			 * necessary because iscsi_crc32c calculates the
			 * value as it expects to be written
			 */
			crc_data = iscsi_crc32c(data, data_len);
			crc_data = iscsi_crc32c_continued(
			    (char *)&pad, pad_len, crc_data);

			iovec[iovlen].iov_base = (void *)&crc_data;
			iovec[iovlen].iov_len  = sizeof (crc_data);
			total_len += sizeof (crc_data);
			iovlen++;
		}
	}

	DTRACE_PROBE4(tx, void *, socket, iovec_t *, &iovec[0],
	    int, iovlen, int, total_len);

	/* Initialization of the message header. */
	bzero(&msg, sizeof (msg));
	msg.msg_iov	= &iovec[0];
	msg.msg_flags	= MSG_WAITALL;
	msg.msg_iovlen	= iovlen;

	send_len = iscsi_net->sendmsg((struct sonode *)socket, &msg);
	DTRACE_PROBE2(sendmsg, size_t, total_len, size_t, send_len);
	if (total_len != send_len) {
		return (ISCSI_STATUS_TCP_TX_ERROR);
	}
	return (ISCSI_STATUS_SUCCESS);
}

/*
 * iscsi_net_recvhdr - receive iscsi hdr on socket
 */
static iscsi_status_t
iscsi_net_recvhdr(void *socket, iscsi_hdr_t *ihp, int header_length,
    int timeout, int flags)
{
	iovec_t		    iov[ISCSI_MAX_IOVEC];
	int		    iovlen		= 1;
	int		    total_len		= 0;
	uint32_t	    crc_actual		= 0;
	uint32_t	    crc_calculated	= 0;
	char		    *adhdr		= NULL;
	int		    adhdr_length	= 0;
	struct msghdr	    msg;
	size_t		    recv_len;

	ASSERT(socket != NULL);
	ASSERT(ihp != NULL);

	if (header_length < sizeof (iscsi_hdr_t)) {
		ASSERT(FALSE);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	/*
	 * Receive primary header
	 */
	iov[0].iov_base = (char *)ihp;
	iov[0].iov_len = sizeof (iscsi_hdr_t);

	bzero(&msg, sizeof (msg));
	msg.msg_iov	= iov;
	msg.msg_flags	= MSG_WAITALL;
	msg.msg_iovlen	= iovlen;

	recv_len = iscsi_net->recvmsg(socket, &msg, timeout);
	if (recv_len != sizeof (iscsi_hdr_t)) {
		return (ISCSI_STATUS_TCP_RX_ERROR);
	}

	DTRACE_PROBE2(rx_hdr, void *, socket, iovec_t *iop, &iov[0]);

	/* verify incoming opcode is a valid operation */
	if (is_incoming_opcode_invalid[ihp->opcode]) {
		cmn_err(CE_WARN, "iscsi connection(%p) protocol error - "
		    "received an unsupported opcode:0x%02x",
		    socket, ihp->opcode);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	/*
	 * Setup receipt of additional header
	 */
	if (ihp->hlength > 0) {
		adhdr = ((char *)ihp) + sizeof (iscsi_hdr_t);
		adhdr_length = header_length - sizeof (iscsi_hdr_t);
		/* make sure enough space is available for adhdr */
		if (ihp->hlength > adhdr_length) {
			ASSERT(FALSE);
			return (ISCSI_STATUS_INTERNAL_ERROR);
		}

		ASSERT(iovlen < ISCSI_MAX_IOVEC);
		iov[iovlen].iov_base = adhdr;
		iov[iovlen].iov_len = adhdr_length;
		total_len += adhdr_length;
		iovlen++;
	}

	/*
	 * Setup receipt of header digest if enabled and connection
	 * is in full feature mode.
	 */
	if ((flags & ISCSI_NET_HEADER_DIGEST) != 0) {
		ASSERT(iovlen < ISCSI_MAX_IOVEC);
		iov[iovlen].iov_base = (char *)&crc_actual;
		iov[iovlen].iov_len = sizeof (uint32_t);
		total_len += sizeof (uint32_t);
		iovlen++;
	}

	/*
	 * Read additional header and/or header digest if pieces
	 * are available
	 */
	if (iovlen > 1) {

		bzero(&msg, sizeof (msg));
		msg.msg_iov	= iov;
		msg.msg_flags	= MSG_WAITALL;
		msg.msg_iovlen	= iovlen;

		recv_len = iscsi_net->recvmsg(socket, &msg, timeout);
		if (recv_len != total_len) {
			return (ISCSI_STATUS_TCP_RX_ERROR);
		}

		DTRACE_PROBE4(rx_adhdr_digest, void *, socket,
		    iovec_t *iop, &iov[0], int, iovlen, int, total_len);

		/*
		 * Verify header digest if enabled and connection
		 * is in full feature mode
		 */
		if ((flags & ISCSI_NET_HEADER_DIGEST) != 0) {
			crc_calculated = iscsi_crc32c((uchar_t *)ihp,
			    sizeof (iscsi_hdr_t) + ihp->hlength * 4);

			/*
			 * Converting actual CRC read via ntohl is not
			 * necessary because iscsi_crc32c calculates the
			 * value as it expect to be read
			 */
			if (crc_calculated != crc_actual) {
				/* Invalid Header Digest */
				cmn_err(CE_WARN, "iscsi connection(%p) "
				    "protocol error - encountered a header "
				    "digest error expected:0x%08x "
				    "received:0x%08x", socket,
				    crc_calculated, crc_actual);
				return (ISCSI_STATUS_HEADER_DIGEST_ERROR);
			}
		}
	}
	return (ISCSI_STATUS_SUCCESS);
}


/*
 * iscsi_net_recvdata - receive iscsi data payload from socket
 */
static iscsi_status_t
iscsi_net_recvdata(void *socket, iscsi_hdr_t *ihp, char *data,
    int max_data_length, int timeout, int flags)
{
	struct iovec	iov[3];
	int		iovlen			= 1;
	int		total_len		= 0;
	int		dlength			= 0;
	int		pad_len			= 0;
	uint8_t		pad[ISCSI_PAD_WORD_LEN];
	uint32_t	crc_calculated		= 0;
	uint32_t	crc_actual		= 0;
	struct msghdr	msg;
	size_t		recv_len;

	ASSERT(socket != NULL);
	ASSERT(ihp != NULL);
	ASSERT(data != NULL);

	/* short hand dlength */
	dlength = ntoh24(ihp->dlength);

	/* verify dlength is valid */
	if (dlength > max_data_length) {
		cmn_err(CE_WARN, "iscsi connection(%p) protocol error - "
		    "invalid data lengths itt:0x%x received:0x%x "
		    "max expected:0x%x", socket, ihp->itt,
		    dlength, max_data_length);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	if (dlength) {

		/* calculate pad */
		pad_len = ((ISCSI_PAD_WORD_LEN -
		    (dlength & (ISCSI_PAD_WORD_LEN - 1))) &
		    (ISCSI_PAD_WORD_LEN - 1));

		/* setup data iovec */
		iov[0].iov_base	= (char *)data;
		iov[0].iov_len	= dlength;
		total_len	= dlength;

		/* if pad setup pad iovec */
		if (pad_len) {
			iov[iovlen].iov_base	= (char *)&pad;
			iov[iovlen].iov_len	= pad_len;
			total_len		+= pad_len;
			iovlen++;
		}

		/* setup data digest */
		if ((flags & ISCSI_NET_DATA_DIGEST) != 0) {
			iov[iovlen].iov_base	= (char *)&crc_actual;
			iov[iovlen].iov_len	= sizeof (crc_actual);
			total_len		+= sizeof (crc_actual);
			iovlen++;
		}

		bzero(&msg, sizeof (msg));
		msg.msg_iov	= iov;
		msg.msg_flags	= MSG_WAITALL;
		msg.msg_iovlen	= iovlen;

		recv_len = iscsi_net->recvmsg(socket, &msg, timeout);
		if (recv_len != total_len) {
			return (ISCSI_STATUS_TCP_RX_ERROR);
		}

		DTRACE_PROBE4(rx_data, void *, socket, iovec_t *iop,
		    &iov[0], int, iovlen, int, total_len);

		/* verify data digest is present */
		if ((flags & ISCSI_NET_DATA_DIGEST) != 0) {

			crc_calculated = iscsi_crc32c(data, dlength);
			crc_calculated = iscsi_crc32c_continued(
			    (char *)&pad, pad_len, crc_calculated);

			/*
			 * Converting actual CRC read via ntohl is not
			 * necessary because iscsi_crc32c calculates the
			 * value as it expects to be read
			 */
			if (crc_calculated != crc_actual) {
				cmn_err(CE_WARN, "iscsi connection(%p) "
				    "protocol error - encountered a data "
				    "digest error itt:0x%x expected:0x%08x "
				    "received:0x%08x", socket,
				    ihp->itt, crc_calculated, crc_actual);
				return (ISCSI_STATUS_DATA_DIGEST_ERROR);
			}
		}
	}
	return (ISCSI_STATUS_SUCCESS);
}
