/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * The illumos dlpi backend
 */

#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <libdlpi.h>

#include "config.h"
#include "debug.h"
#include "iov.h"
#include "mevent.h"
#include "net_backends.h"
#include "net_backends_priv.h"

/*
 * The size of the bounce buffer used to implement the peek callback.
 * This value should be big enough to accommodate the largest of all possible
 * frontend packet lengths. The value here matches the definition of
 * VTNET_MAX_PKT_LEN in pci_virtio_net.c
 */
#define	DLPI_BBUF_SIZE (65536 + 64)

typedef struct be_dlpi_priv {
	dlpi_handle_t bdp_dhp;
	struct mevent *bdp_mevp;
	/*
	 * A bounce buffer that allows us to implement the peek_recvlen
	 * callback. Each structure is only used by a single thread so
	 * one is enough.
	 */
	uint8_t bdp_bbuf[DLPI_BBUF_SIZE];
	ssize_t bdp_bbuflen;
} be_dlpi_priv_t;

static void
be_dlpi_cleanup(net_backend_t *be)
{
	be_dlpi_priv_t *priv = NET_BE_PRIV(be);

	if (priv->bdp_dhp != NULL)
		dlpi_close(priv->bdp_dhp);
	priv->bdp_dhp = NULL;

	if (priv->bdp_mevp != NULL)
		mevent_delete(priv->bdp_mevp);
	priv->bdp_mevp = NULL;

	priv->bdp_bbuflen = 0;
	be->fd = -1;
}

static void
be_dlpi_err(int ret, const char *dev, char *msg)
{
	EPRINTLN("%s: %s (%s)", dev, msg, dlpi_strerror(ret));
}

static int
be_dlpi_init(net_backend_t *be, const char *devname __unused,
     nvlist_t *nvl, net_be_rxeof_t cb, void *param)
{
	be_dlpi_priv_t *priv = NET_BE_PRIV(be);
	const char *vnic;
	int ret;

	if (cb == NULL) {
		EPRINTLN("dlpi backend requires non-NULL callback");
		return (-1);
	}

	vnic = get_config_value_node(nvl, "vnic");
	if (vnic == NULL) {
		EPRINTLN("dlpi backend requires a VNIC");
		return (-1);
	}

	priv->bdp_bbuflen = 0;

	ret = dlpi_open(vnic, &priv->bdp_dhp, DLPI_RAW);

	if (ret != DLPI_SUCCESS) {
		be_dlpi_err(ret, vnic, "open failed");
		goto error;
	}

	if ((ret = dlpi_bind(priv->bdp_dhp, DLPI_ANY_SAP, NULL)) !=
	    DLPI_SUCCESS) {
		be_dlpi_err(ret, vnic, "bind failed");
		goto error;
	}

	if (get_config_bool_node_default(nvl, "promiscrxonly", true)) {
		if ((ret = dlpi_promiscon(priv->bdp_dhp, DL_PROMISC_RX_ONLY)) !=
		    DLPI_SUCCESS) {
			be_dlpi_err(ret, vnic,
			    "enable promiscuous mode(rxonly) failed");
			goto error;
		}
	}
	if (get_config_bool_node_default(nvl, "promiscphys", false)) {
		if ((ret = dlpi_promiscon(priv->bdp_dhp, DL_PROMISC_PHYS)) !=
		    DLPI_SUCCESS) {
			be_dlpi_err(ret, vnic,
			    "enable promiscuous mode(physical) failed");
			goto error;
		}
	}
	if (get_config_bool_node_default(nvl, "promiscsap", true)) {
		if ((ret = dlpi_promiscon(priv->bdp_dhp, DL_PROMISC_SAP)) !=
		    DLPI_SUCCESS) {
			be_dlpi_err(ret, vnic,
			    "enable promiscuous mode(SAP) failed");
			goto error;
		}
	}
	if (get_config_bool_node_default(nvl, "promiscmulti", true)) {
		if ((ret = dlpi_promiscon(priv->bdp_dhp, DL_PROMISC_MULTI)) !=
		    DLPI_SUCCESS) {
			be_dlpi_err(ret, vnic,
			    "enable promiscuous mode(muticast) failed");
			goto error;
		}
	}

        be->fd = dlpi_fd(priv->bdp_dhp);

        if (fcntl(be->fd, F_SETFL, O_NONBLOCK) < 0) {
                EPRINTLN("%s: enable O_NONBLOCK failed", vnic);
		goto error;
        }

	priv->bdp_mevp = mevent_add_disabled(be->fd, EVF_READ, cb, param);
	if (priv->bdp_mevp == NULL) {
		EPRINTLN("Could not register event");
		goto error;
	}

	return (0);

error:
	be_dlpi_cleanup(be);
	return (-1);
}

/*
 * Called to send a buffer chain out to the dlpi device
 */
static ssize_t
be_dlpi_send(net_backend_t *be, const struct iovec *iov, int iovcnt)
{
	be_dlpi_priv_t *priv = NET_BE_PRIV(be);
	ssize_t len = 0;
	int ret;

	if (iovcnt == 1) {
		len = iov[0].iov_len;
		ret = dlpi_send(priv->bdp_dhp, NULL, 0, iov[0].iov_base, len,
		    NULL);
	} else {
		void *buf = NULL;

		len = iov_to_buf(iov, iovcnt, &buf);

		if (len <= 0 || buf == NULL)
			return (-1);

		ret = dlpi_send(priv->bdp_dhp, NULL, 0, buf, len, NULL);
		free(buf);
	}

	if (ret != DLPI_SUCCESS)
		return (-1);

	return (len);
}

static ssize_t
be_dlpi_peek_recvlen(net_backend_t *be)
{
	be_dlpi_priv_t *priv = NET_BE_PRIV(be);
	dlpi_recvinfo_t recv;
	size_t len;
	int ret;

	/*
	 * We already have a packet in the bounce buffer.
	 * Just return its length.
	 */
	if (priv->bdp_bbuflen > 0)
		return (priv->bdp_bbuflen);

	/*
	 * Read the next packet (if any) into the bounce buffer, so
	 * that we get to know its length and we can return that
	 * to the caller.
	 */
	len = sizeof (priv->bdp_bbuf);
	ret = dlpi_recv(priv->bdp_dhp, NULL, NULL, priv->bdp_bbuf, &len,
	    0, &recv);
	if (ret == DL_SYSERR) {
		if (errno == EWOULDBLOCK)
			return (0);
		return (-1);
	} else if (ret == DLPI_ETIMEDOUT) {
		return (0);
	} else if (ret != DLPI_SUCCESS) {
		return (-1);
	}

	if (recv.dri_totmsglen > sizeof (priv->bdp_bbuf)) {
		EPRINTLN("DLPI bounce buffer was too small! - needed %x bytes",
		    recv.dri_totmsglen);
	}

	priv->bdp_bbuflen = len;

	return (len);
}

static ssize_t
be_dlpi_recv(net_backend_t *be, const struct iovec *iov, int iovcnt)
{
	be_dlpi_priv_t *priv = NET_BE_PRIV(be);
	size_t len;
	int ret;

	if (priv->bdp_bbuflen > 0) {
		/*
		 * A packet is available in the bounce buffer, so
		 * we read it from there.
		 */
		len = buf_to_iov(priv->bdp_bbuf, priv->bdp_bbuflen,
		    iov, iovcnt);

		/* Mark the bounce buffer as empty. */
		priv->bdp_bbuflen = 0;

		if (len == 0)
			return (-1);

		return (len);
	}

	len = iov[0].iov_len;
	ret = dlpi_recv(priv->bdp_dhp, NULL, NULL,
	    (uint8_t *)iov[0].iov_base, &len, 0, NULL);
	if (ret == DL_SYSERR) {
		if (errno == EWOULDBLOCK)
			return (0);
		return (-1);
	} else if (ret == DLPI_ETIMEDOUT) {
		return (0);
	} else if (ret != DLPI_SUCCESS) {
		return (-1);
	}

	return (len);
}

static void
be_dlpi_recv_enable(net_backend_t *be)
{
	be_dlpi_priv_t *priv = NET_BE_PRIV(be);

	mevent_enable(priv->bdp_mevp);
}

static void
be_dlpi_recv_disable(net_backend_t *be)
{
	be_dlpi_priv_t *priv = NET_BE_PRIV(be);

	mevent_disable(priv->bdp_mevp);
}

static uint64_t
be_dlpi_get_cap(net_backend_t *be)
{
	return (0); /* no capabilities for now */
}

static int
be_dlpi_set_cap(net_backend_t *be, uint64_t features,
    unsigned vnet_hdr_len)
{
	return ((features || vnet_hdr_len) ? -1 : 0);
}

static int
be_dlpi_get_mac(net_backend_t *be, void *buf, size_t *buflen)
{
	be_dlpi_priv_t *priv = NET_BE_PRIV(be);
	uchar_t physaddr[DLPI_PHYSADDR_MAX];
	size_t physaddrlen = DLPI_PHYSADDR_MAX;
	int ret;

	if ((ret = dlpi_get_physaddr(priv->bdp_dhp, DL_CURR_PHYS_ADDR,
	    physaddr, &physaddrlen)) != DLPI_SUCCESS) {
		be_dlpi_err(ret, dlpi_linkname(priv->bdp_dhp),
		    "read MAC address failed");
		return (EINVAL);
	}

	if (physaddrlen != ETHERADDRL) {
		EPRINTLN("%s: bad MAC address len %d",
		    dlpi_linkname(priv->bdp_dhp), physaddrlen);
		return (EINVAL);
	}

	if (physaddrlen > *buflen) {
		EPRINTLN("%s: MAC address too long (%d bytes required)",
		    dlpi_linkname(priv->bdp_dhp), physaddrlen);
		return (ENOMEM);
	}

	*buflen = physaddrlen;
	memcpy(buf, physaddr, *buflen);

	return (0);
}

static struct net_backend dlpi_backend = {
	.prefix = "dlpi",
	.priv_size = sizeof(struct be_dlpi_priv),
	.init = be_dlpi_init,
	.cleanup = be_dlpi_cleanup,
	.send = be_dlpi_send,
	.peek_recvlen = be_dlpi_peek_recvlen,
	.recv = be_dlpi_recv,
	.recv_enable = be_dlpi_recv_enable,
	.recv_disable = be_dlpi_recv_disable,
	.get_cap = be_dlpi_get_cap,
	.set_cap = be_dlpi_set_cap,
	.get_mac = be_dlpi_get_mac,
};

DATA_SET(net_backend_set, dlpi_backend);
