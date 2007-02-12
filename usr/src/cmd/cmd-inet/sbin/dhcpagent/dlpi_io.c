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
#include <sys/types.h>
#include <sys/pfmod.h>
#include <sys/socket.h>
#include <net/if.h>			/* IFNAMSIZ */
#include <netinet/in.h>			/* in_addr (ip.h) */
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stropts.h>
#include <string.h>			/* strpbrk */
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/dlpi.h>
#include <unistd.h>
#include <stdlib.h>
#include <dhcpmsg.h>
#include <libinetutil.h>

#include "dlprims.h"
#include "dlpi_io.h"
#include "v4_sum_impl.h"

/*
 * dhcp_dlpi_open(): opens a DLPI stream to the given interface and returns
 *		     information purpose about that interface.
 *
 *   input: const char *: the name of the interface to open
 *	    dl_info_ack_t *: a place to store information about the interface
 *	    size_t: the size of dl_info_ack_t
 *	    t_uscalar_t: the sap to bind to on this interface
 *  output: int: the open file descriptor on success, -1 on failure
 */

int
dhcp_dlpi_open(const char *if_name, dl_info_ack_t *dlia, size_t dlia_size,
    t_uscalar_t dl_sap)
{
	char		device_name[sizeof ("/dev/") + IFNAMSIZ];
	int		fd;
	ifspec_t	ifsp;
	int		is_style2 = 0;

	if (!ifparse_ifspec(if_name, &ifsp)) {
		dhcpmsg(MSG_ERROR, "dhcp_dlpi_open: invalid interface name");
		return (-1);
	}

	if (ifsp.ifsp_modcnt != 0) {
		dhcpmsg(MSG_ERROR, "dhcp_dlpi_open: modules cannot be "
		    "specified with an interface name");
		return (-1);
	}

	/* try dlpi style1 interface first; if it fails, try style 2 */
	(void) snprintf(device_name, sizeof (device_name),
	    "/dev/%s%d", ifsp.ifsp_devnm, ifsp.ifsp_ppa);
	if ((fd = open(device_name, O_RDWR)) == -1) {
		dhcpmsg(MSG_DEBUG, "dhcp_dlpi_open: open on `%s'", device_name);

		/* try style 2 interface */
		(void) snprintf(device_name, sizeof (device_name),
		    "/dev/%s", ifsp.ifsp_devnm);
		fd = open(device_name, O_RDWR);

		/*
		 * temporary hack:  if the style-2 open of the /dev link fails,
		 * try the corresponding /devices/pseudo path.  this allows a
		 * diskless boot to succeed without necessarily pre-creating the
		 * /dev links, by taking advantage of devfs's ability to create
		 * /devices nodes for h/w devices on demand.  this is to avoid
		 * the need to fiddle with packaging scripts to boot off a new
		 * NIC device.  when /dev links are created on demand, this
		 * work-around may be removed.
		 */

		{
			const char prefix[] = "/devices/pseudo/clone@0:";
			char path[sizeof (prefix) + IFNAMSIZ];
			if (fd == -1 && errno == ENOENT) {
				(void) snprintf(path, sizeof (path), "%s%s",
				    prefix, ifsp.ifsp_devnm);
				fd = open(path, O_RDWR);
			}
		}

		if (fd == -1) {
			dhcpmsg(MSG_ERR, "dhcp_dlpi_open: open on `%s'",
			    device_name);
			return (-1);
		}
		is_style2 = 1;
	}

	/*
	 * okay, so we've got an open DLPI stream now.  make sure that
	 * it's DL_VERSION_2, DL_STYLE2, and that it's connectionless.
	 * from there, attach to the appropriate ppa, bind to dl_sap,
	 * and get ready to roll.
	 */

	if (dlinforeq(fd, dlia, dlia_size) != 0) {
		dhcpmsg(MSG_ERR, "dhcp_dlpi_open: DL_INFO_REQ on %s (1)",
		    device_name);
		(void) close(fd);
		return (-1);
	}

	if (dlia->dl_version != DL_VERSION_2) {
		dhcpmsg(MSG_ERROR, "dhcp_dlpi_open: %s is DLPI version %ld, "
		    "not 2", device_name, dlia->dl_version);
		(void) close(fd);
		return (-1);
	}

	if (is_style2 && dlia->dl_provider_style != DL_STYLE2) {
		dhcpmsg(MSG_ERROR,
		    "dhcp_dlpi_open: %s is DL_STYLE %lx, not DL_STYLE2",
		    device_name, dlia->dl_provider_style);
		(void) close(fd);
		return (-1);
	}

	if ((dlia->dl_service_mode & DL_CLDLS) == 0) {
		dhcpmsg(MSG_ERROR, "dhcp_dlpi_open: %s is %#lx, not DL_CLDLS, "
		    "which is not supported", device_name,
		    dlia->dl_service_mode);
		(void) close(fd);
		return (-1);
	}

	if (is_style2 && dlattachreq(fd, ifsp.ifsp_ppa) == -1) {
		dhcpmsg(MSG_ERR, "dhcp_dlpi_open: DL_ATTACH_REQ on %s",
		    device_name);
		(void) close(fd);
		return (-1);
	}

	if (dlbindreq(fd, dl_sap, 0, DL_CLDLS, 0) == -1) {
		dhcpmsg(MSG_ERR, "dhcp_dlpi_open: DL_BIND_REQ on %s",
		    device_name);
		(void) close(fd);
		return (-1);
	}

	/*
	 * we call this again since some of the information obtained
	 * previously was not valid since we had not yet attached (in
	 * particular, our MAC address) (but we needed to check the
	 * STYLE before we did the attach)
	 */

	if (dlinforeq(fd, dlia, dlia_size) != 0) {
		dhcpmsg(MSG_ERR, "dhcp_dlpi_open: DL_INFO_REQ on %s (2)",
		    device_name);
		(void) close(fd);
		return (-1);
	}

	if (ioctl(fd, I_PUSH, "pfmod") == -1) {
		dhcpmsg(MSG_ERR, "dhcp_dlpi_open: cannot push pfmod on stream");
		(void) close(fd);
		return (-1);
	}

	(void) ioctl(fd, I_FLUSH, FLUSHR);
	return (fd);
}

/*
 * dhcp_dlpi_close(): closes a previously opened DLPI stream
 *
 *   input: int: the file descriptor of the DLPI stream
 *  output: int: 0 on success, -1 on failure
 */

int
dhcp_dlpi_close(int fd)
{
	/* don't bother dismantling.  it will happen automatically */
	return (close(fd));
}

/*
 * dlpi_recvfrom(): receives data on a DLPI stream
 *
 *   input: int: the socket to receive the data on
 *	    void *: a buffer to store the data in
 *	    size_t: the size of the buffer
 *	    struct sockaddr_in *: if non-NULL, sender's IP address is filled in
 *	    struct sockaddr_in *: if non-NULL, recipient's IP address
 *  output: ssize_t: the number of bytes read on success, -1 on failure
 */

ssize_t
dlpi_recvfrom(int fd, void *buffer, size_t buf_len, struct sockaddr_in *from,
    struct sockaddr_in *to)
{
	struct ip		*ip;
	struct udphdr		*udphdr;
	void			*data_buffer;
	ssize_t			data_length;

	data_length = buf_len + sizeof (struct ip) + sizeof (struct udphdr);
	data_buffer = malloc(data_length);

	if (data_buffer == NULL) {
		dhcpmsg(MSG_ERR, "dlpi_recvfrom: cannot allocate packet");
		return (-1);
	}

	data_length = dlpi_recv_link(fd, data_buffer, data_length, 0);
	if (data_length == -1)
		return (-1);

	/*
	 * since we're just pulling data off the wire, what we have
	 * may look nothing like a DHCP packet.  note that this
	 * shouldn't happen (pfmod should have tossed it already).
	 */

	if (data_length < sizeof (struct ip) + sizeof (struct udphdr)) {
		dhcpmsg(MSG_WARNING, "dlpi_recvfrom: dropped short packet");
		free(data_buffer);
		return (-1);
	}

	/*
	 * verify checksums
	 */

	ip = (struct ip *)data_buffer;
	if (ipv4cksum((uint16_t *)ip, ip->ip_hl << 2) != 0) {
		dhcpmsg(MSG_WARNING, "dlpi_recvfrom: dropped packet with bad "
		    "ipv4 checksum");
		free(data_buffer);
		return (-1);
	}

	udphdr = (struct udphdr *)&ip[1];
	if ((udphdr->uh_sum != 0) &&
	    (udp_chksum(udphdr, &ip->ip_src, &ip->ip_dst, ip->ip_p) != 0)) {
		dhcpmsg(MSG_WARNING, "dlpi_recvfrom: dropped packet with bad "
		    "UDP checksum");
		free(data_buffer);
		return (-1);
	}

	data_length -= (sizeof (struct ip) + sizeof (struct udphdr));
	(void) memcpy(buffer, &udphdr[1], data_length);

	if (from != NULL) {
		from->sin_family = AF_INET;
		from->sin_addr = ip->ip_src;
		from->sin_port = udphdr->uh_sport;
	}

	if (to != NULL) {
		to->sin_family = AF_INET;
		to->sin_addr = ip->ip_dst;
		to->sin_port = udphdr->uh_dport;
	}

	free(data_buffer);
	return (data_length);
}

/*
 * dlpi_recv_link(): receives raw data on a DLPI stream
 *
 *   input: int: the DLPI stream to receive the data on
 *	    void *: a buffer to store the data in
 *	    size_t: the size of the buffer
 *	    uint32_t: flags (see dlpi_io.h)
 *  output: ssize_t: the number of bytes received on success, -1 on failure
 */

ssize_t
dlpi_recv_link(int fd, void *data_buffer, size_t data_length, uint32_t flags)
{
	int			getmsg_flags = 0;
	struct strbuf		ctrl, data;
	char			ctrlbuf[1024];

	ctrl.maxlen = sizeof (ctrlbuf);
	ctrl.buf    = ctrlbuf;

	data.maxlen = data_length;
	data.buf    = data_buffer;

	switch (getmsg(fd, &ctrl, &data, &getmsg_flags)) {

	case MORECTL:
	case MOREDATA:
	case MOREDATA|MORECTL:

		(void) ioctl(fd, I_FLUSH, FLUSHR);

		if ((flags & DLPI_RECV_SHORT) == 0)
			dhcpmsg(MSG_WARNING, "dlpi_recv_link: discarding stray "
			    "data on streamhead");
		break;

	case -1:
		dhcpmsg(MSG_ERR, "dlpi_recv_link: getmsg");
		return (-1);

	default:
		break;
	}

	return (data.len);
}


/*
 * dlpi_sendto(): sends UDP packets on a DLPI stream
 *
 *   input: int: the socket to send the packet on
 *	    void *: a buffer to send
 *	    size_t: the size of the buffer
 *	    struct sockaddr_in *: the IP address to send the data to
 *	    uchar_t *: the link-layer destination address
 *	    size_t: the size of the link-layer destination address
 *  output: ssize_t: the number of bytes sent on success, -1 on failure
 */

ssize_t
dlpi_sendto(int fd, void *buffer, size_t buf_len, struct sockaddr_in *to,
    uchar_t *dl_to, size_t dl_to_len)
{
	struct ip		*ip;
	struct udphdr		*udphdr;
	void			*data_buffer;
	size_t			data_length;
	static uint16_t		ip_id = 0;

	/*
	 * TODO: someday we might want to support `to' not being
	 * the same as INADDR_BROADCAST.  we don't need the support
	 * right now, but it's annoying to have a general interface
	 * that only supports a specific function.
	 */

	if (to->sin_addr.s_addr != htonl(INADDR_BROADCAST)) {
		dhcpmsg(MSG_ERROR, "dlpi_sendto: send to unicast address");
		return (-1);
	}

	/*
	 * we allocate one extra byte here in case the UDP checksum
	 * routine needs it to get the packet length to be even.
	 */

	data_length = sizeof (struct ip) + sizeof (struct udphdr) + buf_len;
	data_buffer = calloc(1, data_length + 1);
	if (data_buffer == NULL) {
		dhcpmsg(MSG_ERR, "dlpi_sendto: cannot allocate packet");
		return (-1);
	}

	ip	= (struct ip *)data_buffer;
	udphdr	= (struct udphdr *)&ip[1];

	(void) memcpy(&udphdr[1], buffer, buf_len);

	/*
	 * build the ipv4 header.  assume that our source address is 0
	 * (since we wouldn't be using DLPI if we could actually send
	 * packets an easier way).  note that we only need to set nonzero
	 * fields since we got calloc()'d memory above.
	 */

	/*
	 * From a purist's perspective, we should set the TTL to 1 for
	 * limited broadcasts. But operational experience (cisco routers)
	 * has shown that doing so results in the relay agent dropping our
	 * packets. These same devices (ciscos) also don't set the TTL
	 * to MAXTTL on the unicast side of the relay agent. Thus, the only
	 * safe thing to do is to always set the ttl to MAXTTL. Sigh.
	 */

	ip->ip_ttl	  = MAXTTL;

	ip->ip_v	  = 4;
	ip->ip_hl	  = sizeof (struct ip) / 4;
	ip->ip_id	  = htons(ip_id++);
	ip->ip_off	  = htons(IP_DF);
	ip->ip_p	  = IPPROTO_UDP;
	ip->ip_len	  = htons(data_length);
	ip->ip_dst	  = to->sin_addr;
	ip->ip_src.s_addr = htonl(INADDR_ANY);
	ip->ip_sum	  = ipv4cksum((uint16_t *)ip, sizeof (struct ip));

	udphdr->uh_ulen	  = htons(sizeof (struct udphdr) + buf_len);
	udphdr->uh_sport  = htons(IPPORT_BOOTPC);
	udphdr->uh_dport  = htons(IPPORT_BOOTPS);
	udphdr->uh_sum = udp_chksum(udphdr, &ip->ip_src, &ip->ip_dst, ip->ip_p);

	if (dlpi_send_link(fd, data_buffer, data_length, dl_to, dl_to_len)
	    == -1) {
		free(data_buffer);
		dhcpmsg(MSG_ERR, "dlpi_sendto: dlpi_send_link");
		return (-1);
	}

	free(data_buffer);
	return (buf_len);
}

/*
 * dlpi_send_link(): sends raw data down a DLPI stream
 *
 *   input: int: the DLPI stream to send the data on
 *	    void *: the raw data to send
 *	    size_t: the size of the raw data
 *	    uchar_t *: the link-layer destination address
 *	    size_t: the size of the link-layer destination address
 *  output: ssize_t: 0 on success, -1 on failure
 */

ssize_t
dlpi_send_link(int fd, void *data_buffer, size_t data_length,
    uchar_t *dest_addr, size_t dest_addr_length)
{
	struct strbuf		ctrl, data;
	ssize_t			retval;
	dl_unitdata_req_t	*dl_req;

	/*
	 * allocate the control part of the message and fill it in.
	 * all we really indicate is the destination address
	 */

	dl_req = malloc(sizeof (dl_unitdata_req_t) + data_length);
	if (dl_req == NULL) {
		dhcpmsg(MSG_ERR, "dlpi_send_link: dl_unitdata_req allocation");
		return (-1);
	}

	ctrl.len = sizeof (dl_unitdata_req_t) + data_length;
	ctrl.buf = (caddr_t)dl_req;

	data.len = data_length;
	data.buf = data_buffer;

	dl_req->dl_primitive		= DL_UNITDATA_REQ;
	dl_req->dl_priority.dl_min	= 0;
	dl_req->dl_priority.dl_max	= 0;
	dl_req->dl_dest_addr_offset	= sizeof (dl_unitdata_req_t);
	dl_req->dl_dest_addr_length	= dest_addr_length;
	(void) memcpy(&dl_req[1], dest_addr, dest_addr_length);

	retval = putmsg(fd, &ctrl, &data, 0);
	free(dl_req);
	return (retval);
}

/*
 * set_packet_filter(): sets the current packet filter on a DLPI stream
 *
 *   input: int: the DLPI stream to set the packet filter on
 *	    filter_func_t *: the filter to use
 *	    void *: an argument to pass to the filter function
 *	    const char *: a text description of the filter's purpose
 *  output: void
 */

void
set_packet_filter(int fd, filter_func_t *filter, void *arg,
    const char *filter_name)
{
	struct strioctl		sioc;
	struct packetfilt	pf;
	ushort_t		*pfp = pf.Pf_Filter;

	pf.Pf_FilterLen = filter(pfp, arg) - pf.Pf_Filter;

	sioc.ic_cmd	= PFIOCSETF;
	sioc.ic_timout	= DLPI_TIMEOUT;
	sioc.ic_len	= sizeof (struct packetfilt);
	sioc.ic_dp	= (caddr_t)&pf;

	/*
	 * if this ioctl() fails, we're really hosed.  the best we can
	 * really do is play on.
	 */

	if (ioctl(fd, I_STR, &sioc) == -1)
		dhcpmsg(MSG_ERR, "set_packet_filter: PFIOCSETF");
	else
		dhcpmsg(MSG_DEBUG, "set_packet_filter: set filter %p "
		    "(%s filter)", (void *)filter, filter_name);

	/*
	 * clean out any potential cruft on the descriptor that
	 * appeared before we were able to set the filter
	 */

	(void) ioctl(fd, I_FLUSH, FLUSHR);
}

/*
 * dhcp_filter(): builds a packet filter that permits only DHCP/BOOTP messages
 *
 *   input: ushort_t *: a place to store the packet filter code
 *	    void *: not used
 *  output: ushort_t *: two bytes past the last byte in the packet filter
 */

/* ARGSUSED */
ushort_t *
dhcp_filter(ushort_t *pfp, void *arg)
{
	/*
	 * only pass up UDP packets -- 8th byte is the ttl/proto field
	 */

	*pfp++ = ENF_PUSHWORD + 4;
	*pfp++ = ENF_PUSHLIT | ENF_AND;
	*pfp++ = htons(0xff);
	*pfp++ = ENF_PUSHLIT | ENF_CAND;
	*pfp++ = htons(IPPROTO_UDP);

	/*
	 * make sure the IP packet doesn't have any options.  2nd
	 * nibble is the header length field.
	 * TODO: if we decide to handle options, this code goes away.
	 */

	*pfp++ = ENF_PUSHWORD + 0;
	*pfp++ = ENF_PUSHLIT | ENF_AND;
	*pfp++ = htons(0x0f00);			/* only care about 2nd nibble */
	*pfp++ = ENF_PUSHLIT | ENF_CAND;
	*pfp++ = htons(0x0500);			/* which should be 5 * 4 = 20 */

	/*
	 * if there's a fragment offset, or if the IP_MF bit is lit,
	 * pitch the packet.  this  pitches all fragments.
	 * TODO: if we decide to handle fragments, this code goes away.
	 */

	*pfp++ = ENF_PUSHWORD + 3;
	*pfp++ = ENF_PUSHLIT | ENF_AND;
	*pfp++ = htons(0x1fff | IP_MF);
	*pfp++ = ENF_PUSHZERO | ENF_CAND;

	/*
	 * make sure the packet is for the DHCP client port -- 22nd
	 * byte is the UDP port number.
	 */

	*pfp++ = ENF_PUSHWORD + 11;
	*pfp++ = ENF_PUSHLIT | ENF_CAND;
	*pfp++ = htons(IPPORT_BOOTPC);

	return (pfp);
}

/*
 * build_broadcast_dest(): builds a DLPI destination address for the broadcast
 *			   address for use in DL_UNITDATA_REQs
 *
 *   input: dl_info_ack_t *: information about the interface
 *	    uchar_t *: set to the length of the returned address
 *  output: uchar_t *: the broadcast address (dynamically allocated)
 */

uchar_t *
build_broadcast_dest(dl_info_ack_t *dlia, uchar_t *length)
{
	uchar_t		sap_len = abs(dlia->dl_sap_length);
	caddr_t		dl_sap;
	uchar_t		*dest_addr;

	*length	  = dlia->dl_brdcst_addr_length + sap_len;
	dest_addr = malloc(*length);
	if (dest_addr == NULL)
		return (NULL);

	if (dlia->dl_sap_length > 0) {				/* sap before */
		dl_sap = (caddr_t)dlia + dlia->dl_addr_offset;
		(void) memcpy(dest_addr, dl_sap, sap_len);
		(void) memcpy(dest_addr + sap_len, (caddr_t)dlia +
		    dlia->dl_brdcst_addr_offset, dlia->dl_brdcst_addr_length);
	} else {
		dl_sap = (caddr_t)dlia + dlia->dl_addr_offset +
		    (dlia->dl_addr_length - sap_len);
		(void) memcpy(dest_addr, (caddr_t)dlia +
		    dlia->dl_brdcst_addr_offset, dlia->dl_brdcst_addr_length);
		(void) memcpy(dest_addr + dlia->dl_brdcst_addr_length,
		    dl_sap, sap_len);
	}

	return (dest_addr);
}
