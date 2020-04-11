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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <strings.h>
#include <limits.h>
#include <syslog.h>
#include <sys/open.h>
#include <string.h>
#include <alloca.h>
#include <libintl.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <picl.h>
#include <picltree.h>
#include <fru_access.h>
#include <sys/sgfrutree.h>

/*
 * these functions will overlay the symbol table of libfruaccess
 * at runtime
 */
container_hdl_t	fru_open_container(picl_nodehdl_t fru);
int		fru_close_container(container_hdl_t fru);
int		fru_get_num_sections(container_hdl_t container,
		    door_cred_t *cred);
int		fru_get_sections(container_hdl_t container, section_t *section,
		    int max_sections, door_cred_t *cred);
int		fru_get_num_segments(section_hdl_t section, door_cred_t *cred);
int		fru_get_segments(section_hdl_t section, segment_t *segment,
		    int max_segments, door_cred_t *cred);
int		fru_add_segment(section_hdl_t section, segment_t *segment,
		    section_hdl_t *newsection, door_cred_t *cred);
int		fru_delete_segment(segment_hdl_t segment,
		    section_hdl_t *newsection, door_cred_t *cred);
ssize_t		fru_read_segment(segment_hdl_t segment, void *buffer,
		    size_t nbytes, door_cred_t *cred);
ssize_t		fru_write_segment(segment_hdl_t segment, const void *data,
		    size_t nbytes, segment_hdl_t *newsegment,
		    door_cred_t *cred);
int		fru_get_num_packets(segment_hdl_t segment, door_cred_t *cred);
int		fru_get_packets(segment_hdl_t segment, packet_t *packet,
		    int max_packets, door_cred_t *cred);
int		fru_update_payload(packet_hdl_t packet, const void *data,
		    size_t nbytes, packet_hdl_t *newpacket, door_cred_t *cred);
int		fru_append_packet(segment_hdl_t segment, packet_t *packet,
		    const void *payload, size_t nbytes,
		    segment_hdl_t *newsegment, door_cred_t *cred);
int		fru_delete_packet(packet_hdl_t packet,
		    segment_hdl_t *newsegment, door_cred_t *cred);
int		fru_is_data_available(picl_nodehdl_t fru);

#define	PICL_PROP_SC_HANDLE	"SC_handle"
#define	PICL_PROP_DATA_AVAIL	"FRUDataAvailable"
#define	MAX_LINE_SIZE		1024

#define	OPENDEVFRU gettext("fru_open_dev: open of %s failed %s")
#define	GETPV gettext("fru_open_container: ptree_get_propval_by_name failed %s")

static int
fru_open_dev(void)
{
	static int opendevfru = 0;
	static int frufd = 0;

	if ((opendevfru == 0) && (frufd == 0)) {
		if ((frufd = open(FRU_PSEUDO_DEV, O_RDWR, access)) == -1) {
			syslog(LOG_ERR, OPENDEVFRU, FRU_PSEUDO_DEV,
			    strerror(errno));
			return (-1);
		}
		opendevfru = 1;
	}
	return (frufd);
}

/*
 * Look up the container_hdl in the PICL tree.
 */
container_hdl_t
fru_open_container(picl_nodehdl_t fruh)
{
	int err;
	container_hdl_t container_hdl;

	if (fru_open_dev() == -1) {
		return (0);
	}

	err = ptree_get_propval_by_name(fruh, PICL_PROP_DATA_AVAIL, NULL, 0);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, GETPV, PICL_PROP_DATA_AVAIL, err);
		return (0);
	}
	err = ptree_get_propval_by_name(fruh, PICL_PROP_SC_HANDLE,
	    &container_hdl, sizeof (container_hdl_t));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, GETPV, PICL_PROP_SC_HANDLE, err);
		return (0);
	}
	return (container_hdl);
}

/*
 * Note : fru_open_container and fru_close_container do not map onto the opens
 * and closes of the sgfru device on lw8. There is one sgfru device which
 * handles all containers.
 */
/*ARGSUSED*/
int
fru_close_container(container_hdl_t fru)
{
	if (fru_open_dev() == -1) {
		return (-1);
	}
	return (0);
}

/*ARGSUSED*/
int
fru_get_num_sections(container_hdl_t container, door_cred_t *cred)
{
	section_info_t numsections;
	int fd;

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	numsections.hdl = container;
	numsections.cnt = 0;
	if (ioctl(fd, SGFRU_GETNUMSECTIONS, &numsections) != 0) {
		return (-1);
	}
	return (numsections.cnt);
}

/*ARGSUSED*/
int
fru_get_sections(container_hdl_t container, section_t *section,
    int max_sections, door_cred_t *cred)
{
	sections_t sections;
	int fd;

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	sections.fru_hdl = container;
	sections.fru_cnt = max_sections;
	sections.frus = section;
	if (ioctl(fd, SGFRU_GETSECTIONS, &sections) != 0) {
		return (-1);
	}
	return (sections.fru_cnt);
}

/*ARGSUSED*/
int
fru_get_num_segments(section_hdl_t section, door_cred_t *cred)
{
	segment_info_t numsegments;
	int fd;

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	numsegments.hdl = section;
	numsegments.cnt = 0;
	if (ioctl(fd, SGFRU_GETNUMSEGMENTS, &numsegments) != 0) {
		return (-1);
	}
	return (numsegments.cnt);
}

/*ARGSUSED*/
int
fru_get_segments(section_hdl_t section, segment_t *segment, int max_segments,
    door_cred_t *cred)
{
	segments_t segments;
	int fd;

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	segments.fru_hdl = section;
	segments.fru_cnt = max_segments;
	segments.frus = segment;
	if (ioctl(fd, SGFRU_GETSEGMENTS, &segments) != 0) {
		return (-1);
	}
	return (segments.fru_cnt);
}

/*ARGSUSED*/
int
fru_add_segment(section_hdl_t section, segment_t *segment,
    section_hdl_t *newsection, door_cred_t *cred)
{
	segments_t newsegment;
	int fd;

	/* check the effective uid of the client */
	if (cred->dc_euid != 0) {
		errno = EPERM;
		return (-1);	/* not a root */
	}

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	newsegment.fru_hdl = section;
	newsegment.fru_cnt = 1;
	newsegment.frus = segment;
	if (ioctl(fd, SGFRU_ADDSEGMENT, &newsegment) != 0) {
		return (-1);
	}
	/*
	 * The new segment handle is returned in segment,
	 * return the updated section handle in newsection.
	 */
	*newsection = newsegment.fru_hdl;
	return (0);
}

int
fru_delete_segment(segment_hdl_t segment, section_hdl_t *newsection,
    door_cred_t *cred)
{
	segment_info_t delsegment;
	int fd;

	/* check the effective uid of the client */
	if (cred->dc_euid != 0) {
		errno = EPERM;
		return (-1);	/* not a root */
	}

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	delsegment.hdl = segment;
	if (ioctl(fd, SGFRU_DELETESEGMENT, &delsegment) != 0) {
		return (-1);
	}
	/* Return the updated section handle in newsection. */
	*newsection = delsegment.hdl;
	return (0);
}

/*ARGSUSED*/
ssize_t
fru_read_segment(segment_hdl_t segment, void *buffer, size_t nbytes,
    door_cred_t *cred)
{
	segments_t readsegment;
	int fd;

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	readsegment.fru_hdl = segment;
	readsegment.fru_cnt = nbytes;
	readsegment.frus = buffer;
	if (ioctl(fd, SGFRU_READRAWSEGMENT, &readsegment) != 0) {
		return (-1);
	}
	return ((ssize_t)readsegment.fru_cnt);
}

/*ARGSUSED*/
ssize_t
fru_write_segment(segment_hdl_t segment, const void *buffer, size_t nbytes,
    segment_hdl_t *newsegment, door_cred_t *cred)
{
	segments_t writesegment;
	int fd;

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	writesegment.fru_hdl = segment;
	writesegment.fru_cnt = nbytes;
	writesegment.frus = (void *)buffer;
	if (ioctl(fd, SGFRU_WRITERAWSEGMENT, &writesegment) != 0) {
		return (-1);
	}
	/* Return the updated segment handle in newsegment. */
	*newsegment = writesegment.fru_hdl;
	return ((ssize_t)writesegment.fru_cnt);
}

/*ARGSUSED*/
int
fru_get_num_packets(segment_hdl_t segment, door_cred_t *cred)
{
	packet_info_t numpackets;
	int fd;

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	numpackets.hdl = segment;
	numpackets.cnt = 0;
	if (ioctl(fd, SGFRU_GETNUMPACKETS, &numpackets) != 0) {
		return (-1);
	}
	return (numpackets.cnt);
}

/*ARGSUSED*/
int
fru_get_packets(segment_hdl_t segment, packet_t *packet, int max_packets,
    door_cred_t *cred)
{
	packets_t packets;
	int fd;

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	packets.fru_hdl = segment;
	packets.fru_cnt = max_packets;
	packets.frus = packet;
	if (ioctl(fd, SGFRU_GETPACKETS, &packets) != 0) {
		return (-1);
	}
	return (packets.fru_cnt);
}

/*ARGSUSED*/
ssize_t
fru_get_payload(packet_hdl_t packet, void *buffer, size_t nbytes,
    door_cred_t *cred)
{
	payload_t payload;
	int fd;

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	payload.fru_hdl = packet;
	payload.fru_cnt = nbytes;
	payload.frus = buffer;
	if (ioctl(fd, SGFRU_GETPAYLOAD, &payload) != 0) {
		return (-1);
	}
	return ((ssize_t)payload.fru_cnt);
}

int
fru_update_payload(packet_hdl_t packet, const void *data, size_t nbytes,
    packet_hdl_t *newpacket, door_cred_t *cred)
{
	payload_t payload;
	int fd;

	/* check the effective uid of the client */
	if (cred->dc_euid != 0) {
		errno = EPERM;
		return (-1);	/* not a root */
	}

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	payload.fru_hdl = packet;
	payload.fru_cnt = nbytes;
	payload.frus = (void *)data;
	if (ioctl(fd, SGFRU_UPDATEPAYLOAD, &payload) != 0) {
		return (-1);
	}
	/* Return the updated packet handle in newpacket. */
	*newpacket = payload.fru_hdl;
	return (0);
}

int
fru_append_packet(segment_hdl_t segment, packet_t *packet, const void *payload,
    size_t nbytes, segment_hdl_t *newsegment, door_cred_t *cred)
{
	append_info_t appendpkt;
	int fd;

	/* check the effective uid of the client */
	if (cred->dc_euid != 0) {
		errno = EPERM;
		return (-1);	/* not a root */
	}

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	appendpkt.packet = *packet;
	appendpkt.payload_hdl = segment;
	appendpkt.payload_cnt = nbytes;
	appendpkt.payload_data = (void *)payload;
	if (ioctl(fd, SGFRU_APPENDPACKET, &appendpkt) != 0) {
		return (-1);
	}
	/*
	 * The new packet handle is returned in packet,
	 * return the updated segment handle in newsegment.
	 */
	packet->handle = appendpkt.packet.handle;
	*newsegment = appendpkt.payload_hdl;
	return (0);
}

int
fru_delete_packet(packet_hdl_t packet, segment_hdl_t *newsegment,
    door_cred_t *cred)
{
	packet_info_t delpacket;
	int fd;

	/* check the effective uid of the client */
	if (cred->dc_euid != 0) {
		errno = EPERM;
		return (-1);	/* not a root */
	}

	if ((fd = fru_open_dev()) == -1) {
		return (-1);
	}
	delpacket.hdl = packet;
	if (ioctl(fd, SGFRU_DELETEPACKET, &delpacket) != 0) {
		return (-1);
	}
	/* Return the updated segment handle in newsegment. */
	*newsegment = delpacket.hdl;
	return (0);
}

/*
 * Description :
 *		fru_is_data_available() checks to see if the frudata
 *		is available on a fru.
 *
 * Arguments   :
 *		picl_nodehdl_t holds the picl node handle of the fru.
 *
 * Return      :
 *		int
 *		return 1: if FRUID information is available
 *		return 0: if FRUID information is not present
 *
 */

/* ARGSUSED */
int
fru_is_data_available(picl_nodehdl_t fru)
{
	return (0);
}
