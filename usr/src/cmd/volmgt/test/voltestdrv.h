/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1992-1996 by Sun Microsystems, Inc.
 * All rights reserved
 */

#ifndef __VOLTESTDRV_H
#define __VOLTESTDRV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/cdio.h>
#include <sys/ioccom.h>
#include <sys/vtoc.h>


struct vt_name {
	minor_t	vtn_unit;	/* vt unit to map */
	char	*vtn_name;	/* "label" of the device */
};
struct vt_tag {
	minor_t	vtt_unit;	/* vt unit to tag */
	u_int	vtt_tag;	/* magic cookie to return */
};

struct vt_event {
	minor_t	vte_dev;	/* inserted minor number */
};

struct vt_lab {
	minor_t	vtl_unit;	/* unit to assign label to */
	int	vtl_errno;	/* error to generate on block 0 reads. */
	size_t	vtl_readlen;	/* byte offset for generating error. */
	size_t	vtl_len;	/* number of bytes in label */
	char	*vtl_label;	/* pointer to label */
};

enum vt_evtype {
	VSE_WRTERR
};

struct vt_status {
	enum vt_evtype	vte_type;
	union {
		/* write error message */
		struct ve_wrterr {
			minor_t	vwe_unit;	/* unit bad data was on */
			int	vwe_want;	/* data that we wanted */
			int	vwe_got;	/* data that we got */
		} vse_u_wrterr;
	} vse_un;
};

/*
 * vt_vtoc contains information that the vt driver will use to respond to
 * DKIOCGVTOC ioctls.
 */

struct vt_vtoc {
	int		vtvt_errno;	/* error to return on DKIOCGVTOC */
	struct vtoc	vtvt_vtoc;	/* vol. table of contents. */
};

/*
 * Use vt_vtdes to load the vt_vtoc structure into the driver.
 */

struct vt_vtdes {
	minor_t		vtvd_unit;	/* test unit to load */
	struct vt_vtoc	vtvd_vtoc;	/* table of contents info. */
};

/*
 * vt_hdrinfo contains information that the vt driver will use to
 * respond to the CDROMREADTOCHDR ioctl.
 */

struct vt_hdrinfo {
    	int			vttoc_errno;	/* error for CDROMREADTOCHDR */
	struct cdrom_tochdr	vttoc_hdr;	/* TOC hdader information */
};

/*
 * Use vt_tochdr to load vt_hdrinfo into the driver using the
 * VTIOCSTOCHDR ioctl.
 */

struct vt_tochdr {
    	minor_t			vtt_unit;	/* unit to load. */
    	struct vt_hdrinfo	vtt_toc;	/* CDROMREADTOCHDR info. */
};

/*
 * Use vt_tedes to load cdrom toc entries and error generation information
 * into the vt driver using the VTIOCSTOCENTRIES ioctl.
 */

struct vt_tedes {
	minor_t			vttd_unit;	/* test unit to load. */
	int			vttd_errno;	/* error to return. */
	unsigned char		vttd_err_track;	/* track to gen. error for. */
	size_t			vttd_count;	/* number of toc entries. */
	struct cdrom_tocentry	*vttd_entries;	/* array of toc entries. */
};

#define vse_wrterr	vse_un.vse_u_wrterr

/*
 * this test driver uses the same "key" as the vol driver
 */
#define	VTIOC		('v' << 8)

#define VTIOCNAME		(VTIOC|1)
#define VTKIOCEVENT		(VTIOC|2)
#define VTIOCEVENT		(VTIOC|3)
#define VTIOCUNITS		(VTIOC|4)
#define VTIOCTAG		(VTIOC|5)
#define VTIOCLABEL		(VTIOC|6)
#define VTIOCSTATUS		(VTIOC|7)
#define	VTIOCSVTOC		(VTIOC|8)
#define VTIOCSTOCHDR		(VTIOC|9)
#define VTIOCSTOCENTRIES	(VTIOC|10)

/*
 * the following defines are for backwards compatability
 */
#define VTIOCNAME_OLD		_IOR('v', 1, struct vt_name)
#define VTKIOCEVENT_OLD		_IOW('v', 2, struct vt_event)
#define VTIOCEVENT_OLD		_IOW('v', 3, struct vt_event)
#define VTIOCUNITS_OLD		_IOW('v', 4, u_int)
#define VTIOCTAG_OLD		_IOR('v', 5, struct vt_tag)
#define VTIOCLABEL_OLD		_IOR('v', 6, struct vt_lab)
#define VTIOCSTATUS_OLD		_IOW('v', 7, struct vt_status)
#define VTIOCSVTOC_OLD		_IOR('v', 8, struct vt_vtdes)
#define VTIOCSTOCHDR_OLD	_IOR('v', 9, struct vt_tochdr)
#define VTIOCSTOCENTRIES_OLD	_IOR('v', 10, struct vt_tedes)


#define VTCTLNAME	"voltestdrvctl"

#ifdef	__cplusplus
}
#endif

#endif /* __VOLTESTDRV_H */
