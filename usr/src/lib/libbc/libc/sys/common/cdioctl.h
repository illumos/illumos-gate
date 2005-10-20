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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * Defines for SCSI direct access devices modified for CDROM, based on sddef.h
 *
 */

/*
 * CDROM io controls type definitions
 */
struct cdrom_msf {
	unsigned char	cdmsf_min0;	/* starting minute */
	unsigned char	cdmsf_sec0;	/* starting second */
	unsigned char	cdmsf_frame0;	/* starting frame  */
	unsigned char	cdmsf_min1;	/* ending minute   */
	unsigned char	cdmsf_sec1;	/* ending second   */
	unsigned char	cdmsf_frame1;	/* ending frame	   */
};

struct cdrom_ti {
	unsigned char	cdti_trk0;	/* starting track */
	unsigned char	cdti_ind0;	/* starting index */
	unsigned char	cdti_trk1;	/* ending track */
	unsigned char	cdti_ind1;	/* ending index */
};

struct cdrom_tochdr {
	unsigned char	cdth_trk0;	/* starting track */
	unsigned char	cdth_trk1;	/* ending track */
};

struct cdrom_tocentry {
	unsigned char	cdte_track;
	unsigned char	cdte_adr	:4;
	unsigned char	cdte_ctrl	:4;
	unsigned char	cdte_format;
	union {
		struct {
			unsigned char	minute;
			unsigned char	second;
			unsigned char	frame;
		} msf;
		int	lba;
	} cdte_addr;
	unsigned char	cdte_datamode;
};

struct cdrom_subchnl {
	unsigned char	cdsc_format;
	unsigned char	cdsc_audiostatus;
	unsigned char	cdsc_adr:	4;
	unsigned char	cdsc_ctrl:	4;
	unsigned char	cdsc_trk;
	unsigned char	cdsc_ind;
	union {
		struct {
			unsigned char	minute;
			unsigned char	second;
			unsigned char	frame;
		} msf;
		int	lba;
	} cdsc_absaddr;
	union {
		struct {
			unsigned char	minute;
			unsigned char	second;
			unsigned char	frame;
		} msf;
		int	lba;
	} cdsc_reladdr;
};

/*
 * definition of audio volume control structure
 */
struct cdrom_volctrl {
	unsigned char	channel0;
	unsigned char	channel1;
	unsigned char	channel2;
	unsigned char	channel3;
};

struct cdrom_read {
	int	cdread_lba;
	caddr_t	cdread_bufaddr;
	int	cdread_buflen;
};

/*
 * CDROM io control commands
 */
#define	CDROMPAUSE	_IO('c', 10)	/* Pause Audio Operation */

#define	CDROMRESUME	_IO('c', 11)	/* Resume paused Audio Operation */

#define	CDROMPLAYMSF	_IOW('c', 12, struct cdrom_msf)	/* Play Audio MSF */
#define	CDROMPLAYTRKIND	_IOW('c', 13, struct cdrom_ti)	/*
							 * Play Audio
`							 * Track/index
							 */
#define	CDROMREADTOCHDR	\
		_IOR('c', 103, struct cdrom_tochdr)	/* Read TOC header */
#define	CDROMREADTOCENTRY	\
	_IOWR('c', 104, struct cdrom_tocentry)		/* Read a TOC entry */

#define	CDROMSTOP	_IO('c', 105)	/* Stop the cdrom drive */

#define	CDROMSTART	_IO('c', 106)	/* Start the cdrom drive */

#define	CDROMEJECT	_IO('c', 107)	/* Ejects the cdrom caddy */

#define	CDROMVOLCTRL	\
	_IOW('c', 14, struct cdrom_volctrl)	/* control output volume */

#define	CDROMSUBCHNL	\
	_IOWR('c', 108, struct cdrom_subchnl)	/* read the subchannel data */

#define	CDROMREADMODE2	\
	_IOW('c', 110, struct cdrom_read)	/* read CDROM mode 2 data */

#define	CDROMREADMODE1	\
	_IOW('c', 111, struct cdrom_read)	/* read CDROM mode 1 data */
