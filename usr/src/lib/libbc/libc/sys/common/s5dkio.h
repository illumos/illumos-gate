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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS5_DKIO_H
#define	_SYS5_DKIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Structures and definitions for disk io control commands
 */

/*
 * Structures used as data by ioctl calls.
 */

/*
 * Used for controller info
 */
struct s5_dk_cinfo {
	char	dki_cname[DK_DEVLEN];	/* controller name (no unit #) */
	short	dki_ctype;		/* controller type */
	short	dki_flags;		/* flags */
	short	dki_cnum;		/* controller number */
	int	dki_addr;		/* controller address */
	int	dki_space;		/* controller bus type */
	int	dki_prio;		/* interrupt priority */
	int	dki_vec;		/* interrupt vector */
	char	dki_dname[DK_DEVLEN];	/* drive name (no unit #) */
	int	dki_unit;		/* unit number */
	int	dki_slave;		/* slave number */
	short	dki_partition;		/* partition number */
	short	dki_maxtransfer;	/* max. transfer size in DEV_BSIZE */
};


/*
 * Disk io control commands
 * Warning: some other ioctls with the DIOC prefix exist elsewhere.
 */
#define	S5DKIOC		(0x04 << 8)
#define	S5DKIOCGGEOM	(S5DKIOC|1)		/* Get geometry */
#define	S5DKIOCSGEOM	(S5DKIOC|2)		/* Set geometry */
#define	S5DKIOCINFO	(S5DKIOC|3)		/* Get info */
#define	S5DKIOCSAPART	(S5DKIOC|4)		/* Set all partitions */
#define	S5DKIOCGAPART	(S5DKIOC|5)		/* Get all partitions */

/*
 * These from hdio.h
 */
#define S5HDKIOC	(0x04 << 8)
#define	S5HDKIOCSTYPE	(S5HDKIOC|101)		/* Set drive info */
#define	S5HDKIOCGTYPE	(S5HDKIOC|102)		/* Get drive info */
#define	S5HDKIOCSBAD	(S5HDKIOC|103)		/* Set bad sector map */
#define	S5HDKIOCGBAD	(S5HDKIOC|104)		/* Get bad sector map */
#define	S5HDKIOCSCMD	(S5HDKIOC|105)		/* Set generic cmd */
#define	S5HDKIOCGDIAG	(S5HDKIOC|106)		/* Get diagnostics */

/*
 * These are from cdio.h
 * CDROM io control commands
 */
#define	S5CDIOC			(0x04 << 8)
#define	S5CDROMPAUSE		(S5CDIOC|151)	/* Pause Audio Operation */
#define	S5CDROMRESUME		(S5CDIOC|152)	/* Resume paused Audio Operation */
#define	S5CDROMPLAYMSF		(S5CDIOC|153)	/* Play Audio MSF */
#define	S5CDROMPLAYTRKIND	(S5CDIOC|154)	/* Play Audio Track/index */
#define	S5CDROMREADTOCHDR	(S5CDIOC|155)	/* Read TOC header */
#define	S5CDROMREADTOCENTRY	(S5CDIOC|156)	/* Read a TOC entry */
#define	S5CDROMSTOP		(S5CDIOC|157)	/* Stop the CDrom drive */
#define	S5CDROMSTART		(S5CDIOC|158)	/* Start the CDrom drive */
#define	S5CDROMEJECT		(S5CDIOC|159)	/* Ejects the CDrom caddy */
#define	S5CDROMVOLCTRL		(S5CDIOC|160)	/* control output volume */
#define	S5CDROMSUBCHNL		(S5CDIOC|161)	/* read the subchannel data */
#define	S5CDROMREADMODE2	(S5CDIOC|162)	/* read CDROM mode 2 data */
#define	S5CDROMREADMODE1	(S5CDIOC|163)	/* read CDROM mode 1 data */

/*
 * From sys/scsi/impl/uscsi.h
 */
/*
 * definition for user-scsi command structure
 */
struct s5_uscsi_cmd {
	int	uscsi_flags;		/* read, write, etc. see below */
	short	uscsi_status;		/* resulting status  */
	short	uscsi_timeout;		/* Command Timeout */
	caddr_t	uscsi_cdb;		/* cdb to send to target */
	caddr_t	uscsi_bufaddr;		/* i/o source/destination */
	u_int	uscsi_buflen;		/* size of i/o to take place */
	u_int	uscsi_resid;		/* resid from i/o operation */
	u_char	uscsi_cdblen;		/* # of valid cdb bytes */
	u_char	uscsi_reserved_1;	/* Reserved for Future Use */
	u_char	uscsi_reserved_2;	/* Reserved for Future Use */
	u_char	uscsi_reserved_3;	/* Reserved for Future Use */
	caddr_t	uscsi_reserved_4;	/* Reserved for Future Use */
	void   *uscsi_reserved_5;	/* Reserved for Future Use */
};

/*
 * User SCSI io control command
 */
#define	S5USCSIIOC	(0x04 << 8)
#define	S5USCSICMD	(S5USCSIIOC|201) 	/* user scsi command */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS5_DKIO_H */
