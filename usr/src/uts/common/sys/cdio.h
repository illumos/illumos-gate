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

#ifndef _SYS_CDIO_H
#define	_SYS_CDIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

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
	unsigned	cdte_adr	:4;
	unsigned	cdte_ctrl	:4;
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

/*
 * CDROM address format definition, for use with struct cdrom_tocentry
 */
#define	CDROM_LBA	0x01
#define	CDROM_MSF	0x02

/*
 * Bitmask for CD-ROM data track in the cdte_ctrl field
 * A track is either data or audio.
 */
#define	CDROM_DATA_TRACK	0x04

/*
 * For CDROMREADTOCENTRY, set the cdte_track to CDROM_LEADOUT to get
 * the information for the leadout track.
 */
#define	CDROM_LEADOUT	0xAA

struct cdrom_subchnl {
	unsigned char	cdsc_format;
	unsigned char	cdsc_audiostatus;
	unsigned	cdsc_adr:	4;
	unsigned	cdsc_ctrl:	4;
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
 * Definition for audio status returned from Read Sub-channel
 */
#define	CDROM_AUDIO_INVALID	0x00	/* audio status not supported */
#define	CDROM_AUDIO_PLAY	0x11	/* audio play operation in progress */
#define	CDROM_AUDIO_PAUSED	0x12	/* audio play operation paused */
#define	CDROM_AUDIO_COMPLETED	0x13	/* audio play successfully completed */
#define	CDROM_AUDIO_ERROR	0x14	/* audio play stopped due to error */
#define	CDROM_AUDIO_NO_STATUS	0x15	/* no current audio status to return */

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
	int		cdread_lba;
	caddr_t		cdread_bufaddr;
	int		cdread_buflen;
};

#if defined(_SYSCALL32)

struct cdrom_read32 {
	int		cdread_lba;
	caddr32_t	cdread_bufaddr;
	int		cdread_buflen;
};

#define	cdrom_read32tocdrom_read(cdrd32, cdrd)				\
	cdrd->cdread_lba	= cdrd32->cdread_lba;			\
	cdrd->cdread_bufaddr	= (caddr_t)(uintptr_t)cdrd32->cdread_bufaddr; \
	cdrd->cdread_buflen	= cdrd32->cdread_buflen

#define	cdrom_readtocdrom_read32(cdrd, cdrd32)				\
	cdrd32->cdread_lba	= cdrd->cdread_lba;			\
	cdrd32->cdread_bufaddr	= (caddr32_t)(uintptr_t)cdrd->cdread_bufaddr; \
	cdrd32->cdread_buflen	= cdrd->cdread_buflen

#endif	/* _SYSCALL32 */

/*
 * Definition of CD/DA structure
 */
struct cdrom_cdda {
	unsigned int	cdda_addr;
	unsigned int	cdda_length;
	caddr_t		cdda_data;
	unsigned char	cdda_subcode;
};

#if defined(_SYSCALL32)
struct cdrom_cdda32 {
	unsigned int	cdda_addr;
	unsigned int	cdda_length;
	caddr32_t	cdda_data;
	unsigned char	cdda_subcode;
};

#define	cdrom_cdda32tocdrom_cdda(cdda32, cdda)			\
	cdda->cdda_addr		= cdda32->cdda_addr;		\
	cdda->cdda_length	= cdda32->cdda_length;		\
	cdda->cdda_data		= (caddr_t)(uintptr_t)cdda32->cdda_data; \
	cdda->cdda_subcode	= cdda32->cdda_subcode

#define	cdrom_cddatocdrom_cdda32(cdda, cdda32)			\
	cdda32->cdda_addr	= cdda->cdda_addr;		\
	cdda32->cdda_length	= cdda->cdda_length;		\
	cdda32->cdda_data	= (caddr32_t)(uintptr_t)cdda->cdda_data; \
	cdda32->cdda_subcode	= cdda->cdda_subcode

#endif	/* _SYSCALL32 */

/*
 * Definitions for cdda_subcode field
 */
#define	CDROM_DA_NO_SUBCODE	0x00	/* CD/DA data with no subcode */
#define	CDROM_DA_SUBQ		0x01	/* CD/DA data with sub Q code */
#define	CDROM_DA_ALL_SUBCODE	0x02	/* CD/DA data with all subcode */
#define	CDROM_DA_SUBCODE_ONLY	0x03	/* All subcode only */

/*
 * Definition of CD/XA structure
 */
struct cdrom_cdxa {
	unsigned int	cdxa_addr;
	unsigned int	cdxa_length;
	caddr_t		cdxa_data;
	unsigned char	cdxa_format;
};

#if defined(_SYSCALL32)

struct cdrom_cdxa32 {
	unsigned int	cdxa_addr;
	unsigned int	cdxa_length;
	caddr32_t	cdxa_data;
	unsigned char	cdxa_format;
};

#define	cdrom_cdxa32tocdrom_cdxa(cdxa32, cdxa)				\
	cdxa->cdxa_addr		= cdxa32->cdxa_addr;			\
	cdxa->cdxa_length	= cdxa32->cdxa_length;			\
	cdxa->cdxa_data		= (caddr_t)(uintptr_t)cdxa32->cdxa_data; \
	cdxa->cdxa_format	= cdxa32->cdxa_format

#define	cdrom_cdxatocdrom_cdxa32(cdxa, cdxa32)				\
	cdxa32->cdxa_addr	= cdxa->cdxa_addr;			\
	cdxa32->cdxa_length	= cdxa->cdxa_length;			\
	cdxa32->cdxa_data	= (caddr32_t)(uintptr_t)cdxa->cdxa_data; \
	cdxa32->cdxa_format	= cdxa->cdxa_format

#endif	/* _SYSCALL32 */

/*
 * Definitions for cdxa_format field
 */
#define	CDROM_XA_DATA		0x00	/* CD/XA data only */
#define	CDROM_XA_SECTOR_DATA	0x01	/* CD/XA all sector data */
#define	CDROM_XA_DATA_W_ERROR	0x02	/* CD/XA data with error flags data */

/*
 * Definition of subcode structure
 */
struct cdrom_subcode {
	unsigned int	cdsc_length;
	caddr_t		cdsc_addr;
};

#if defined(_SYSCALL32)

struct cdrom_subcode32 {
	unsigned int	cdsc_length;
	caddr32_t	cdsc_addr;
};

#define	cdrom_subcode32tocdrom_subcode(cdsc32, cdsc)			\
	cdsc->cdsc_length	= cdsc32->cdsc_length;			\
	cdsc->cdsc_addr		= (caddr_t)(uintptr_t)cdsc32->cdsc_addr

#define	cdrom_subcodetocdrom_subcode32(cdsc, cdsc32)			\
	cdsc32->cdsc_length	= cdsc->cdsc_length;			\
	cdsc32->cdsc_addr	= (caddr32_t)(uintptr_t)cdsc->cdsc_addr

#endif	/* _SYSCALL32 */

/*
 * Definitions for block size supported
 */
#define	CDROM_BLK_512		512
#define	CDROM_BLK_1024		1024
#define	CDROM_BLK_2048		2048
#define	CDROM_BLK_2056		2056
#define	CDROM_BLK_2324		2324
#define	CDROM_BLK_2336		2336
#define	CDROM_BLK_2340		2340
#define	CDROM_BLK_2352		2352
#define	CDROM_BLK_2368		2368
#define	CDROM_BLK_2448		2448
#define	CDROM_BLK_2646		2646
#define	CDROM_BLK_2647		2647
#define	CDROM_BLK_SUBCODE	96

/*
 * Definitions for drive speed supported
 */
#define	CDROM_NORMAL_SPEED	0x00
#define	CDROM_DOUBLE_SPEED	0x01
#define	CDROM_QUAD_SPEED	0x03
#define	CDROM_TWELVE_SPEED	0x0C
#define	CDROM_MAXIMUM_SPEED	0xff

/*
 * CDROM io control commands
 */
#define	CDIOC			(0x04 << 8)
#define	CDROMPAUSE		(CDIOC|151)	/* Pause Audio Operation */
#define	CDROMRESUME		(CDIOC|152) /* Resume paused Audio Operation */
#define	CDROMPLAYMSF		(CDIOC|153)	/* Play Audio MSF */
#define	CDROMPLAYTRKIND		(CDIOC|154)	/* Play Audio Track/index */
#define	CDROMREADTOCHDR		(CDIOC|155)	/* Read TOC header */
#define	CDROMREADTOCENTRY	(CDIOC|156)	/* Read a TOC entry */
#define	CDROMSTOP		(CDIOC|157)	/* Stop the cdrom drive */
#define	CDROMSTART		(CDIOC|158)	/* Start the cdrom drive */
#define	CDROMEJECT		(CDIOC|159)	/* Ejects the cdrom caddy */
#define	CDROMVOLCTRL		(CDIOC|160)	/* control output volume */
#define	CDROMSUBCHNL		(CDIOC|161)	/* read the subchannel data */
#define	CDROMREADMODE2		(CDIOC|162)	/* read CDROM mode 2 data */
#define	CDROMREADMODE1		(CDIOC|163)	/* read CDROM mode 1 data */

#define	CDROMREADOFFSET		(CDIOC|164)	/* read multi-session offset */

#define	CDROMGBLKMODE		(CDIOC|165)	/* get current block mode */
#define	CDROMSBLKMODE		(CDIOC|166)	/* set current block mode */
#define	CDROMCDDA		(CDIOC|167)	/* read CD/DA data */
#define	CDROMCDXA		(CDIOC|168)	/* read CD/XA data */
#define	CDROMSUBCODE		(CDIOC|169)	/* read subcode */
#define	CDROMGDRVSPEED		(CDIOC|170)	/* get current drive speed */
#define	CDROMSDRVSPEED		(CDIOC|171)	/* set current drive speed */

#define	CDROMCLOSETRAY		(CDIOC|172)	/* close cd tray,load media */

/*
 * Additional commands for CD-ROM
 */
/*
 *
 *	Group 2 Commands
 *
 */
#define	SCMD_READ_SUBCHANNEL	0x42		/* optional SCSI command */
#define	SCMD_READ_TOC		0x43		/* optional SCSI command */
#define	SCMD_READ_HEADER	0x44		/* optional SCSI command */
#define	SCMD_PLAYAUDIO10	0x45		/* optional SCSI command */
#define	SCMD_PLAYAUDIO_MSF	0x47		/* optional SCSI command */
#define	SCMD_PLAYAUDIO_TI	0x48		/* optional SCSI command */
#define	SCMD_PLAYTRACK_REL10	0x49		/* optional SCSI command */
#define	SCMD_PAUSE_RESUME	0x4B		/* optional SCSI command */

/*
 *
 *	Group 5 Commands
 *
 */
#define	SCMD_PLAYAUDIO12	0xA5		/* optional SCSI command */
#define	SCMD_PLAYTRACK_REL12	0xA9		/* optional SCSI command */
#define	SCMD_SET_CDROM_SPEED	0xBB		/* optional SCSI command */
#define	SCMD_READ_CD		0xBE	/* Universal way of accessing CD data */

/*
 * These defines are for SCMD_READ_CD command.
 * See Expected Sector Type Field Definition (SCSI MMC-2 Spec section 6.1.15)
 * This information is used to figure out which block size to use.
 */
#define	READ_CD_EST_ALLTYPE	0x0	/* All Types */
#define	READ_CD_EST_CDDA	0x1	/* Only CD-DA */
#define	READ_CD_EST_MODE1	0x2	/* Only Yellow Book 2048 bytes */
#define	READ_CD_EST_MODE2	0x3	/* Only Yellow Book 2336 byte sectors */
#define	READ_CD_EST_MODE2FORM1	0x4	/* Only sectors with 2048 bytes */
#define	READ_CD_EST_MODE2FORM2	0x5	/* Only sectors with 2324 bytes */
#define	READ_CD_EST_RSVD1	0x6	/* reserved */
#define	READ_CD_EST_RSVD2	0x7	/* reserved */


/*
 *
 *	Group 6 Commands
 *
 */
#define	SCMD_CD_PLAYBACK_CONTROL 0xC9	/* SONY unique SCSI command */
#define	SCMD_CD_PLAYBACK_STATUS	0xC4	/* SONY unique SCSI command */
#define	SCMD_READ_CDDA		0xD8	/* Vendor unique SCSI command */
#define	SCMD_READ_CDXA		0xDB	/* Vendor unique SCSI command */
#define	SCMD_READ_ALL_SUBCODES	0xDF	/* Vendor unique SCSI command */

#define	CDROM_MODE2_SIZE	2336

/*
 * scsi_key_strings for CDROM cdio SCMD_ definitions
 */
#define	SCSI_CMDS_KEY_STRINGS_CDIO				\
/* 0x42 */ SCMD_READ_SUBCHANNEL,	"read_subchannel",		\
/* 0x43 */ SCMD_READ_TOC,		"read_toc",			\
/* 0x44 */ SCMD_REPORT_DENSITIES |					\
		SCMD_READ_HEADER,	"report_densities/read_header",	\
/* 0x45 */ SCMD_PLAYAUDIO10,		"playaudio",			\
/* 0x46 */ SCMD_GET_CONFIGURATION,	"get_configuration",		\
/* 0x47 */ SCMD_PLAYAUDIO_MSF,		"playaudio_msf",		\
/* 0x48 */ SCMD_PLAYAUDIO_TI,		"playaudio_ti",			\
/* 0x49 */ SCMD_PLAYTRACK_REL10,	"playaudio_rel",		\
/* 0x4b */ SCMD_PAUSE_RESUME,		"pause_resume",			\
									\
/* 0xa5 */ SCMD_PLAYAUDIO12,		"playaudio(12)",		\
/* 0xa9 */ SCMD_PLAYTRACK_REL12,	"playtrack_rel",		\
/* 0xbb */ SCMD_SET_CDROM_SPEED,	"set_cd_speed",			\
/* 0xbe */ SCMD_READ_CD,		"read_cd",			\
									\
/* 0xc4 */ SCMD_CD_PLAYBACK_STATUS,	"cd_playback_status",		\
/* 0xc9 */ SCMD_CD_PLAYBACK_CONTROL,	"cd_playback_control",		\
/* 0xd8 */ SCMD_READ_CDDA,		"read_cdda",			\
/* 0xdb */ SCMD_READ_CDXA,		"read_cdxa",			\
/* 0xdf */ SCMD_READ_ALL_SUBCODES,	"read_all_subcodes"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CDIO_H */
