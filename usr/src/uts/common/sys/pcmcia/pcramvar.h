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
 */

#ifndef	_PCRAMVAR_H
#define	_PCRAMVAR_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This is a private interface
 *	fdformat utility and SunVTS use these ioctls.
 */
#define	PCRAM_GETMEDIA	(PCRAMIOC|21)	/* Get media type */
#define	PCRAM_PROBESIZE	(PCRAMIOC|22)	/* Probe card size */

/*
 * PCRAM_GETMEDIA - Get PCMCIA memory media type ioctl()
 *
 *	The argument is a pointer to a pcmm_info structure
 *	described  below
 */
struct pcmm_info {
	ushort_t pcmm_type;	/* supported media type */
};

/*
 * PCMCIA memory media types
 */
#define	PCMM_TYPE_RAM		0x01	/* SRAM/DRam/Masked ROM */
#define	PCMM_TYPE_FLASH		0x02	/* FLASH */
#define	PCMM_TYPE_EEPROM	0x04	/* EPROM/EEPROM */
#define	PCMM_TYPE_OTP		0x08	/* One-time programmable ROM */


/*
 * PCRAM_PROBESIZE - Probe memory card size ioctl()
 *
 *	This ioctl() asks the memory driver for the
 *	card size information.
 *
 *	If a memory card has a Card Information Structure (CIS),
 *	the memory driver then uses a read-only operation to get
 *	the card size from CIS.
 *	When there is no CIS on a memory card, this ioctl() forces
 *	the memory driver to perform a write/verify/restore data
 *	operation to determine the card size.
 *
 *	The argument is a pointer to a dk_geom structure
 *	described in dkio(7I).
 */


/*
 * Debug
 */
#define	PCRAM_DEBUG_TRACE		0x000000001
#define	PCRAM_DEBUG_SIZE		0x000000100
#define	PCRAM_DEBUG_CARD_STATUS		0x000000200
#define	PCRAM_DEBUG_VOLD		0x000000400
#define	PCRAM_DEBUG_CIS			0x000000800

/*
 * Values for CS_EVENT_CLIENT_INFO event handler
 */
#define	PCRAM_CLIENT_DESCRIPTION	"PCMCIA SRAM memory card driver"
#define	PCRAM_VENDOR_DESCRIPTION	CS_SUN_VENDOR_DESCRIPTION
#define	PCRAM_REV_LEVEL			0x100
#define	PCRAM_REV_DAY			01
#define	PCRAM_REV_MONTH			4
#define	PCRAM_REV_YEAR			16
#define	PCRAM_REV_DATE			CS_CLIENT_INFO_MAKE_DATE( \
						PCRAM_REV_DAY, \
						PCRAM_REV_MONTH, \
						PCRAM_REV_YEAR)

/*
 * PC Card present macro
 */
#define	PCRAM_CARD_PRESENT(rs)	((rs)->card_event & \
					PCRAM_CARD_INSERTED)
/*
 * PCRAM card present timeout
 * Used in pcram_attach routine to timeout if Card presence is not detected
 * in this interval.
 */
#define	PCRAM_CARD_INSERTION_TIMEOUT	SEC_TO_TICK(60)

/*
 * driver ID string
 */
#define	PCRAM_DRIVERID		"PCMCIA Memory Card Driver"
#define	PCRAM_NAME		"pcram"
				/*
				 * SunVTS uses PCRAM_DKC_CNAME for
				 *	checking if it is a pcram controller
				 */
#define	PCRAM_DKC_CNAME		PCRAM_NAME
#define	PCRAM_DKC_DNAME		"pccard"

/*
 * Minor device number encoding:
 *
 *      s s s s | s s p p | p p p p | p p p p
 *
 *      s - socket number of this device
 *      p - partition number of this device
 *
 */
#define	PCRAM_SOCKET(dev)		((getminor(dev) >> 10) & 0x3f)
#define	PCRAM_PARTTION(dev)		(getminor(dev) & 0x3ff)
#define	PCRAM_SETMINOR(skt, part)	((skt<<10) | (part))


/*
 * Host buffer - 1KB size
 *
 *	This buffer is used for the problem of the SS2 CACHE+
 *	double word write to the 16-bit slave device.
 */
#define	HOST_BUF_SIZE		(1*1024)


/*
 * flags in pcram_state.flags field
 */
				/* added to interrupt chain */
#define	PCRAM_SOFTINTROK	0x00000001
				/* RegisterCLient is OK */
#define	PCRAM_REGCLIENT		0x00000002
				/* cv/mutex_init in attach */
#define	PCRAM_DIDLOCKS		0x00000004
				/* RequestSocketMask is OK */
#define	PCRAM_REQSOCKMASK	0x00000008
				/* pass pcram_attach() */
#define	PCRAM_ATTACHOK		0x00000010
				/* we have a valid window */
#define	PCRAM_HAS_WINDOW		0x00000020
				/* minor nodes created */
#define	PCRAM_MAKEDEVICENODE	0x00000040

/*
 * Flags used for pcram_state.card_event
 */
				/* card is here */
#define	PCRAM_CARD_INSERTED	0x00000001
				/* write protect */
#define	PCRAM_WRITE_PROTECT	0x00000002
				/* open first time */
#define	PCRAM_FIRST_OPEN	0x00000004

/*
 * Drive characteristic conversion macros
 *	cs   - total card size
 *	hd   - number of head
 *	ss   - sector size
 *	st   - sector per track
 *	cyl  - number of cylinder
 *	tsec - total number of sectors in logical volume
 */
#define	GET_NCYL(cs, hd, ss, st)	(cs/(hd*ss*st))
#define	GET_CSIZ(cyl, hd, ss, st)	(cyl*hd*ss*st)
#define	GET_CSIZ_DOS(tsec, ss)		(tsec*ss)
#define	GET_INFO(b0, b1)		(b0 | b1 << 8)


/*
 * pcram_card_sizing defines
 */
#define	SIZE_1KB		(1024)
				/*
				 * Write/Read/Restore every
				 * 512KB block
				 */
#define	HALF_MEG		(512 * 1024)
				/*  64MB max per PCMCIA spec. */
#define	MAX_CARD_SIZE		(64 * 1024 * 1024)
				/* Alternative write patterns */
#define	PATTERN_1		0x55
#define	PATTERN_2		0xaa
#define	UNRECOGNIZED_MEDIA	-1


/*
 * Default speed of CM region in nS
 *	Used by pcram_build_region_list()
 */
#define	DEFAULT_CM_SPEED	250


/*
 * PCMCIA SRAM memory card characteristic structure
 */
struct hd_char {
	int drv_ncyl;		/* number of cylinders */
	int drv_nhead;		/* number of heads */
	int drv_secptrack;	/* sectors per track */
	int drv_sec_size;	/* sector size */
};


/*
 * Configure number of cylinder so we
 * can get even total sectors on disk
 *
 *	ncyl -  number_of_cylinder
 *	nhd  -  number_of_head
 *	spt  -  sector_per_track
 *	bps  -  byte_per_sector
 *
 *      card_size = ncyl * nhd * spt * bps
 *
 *      card_size       ncyl   nhd     spt      byte/sect
 *      --------------------------------------------------
 *      524288          64      2       8          512
 *      1048576         128     2       8          512
 *      2097152         256     2       8          512
 *         -             -      -       -           -
 *      67108864        8192    2       8          512
 *
 */
static struct hd_char hdtypes = {
		/* setup for maximum 64MB card */
	8192,	/* number of cylinders (64 to 8192) */
	2,	/* number of heads (fixed) */
	8,	/* sectors per track (fixed) */
	512	/* sector size (fixed) */
};


/*
 * mem_region_t
 *
 *	this structure describes a region of memory technology
 */
typedef struct mem_region_t {
	uint32_t	region_num;	/* region number */
	uint32_t	rflags;		/* region flags */
	uint32_t	flags;		/* device tuple flags */
	uint32_t	speed;		/* device speed in device */
					/* speed code format */
	uint32_t	nS_speed;	/* device speed in nS */
	uint32_t	type;		/* device type */
	uint32_t	size;		/* device size */
	uint32_t	size_in_bytes;	/* device size in bytes */
	int		id;		/* manufacturer id */
	int		info;		/* manufacturer specific info */
	struct mem_region_t	*next;
	struct mem_region_t	*prev;
} mem_region_t;

/*
 * Flags for mem_region_t structure.
 */
				/* default region */
#define	REGION_DEFAULT		0x00000001
				/* read-only region */
#define	REGION_READONLY		0x00000002
				/* DOS BPB-FAT region */
#define	REGION_DOS_BPBFAT	0x00000004
				/* Solaris region */
#define	REGION_SOLARIS		0x00000008
				/* region is valid */
#define	REGION_VALID		0x00000010
				/* hole in the address space */
#define	REGION_HOLE		0x00000020


/*
 * Flags for pcram_build_region_list functions.
 */
				/* build list from AM tuples */
#define	BUILD_AM_LIST		0x00000001
				/* build list from CM tuples */
#define	BUILD_CM_LIST		0x00000002
				/* build list from BPB-FAT */
#define	BUILD_DOS_BPBFAT_LIST	0x00000004
				/* build list from Solaris  */
#define	BUILD_SOLARIS_LIST	0x00000008
				/* build default AM/CM list */
#define	BUILD_DEFAULT_LIST	0x00000010


/*
 * Flags for pcram_destroy_region_list functions.
 */
				/* destroy AM list */
#define	DESTROY_AM_LIST		0x00010000
				/* destroy CM list */
#define	DESTROY_CM_LIST		0x00020000


/*
 *
 * This state structure contains:
 *      a pointer to the dev_info node for this instance
 *      mutexes
 *      condition variables
 * This structure is initialized in pcram_attach()
 *
 */
typedef struct pcram_state_t {
				/* various board-level flags */
	unsigned		flags;
				/* soft interrupt cookie */
	ddi_iblock_cookie_t	soft_blk_cookie;
				/* softint identifier */
	ddi_softintr_t		softint_id;
				/* Device dev_info_t */
	dev_info_t		*dip;
				/* dip instance */
	int			instance;

				/* CardServices stuff */
				/* CS client handle */
	client_handle_t		client_handle;
				/* protects hilevel events */
	kmutex_t		event_hilock;
				/* window stuff */
	window_handle_t		window_handle;
				/*  window size */
	uint32_t		win_size;
				/* memory region lists */
				/* number of CM regions */
	int			num_cm_regions;
				/* regions in CM space */
	mem_region_t		*cm_regions;
				/* number of AM regions */
	int			num_am_regions;
				/* regions in AM space */
	mem_region_t		*am_regions;
				/* protects region lists */
	kmutex_t		region_lock;

				/* low-priority mutex */
	kmutex_t		mutex;
				/* xx_strategy: waiting for */
				/* 		I/O to complete */
	kcondvar_t		condvar;
				/* xx_write: waiting for */
				/*		I/O to complete  */
	kcondvar_t		condvar_wr;
				/* xx_write: waiting for */
				/*		I/O to complete  */
	kcondvar_t		condvar_rd;
				/* for DKIOCSTATE ioctl()  */
	kcondvar_t		condvar_mediastate;

				/* block/character device open */
	int			blk_open;
	int			chr_open;
				/* count of layered opens */
	int			nlayered;
				/*
				 * device active, cannot be unloaded
				 * (xx_strategy)
				 */
	int			busy;
				/*
				 * device active, cannot be unloaded
				 * (xx_write)
				 */
	int			busy_wr;
	int			busy_rd;

				/* mode recent card state */
	uint32_t		card_state;
				/* recent card event */
	uint32_t		card_event;

				/* up-to-date media state */
	enum dkio_state		media_state;
				/* transfer list */
	struct	buf		*blist;
				/* Packed label for this unit */
	struct	dk_label	un_label;

				/* posting battery condition */
	int			batter_dead_posted;
	int			batter_low_posted;
				/*  Card Eject Posted Flag  */
	int			card_eject_posted;
				/*  Write-Protect Posted Flag  */
	int			wp_posted;
				/*  ejected while mouting Flag  */
	int			ejected_while_mounting;
				/* PC Card CIS present */
	unsigned		isit_pseudofloppy;

				/* pointer to hard drive */
				/* characteristics */
	struct	hd_char		*hdrv_chars;
				/* Memory card size */
	int			card_size;
				/* base of kernel write buffer */
	volatile caddr_t	host_sp;
				/* access handle for base of window */
	acc_handle_t		access_handle;

	int			sn;	/* Logical socket number */
				/*
				 * enable cv_broadcast
				 *	in pcram_check_media
				 */
	int			checkmedia_flag;
				/*
				 * return state=DKIO_NONE if DKIOCSATE
				 *	ioctl is called twice
				 *	if rs->media_state is still
				 *	at state of DKIO_EJECTED.
				 *	Following SCSI CDROM broken
				 *	way model.
				 */
	int			ejected_media_flag;
				/*
				 * Default size flag is set when there is
				 *	no CIS or DOS_BPBFAT or Solaris VTOC
				 */
	int			default_size_flag;
				/* first open wait */
	kcondvar_t		firstopenwait_cv;
} pcram_state_t;


/*
 * DOS boot parameter block
 *
 *	There is no header file for the bootblock structure
 *	see related pcfs in:
 *		{ws}/usr/src/uts/common/fs/pcfs/pc_vfsops.c
 *
 */
struct	bootblock {
	uchar_t	sig[3];		/* Jump to boot code */
	uchar_t	oem[8];		/* OEM name & version */
	uchar_t	bps[2];		/* bytes per sector */
	uchar_t	alloc;		/* sectors per allocation unit */
	uchar_t	ressec[2];	/* reserved sectors */
	uchar_t	fats;		/* number of FATS */
	uchar_t	nrd[2];		/* number of root directory entries */
	uchar_t	tsec[2];	/* total number of sectors in */
				/* logical volume */
	uchar_t	media;		/* media descriptor byte */
	uchar_t	secfat[2];	/* sectors per FAT */
	uchar_t	sectrack[2];	/* sectors per track */
	uchar_t	heads[2];	/* number of heads */
	uchar_t	misc[484];
};


#ifdef	__cplusplus
}
#endif

#endif /* _PCRAMVAR_H */
