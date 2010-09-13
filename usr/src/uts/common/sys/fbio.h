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
 * Copyright (c) 1986,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_FBIO_H
#define	_SYS_FBIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS4.1.2 5.49 */

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef ASM
/*
 * Frame buffer descriptor.
 * Returned by FBIOGTYPE ioctl on frame buffer devices.
 */
struct	fbtype {
	int	fb_type;	/* as defined below */
	int	fb_height;	/* in pixels */
	int	fb_width;	/* in pixels */
	int	fb_depth;	/* bits per pixel */
	int	fb_cmsize;	/* size of color map (entries) */
	int	fb_size;	/* total size in bytes */
};

#define	FIOC		('F'<<8)
#define	FBIOGTYPE	(FIOC|0)

#ifdef	_KERNEL
struct	fbpixrect {
	struct	pixrect *fbpr_pixrect;	/* Pixrect of dev returned here */
};

#define	FBIOGPIXRECT	(FIOC|1)
#endif /* _KERNEL */

/*
 * General purpose structure for passing info in and out of frame buffers
 * (used for gp1)
 */
struct	fbinfo {
	int		fb_physaddr;	/* physical frame buffer address */
	int		fb_hwwidth;	/* fb board width */
	int		fb_hwheight;	/* fb board height */
	int		fb_addrdelta;	/* phys addr diff between boards */
	unsigned char	*fb_ropaddr;	/* fb va thru kernelmap */
	int		fb_unit;	/* minor devnum of fb */
};

#define	FBIOGINFO	(FIOC|2)

/*
 * Color map I/O.  See also fbcmap_i below.
 */
struct	fbcmap {
	int		index;		/* first element (0 origin) */
	int		count;		/* number of elements */
	unsigned char	*red;		/* red color map elements */
	unsigned char	*green;		/* green color map elements */
	unsigned char	*blue;		/* blue color map elements */
};

#ifdef _SYSCALL32

struct	fbcmap32 {
	int32_t		index;		/* first element (0 origin) */
	int32_t		count;		/* number of elements */
	caddr32_t 	red;		/* red color map elements */
	caddr32_t 	green;		/* green color map elements */
	caddr32_t 	blue;		/* blue color map elements */
};

#endif	/* _SYSCALL32 */

#define	FBIOPUTCMAP	(FIOC|3)
#define	FBIOGETCMAP	(FIOC|4)

/*
 * Set/Get attributes
 */
#define	FB_ATTR_NDEVSPECIFIC	8	/* no. of device specific values */
#define	FB_ATTR_NEMUTYPES	4	/* no. of emulation types */

struct fbsattr {
	int	flags;			/* misc flags */
#define	FB_ATTR_AUTOINIT	1	/* emulation auto init flag */
#define	FB_ATTR_DEVSPECIFIC	2	/* dev. specific stuff valid flag */
	int	emu_type;		/* emulation type (-1 if unused) */
	int	dev_specific[FB_ATTR_NDEVSPECIFIC];	/* catchall */
};

struct fbgattr {
	int	real_type;		/* real device type */
	int	owner;			/* PID of owner, 0 if myself */
	struct fbtype fbtype;		/* fbtype info for real device */
	struct fbsattr sattr;		/* see above */
	int	emu_types[FB_ATTR_NEMUTYPES];	/* possible emulations */
						/* (-1 if unused) */
};

#define	FBIOSATTR	(FIOC|5)
#define	FBIOGATTR	(FIOC|6)


/*
 * Video control
 * (the unused bits are reserved for future use)
 */
#define	FBVIDEO_OFF	0
#define	FBVIDEO_ON	1

#define	FBIOSVIDEO	(FIOC|7)
#define	FBIOGVIDEO	(FIOC|8)

/* Vertical retrace support. */
#define	FBIOVERTICAL	(FIOC|9)
#define	GRABPAGEALLOC	(FIOC|10)
#define	GRABPAGEFREE	(FIOC|11)
#define	GRABATTACH	(FIOC|12)

#define	FBIOGPLNGRP	(FIOC|13)
#define	FBIOGCMSIZE	(FIOC|14)
#define	FBIOSCMSIZE	(FIOC|15)
#define	FBIOSCMS	(FIOC|16)
#define	FBIOAVAILPLNGRP (FIOC|17)


/*
 * Structure to pass double buffering state back and forth the device.
 */

/* used in devstate */
#define	FBDBL_AVAIL	0x80000000
#define	FBDBL_DONT_BLOCK 0x40000000
#define	FBDBL_AVAIL_PG	0x20000000

/* used in read/write/display */
#define	FBDBL_A	 0x1
#define	FBDBL_B	 0x2
#define	FBDBL_BOTH	(FBDBL_A | FBDBL_B)
#define	FBDBL_NONE	0x4

struct fbdblinfo {
	unsigned int	dbl_devstate;
	unsigned int	dbl_read;
	unsigned int	dbl_write;
	unsigned int	dbl_display;
	int		dbl_depth;
	char		dbl_wid;
};

#define	FBIODBLGINFO	(FIOC|18)
#define	FBIODBLSINFO	(FIOC|19)

/* 8-bit emulation in 24-bit ioctls */

#define	FBIOSWINFD	(FIOC|20)
#define	FBIOSAVWINFD	(FIOC|21)
#define	FBIORESWINFD	(FIOC|22)
#define	FBIOSRWINFD	(FIOC|23)

/*
 * hardware cursor control
 */

struct fbcurpos {
	short x, y;
};

struct fbcursor {
	short set;		/* what to set */
#define	FB_CUR_SETCUR	0x01
#define	FB_CUR_SETPOS	0x02
#define	FB_CUR_SETHOT	0x04
#define	FB_CUR_SETCMAP	0x08
#define	FB_CUR_SETSHAPE 0x10
#define	FB_CUR_SETALL	0x1F
	short enable;		/* cursor on/off */
	struct fbcurpos pos;	/* cursor position */
	struct fbcurpos hot;	/* cursor hot spot */
	struct fbcmap cmap;	/* color map info */
	struct fbcurpos size;	/* cursor bit map size */
	char *image;		/* cursor image bits */
	char *mask;		/* cursor mask bits */
};

#ifdef _SYSCALL32
struct fbcursor32 {
	short set;		/* what to set */
	short enable;		/* cursor on/off */
	struct fbcurpos pos;	/* cursor position */
	struct fbcurpos hot;	/* cursor hot spot */
	struct fbcmap32 cmap;	/* color map info */
	struct fbcurpos size;	/* cursor bit map size */
	caddr32_t image;	/* cursor image bits */
	caddr32_t mask;		/* cursor mask bits */
};
#endif	/* _SYSCALL32 */

/* set/get cursor attributes/shape */
#define	FBIOSCURSOR	(FIOC|24)
#define	FBIOGCURSOR	(FIOC|25)

/* set/get cursor position */
#define	FBIOSCURPOS	(FIOC|26)
#define	FBIOGCURPOS	(FIOC|27)

/* get max cursor size */
#define	FBIOGCURMAX	(FIOC|28)

/* Window Grabber info ioctl */
#define	GRABLOCKINFO	(FIOC|29)

/*
 * Window Identification (wid) defines, structures, and ioctls.
 *
 * Some wids need to be unique when used for things such as double
 * buffering or rendering clipping.  Some wids can be shared when
 * used for display attributes only.  What can be shared and how
 * may be device dependent.  The fb_wid_alloc.wa_type and fb_wid_item
 * structure members will be left to device specific interpretation.
 */

#define	FB_WID_SHARED_8		0
#define	FB_WID_SHARED_24	1
#define	FB_WID_DBL_8		2
#define	FB_WID_DBL_24		3

struct fb_wid_alloc {
	unsigned int	wa_type;	/* special attributes		*/
	int		wa_index;	/* base wid returned		*/
	unsigned int	wa_count;	/* how many contiguous wids	*/
};

struct fb_wid_item {
	unsigned int	wi_type;	/* special attributes		*/
	int		wi_index;	/* which lut			*/
	unsigned int	wi_attrs;	/* which attributes		*/
	unsigned int	wi_values[NBBY*sizeof (int)]; /* the attr values */
};

struct fb_wid_list {
	unsigned int	wl_flags;
	unsigned int	wl_count;
	struct fb_wid_item	*wl_list;
};

#ifdef _SYSCALL32

struct fb_wid_list32 {
	uint32_t	wl_flags;
	uint32_t	wl_count;
	caddr32_t	wl_list;
};

#endif /* _SYSCALL32 */

struct fb_wid_dbl_info {
	struct fb_wid_alloc dbl_wid;
	char		dbl_fore;
	char		dbl_back;
	char		dbl_read_state;
	char		dbl_write_state;
};

#define	FBIO_WID_ALLOC	(FIOC|30)
#define	FBIO_WID_FREE	(FIOC|31)
#define	FBIO_WID_PUT	(FIOC|32)
#define	FBIO_WID_GET	(FIOC|33)

#define	FBIO_DEVID	(FIOC|34)
#define	FBIO_U_RST	(FIOC|35)
#define	FBIO_FULLSCREEN_ELIMINATION_GROUPS	(FIOC|36)
#define	FBIO_WID_DBL_SET	(FIOC|37)
#define	FBIOVRTOFFSET	(FIOC|38)

struct cg6_info {
	ushort_t  accessible_width;	/* accessible bytes in scanline */
	ushort_t  accessible_height;	/* number of accessible scanlines */
	ushort_t  line_bytes;		/* number of bytes/scanline */
	ushort_t  hdb_capable;		/* can this thing hardware db? */
	ushort_t  vmsize;		/* this is Mb of video memory */
	uchar_t	  boardrev;		/* board revision # */
	uchar_t	  slot;			/* sbus slot # */
	uint_t	  pad1;			/* expansion */
};

struct s3_info {
	ushort_t  accessible_width;	/* accessible bytes in scanline */
	ushort_t  accessible_height;	/* number of accessible scanlines */
	ushort_t  line_bytes;		/* number of bytes/scanline */
	ushort_t  hdb_capable;		/* can this thing hardware db? */
	ushort_t  vmsize;		/* this is Mb of video memory */
	uchar_t	  boardrev;		/* board revision # */
	uchar_t	  slot;			/* sbus slot # */
	uint_t	  pad1;			/* expansion */
};

struct p9000_info {
	ushort_t  accessible_width;	/* accessible bytes in scanline */
	ushort_t  accessible_height;	/* number of accessible scanlines */
	ushort_t  line_bytes;		/* number of bytes/scanline */
	ushort_t  hdb_capable;		/* can this thing hardware db? */
	ushort_t  vmsize;		/* this is Mb of video memory */
	uchar_t	  boardrev;		/* board revision # */
	uchar_t	  slot;			/* sbus slot # */
	uint_t	  pad1;			/* expansion */
};

struct p9100_info {
	ushort_t  accessible_width;	/* accessible bytes in scanline */
	ushort_t  accessible_height;	/* number of accessible scanlines */
	ushort_t  line_bytes;		/* number of bytes/scanline */
	ushort_t  hdb_capable;		/* can this thing hardware db? */
	ushort_t  vmsize;		/* this is Mb of video memory */
	uchar_t	  boardrev;		/* board revision # */
	uchar_t	  slot;			/* sbus slot # */
	uint_t	  pad1;			/* expansion */
};

struct wd90c24a2_info {
	ushort_t  accessible_width;	/* accessible bytes in scanline */
	ushort_t  accessible_height;	/* number of accessible scanlines */
	ushort_t  line_bytes;		/* number of bytes/scanline */
	ushort_t  hdb_capable;		/* can this thing hardware db? */
	ushort_t  vmsize;		/* this is Mb of video memory */
	uchar_t	  boardrev;		/* board revision # */
	uchar_t	  slot;			/* sbus slot # */
	uint_t	  pad1;			/* expansion */
};

#define	MON_TYPE_STEREO		0x8	/* stereo display */
#define	MON_TYPE_0_OFFSET	0x4	/* black level 0 ire instead of 7.5 */
#define	MON_TYPE_OVERSCAN	0x2	/* overscan */
#define	MON_TYPE_GRAY		0x1	/* greyscale monitor */

struct mon_info {
	uint_t	  mon_type;		/* bit array: defined above */
	uint_t	  pixfreq;		/* pixel frequency in Hz */
	uint_t	  hfreq;		/* horizontal freq in Hz */
	uint_t	  vfreq;		/* vertical freq in Hz */
	uint_t	  vsync;		/* vertical sync in scanlines */
	uint_t	  hsync;		/* horizontal sync in pixels */
					/* these are in pixel units */
	ushort_t  hfporch;		/* horizontal front porch */
	ushort_t  hbporch;		/* horizontal back porch */
	ushort_t  vfporch;		/* vertical front porch */
	ushort_t  vbporch;		/* vertical back porch */
};


#define	FBIOGXINFO	(FIOC|39)
#define	FBIOMONINFO	(FIOC|40)

/*
 * Color map I/O.
 */
struct	fbcmap_i {
	unsigned int	flags;		/* see below */
	int		id;		/* colormap id for multiple cmaps */
	int		index;		/* first element (0 origin) */
	int		count;		/* number of elements */
	unsigned char	*red;		/* red color map elements */
	unsigned char	*green;		/* green color map elements */
	unsigned char	*blue;		/* blue color map elements */
};

#ifdef _SYSCALL32

struct	fbcmap_i32 {
	uint32_t	flags;		/* see below */
	int32_t		id;		/* colormap id for multiple cmaps */
	int32_t		index;		/* first element (0 origin) */
	int32_t		count;		/* number of elements */
	caddr32_t	red;		/* red color map elements */
	caddr32_t	green;		/* green color map elements */
	caddr32_t	blue;		/* blue color map elements */
};

#endif	/* _SYSCALL32 */

#define	FB_CMAP_BLOCK	0x1	/* wait for vrt before returning */
#define	FB_CMAP_KERNEL	0x2	/* called within kernel */

#define	FBIOPUTCMAPI	(FIOC|41)
#define	FBIOGETCMAPI	(FIOC|42)

/* assigning a given window id to a pixrect - special for PHIGS */
#define	FBIO_ASSIGNWID	(FIOC|43)

/* assigning a given window to be stereo */
#define	FBIO_STEREO	(FIOC|44)
#define	FB_WIN_STEREO	    0x2

#endif	/* !ASM */

/* frame buffer type codes */
#define	FBTYPE_NOTYPE		(-1)	/* for backwards compatibility */
#define	FBTYPE_SUN1BW		0	/* Multibus mono */
#define	FBTYPE_SUN1COLOR	1	/* Multibus color */
#define	FBTYPE_SUN2BW		2	/* memory mono */
#define	FBTYPE_SUN2COLOR	3	/* color w/rasterop chips */
#define	FBTYPE_SUN2GP		4	/* GP1/GP2 */
#define	FBTYPE_SUN5COLOR	5	/* RoadRunner accelerator */
#define	FBTYPE_SUN3COLOR	6	/* memory color */
#define	FBTYPE_MEMCOLOR		7	/* memory 24-bit */
#define	FBTYPE_SUN4COLOR	8	/* memory color w/overlay */

#define	FBTYPE_NOTSUN1		9	/* reserved for customer */
#define	FBTYPE_NOTSUN2		10	/* reserved for customer */
#define	FBTYPE_NOTSUN3		11	/* reserved for customer */

#define	FBTYPE_SUNFAST_COLOR	12	/* accelerated 8bit */
#define	FBTYPE_SUNROP_COLOR	13	/* MEMCOLOR with rop h/w */
#define	FBTYPE_SUNFB_VIDEO	14	/* Simple video mixing */
#define	FBTYPE_SUNGIFB		15	/* medical image */
#define	FBTYPE_SUNGPLAS		16	/* plasma panel */
#define	FBTYPE_SUNGP3		17	/* cg12 running gpsi microcode */
#define	FBTYPE_SUNGT		18	/* gt graphics accelerator */
#define	FBTYPE_SUNLEO		19	/* zx graphics accelerator */
#define	FBTYPE_MDICOLOR		20	/* cgfourteen framebuffer */

#define	FBTYPE_LASTPLUSONE	21	/* max number of fbs (change as add) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FBIO_H */
