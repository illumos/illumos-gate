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
 * Copyright 1988-1989, Sun Microsystems, Inc.
 */

#ifndef _SYS_CG6FBC_H
#define	_SYS_CG6FBC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * CG6 register definitions, common to all environments.
 */

/*
 * FBC MISC register bits
 */
typedef enum {
	L_FBC_MISC_BLIT_IGNORE, L_FBC_MISC_BLIT_NOSRC, L_FBC_MISC_BLIT_SRC,
	L_FBC_MISC_BLIT_ILLEGAL
} l_fbc_misc_blit_t;

typedef enum {
	L_FBC_MISC_DATA_IGNORE, L_FBC_MISC_DATA_COLOR8, L_FBC_MISC_DATA_COLOR1,
	L_FBC_MISC_DATA_HRMONO
} l_fbc_misc_data_t;

typedef enum {
	L_FBC_MISC_DRAW_IGNORE, L_FBC_MISC_DRAW_RENDER, L_FBC_MISC_DRAW_PICK,
	L_FBC_MISC_DRAW_ILLEGAL
} l_fbc_misc_draw_t;

typedef enum {
	L_FBC_MISC_BWRITE0_IGNORE, L_FBC_MISC_BWRITE0_ENABLE,
	L_FBC_MISC_BWRITE0_DISABLE, L_FBC_MISC_BWRITE0_ILLEGAL
} l_fbc_misc_bwrite0_t;

typedef enum {
	L_FBC_MISC_BWRITE1_IGNORE, L_FBC_MISC_BWRITE1_ENABLE,
	L_FBC_MISC_BWRITE1_DISABLE, L_FBC_MISC_BWRITE1_ILLEGAL
} l_fbc_misc_bwrite1_t;

typedef enum {
	L_FBC_MISC_BREAD_IGNORE, L_FBC_MISC_BREAD_0, L_FBC_MISC_BREAD_1,
	L_FBC_MISC_BREAD_ILLEGAL
} l_fbc_misc_bread_t;

typedef enum {
	L_FBC_MISC_BDISP_IGNORE, L_FBC_MISC_BDISP_0, L_FBC_MISC_BDISP_1,
	L_FBC_MISC_BDISP_ILLEGAL
} l_fbc_misc_bdisp_t;

struct l_fbc_misc {
	uint32_t	: 10;			/* not used */
	l_fbc_misc_blit_t	l_fbc_misc_blit : 2;	/* blit src check */
	uint32_t	l_fbc_misc_vblank : 1;	/* 1 == VBLANK has occured */
	l_fbc_misc_data_t	l_fbc_misc_data : 2;	/* Color mode select  */
	l_fbc_misc_draw_t	l_fbc_misc_draw : 2;	/* Render/Pick mode  */
	l_fbc_misc_bwrite0_t	l_fbc_misc_bwrite0 : 2;	/* buffer 0 write */
	l_fbc_misc_bwrite1_t	l_fbc_misc_bwrite1 : 2;	/* buffer 1 write */
	l_fbc_misc_bread_t	l_fbc_misc_bread : 2;	/* read enable	  */
	l_fbc_misc_bdisp_t	l_fbc_misc_bdisp : 2;	/* display enable  */
	uint32_t	l_fbc_misc_index_mod : 1;	/* modify index  */
	uint32_t	l_fbc_misc_index : 2;		/* index	  */
	uint32_t	: 4;				/* not used */
};

/*
 * FBC RASTEROP register bits
 */
typedef enum {
	L_FBC_RASTEROP_PLANE_IGNORE, L_FBC_RASTEROP_PLANE_ZEROES,
	L_FBC_RASTEROP_PLANE_ONES, L_FBC_RASTEROP_PLANE_MASK
} l_fbc_rasterop_plane_t;

typedef enum {
	L_FBC_RASTEROP_PIXEL_IGNORE, L_FBC_RASTEROP_PIXEL_ZEROES,
	L_FBC_RASTEROP_PIXEL_ONES, L_FBC_RASTEROP_PIXEL_MASK
} l_fbc_rasterop_pixel_t;

typedef enum {
	L_FBC_RASTEROP_PATTERN_IGNORE, L_FBC_RASTEROP_PATTERN_ZEROES,
	L_FBC_RASTEROP_PATTERN_ONES, L_FBC_RASTEROP_PATTERN_MASK
} l_fbc_rasterop_patt_t;

typedef enum {
	L_FBC_RASTEROP_POLYG_IGNORE, L_FBC_RASTEROP_POLYG_OVERLAP,
	L_FBC_RASTEROP_POLYG_NONOVERLAP, L_FBC_RASTEROP_POLYG_ILLEGAL
} l_fbc_rasterop_polyg_t;

typedef enum {
	L_FBC_RASTEROP_ATTR_IGNORE, L_FBC_RASTEROP_ATTR_UNSUPP,
	L_FBC_RASTEROP_ATTR_SUPP, L_FBC_RASTEROP_ATTR_ILLEGAL
} l_fbc_rasterop_attr_t;

typedef enum {
	L_FBC_RASTEROP_RAST_BOOL, L_FBC_RASTEROP_RAST_LINEAR
} l_fbc_rasterop_rast_t;

typedef enum {
	L_FBC_RASTEROP_PLOT_PLOT, L_FBC_RASTEROP_PLOT_UNPLOT
} l_fbc_rasterop_plot_t;

struct l_fbc_rasterop {
	l_fbc_rasterop_plane_t	l_fbc_rasterop_plane : 2; /* plane mask */
	l_fbc_rasterop_pixel_t	l_fbc_rasterop_pixel : 2; /* pixel mask */
	l_fbc_rasterop_patt_t	l_fbc_rasterop_patt : 2;  /* pattern mask */
	l_fbc_rasterop_polyg_t	l_fbc_rasterop_polyg : 2; /* polygon draw */
	l_fbc_rasterop_attr_t	l_fbc_rasterop_attr : 2;  /* attribute select */
	uint32_t	: 4;				  /* not used */
	l_fbc_rasterop_rast_t	l_fbc_rasterop_rast : 1;  /* rasterop mode */
	l_fbc_rasterop_plot_t	l_fbc_rasterop_plot : 1;  /* plot/unplot mode */
	uint32_t	l_fbc_rasterop_rop11: 4; /* rasterop for f==1, b==1 */
	uint32_t	l_fbc_rasterop_rop10: 4; /* rasterop for f==1, b==0 */
	uint32_t	l_fbc_rasterop_rop01: 4; /* rasterop for f==0, b==1 */
	uint32_t	l_fbc_rasterop_rop00: 4; /* rasterop for f==0, b==0 */
};

/*
 * FBC PATTALIGN register bits
 */
union l_fbc_pattalign {
	uint32_t word;
	uint16_t l_fbc_pattalign_array[2];
#define	l_fbc_pattalign_alignx	l_fbc_pattalign_array[0]
#define	l_fbc_pattalign_aligny	l_fbc_pattalign_array[1]
};

/*
 * FBC offsets &  structure definition
 */
struct fbc {

/* miscellaneous & clipcheck registers */

	uint8_t			fil0[ 0x4 ];

	struct	l_fbc_misc	l_fbc_misc;
	uint32_t		l_fbc_clipcheck;

#define	L_FBC_MISC		(0x004 / sizeof (uint32_t))
#define	L_FBC_CLIPCHECK		(0x008 / sizeof (uint32_t))

	uint8_t			fill00[ 0x10 - 0x08 - 4 ];

	uint32_t		l_fbc_status;
	uint32_t		l_fbc_drawstatus;
	uint32_t		l_fbc_blitstatus;
	uint32_t		l_fbc_font;

/* status and command registers */
#define	L_FBC_STATUS		(0x010 / sizeof (uint32_t))
#define	L_FBC_DRAWSTATUS	(0x014 / sizeof (uint32_t))
#define	L_FBC_BLITSTATUS	(0x018 / sizeof (uint32_t))
#define	L_FBC_FONT		(0x01C / sizeof (uint32_t))

	uint8_t			fill01[ 0x80 - 0x1C - 4 ];

	uint32_t		l_fbc_x0;
	uint32_t		l_fbc_y0;
	uint32_t		l_fbc_z0;
	uint32_t		l_fbc_color0;
	uint32_t		l_fbc_x1;
	uint32_t		l_fbc_y1;
	uint32_t		l_fbc_z1;
	uint32_t		l_fbc_color1;
	uint32_t		l_fbc_x2;
	uint32_t		l_fbc_y2;
	uint32_t		l_fbc_z2;
	uint32_t		l_fbc_color2;
	uint32_t		l_fbc_x3;
	uint32_t		l_fbc_y3;
	uint32_t		l_fbc_z3;
	uint32_t		l_fbc_color3;

/* address registers */
/* writing a z-register just sets the corresponding z clip status bits */
#define	L_FBC_X0		(0x080 / sizeof (uint32_t))
#define	L_FBC_Y0		(0x084 / sizeof (uint32_t))
#define	L_FBC_Z0		(0x088 / sizeof (uint32_t))
#define	L_FBC_COLOR0		(0x08C / sizeof (uint32_t))
#define	L_FBC_X1		(0x090 / sizeof (uint32_t))
#define	L_FBC_Y1		(0x094 / sizeof (uint32_t))
#define	L_FBC_Z1		(0x098 / sizeof (uint32_t))
#define	L_FBC_COLOR1		(0x09C / sizeof (uint32_t))
#define	L_FBC_X2		(0x0A0 / sizeof (uint32_t))
#define	L_FBC_Y2		(0x0A4 / sizeof (uint32_t))
#define	L_FBC_Z2		(0x0A8 / sizeof (uint32_t))
#define	L_FBC_COLOR2		(0x0AC / sizeof (uint32_t))
#define	L_FBC_X3		(0x0B0 / sizeof (uint32_t))
#define	L_FBC_Y3		(0x0B4 / sizeof (uint32_t))
#define	L_FBC_Z3		(0x0B8 / sizeof (uint32_t))
#define	L_FBC_COLOR3		(0x0BC / sizeof (uint32_t))

/* raster offset registers */

	uint32_t		l_fbc_rasteroffx;
	uint32_t		l_fbc_rasteroffy;

#define	L_FBC_RASTEROFFX	(0x0C0 / sizeof (uint32_t))
#define	L_FBC_RASTEROFFY	(0x0C4 / sizeof (uint32_t))

	uint8_t			fill02[ 0xD0 - 0xC4 - 4 ];

	uint32_t		l_fbc_autoincx;
	uint32_t		l_fbc_autoincy;

/* autoincrement registers */
#define	L_FBC_AUTOINCX		(0x0D0 / sizeof (uint32_t))
#define	L_FBC_AUTOINCY		(0x0D4 / sizeof (uint32_t))


/* window registers */

	uint8_t			fill03[ 0xE0 - 0xD4 - 4 ];

	uint32_t		l_fbc_clipminx;
	uint32_t		l_fbc_clipminy;

#define	L_FBC_CLIPMINX		(0x0E0 / sizeof (uint32_t))
#define	L_FBC_CLIPMINY		(0x0E4 / sizeof (uint32_t))

	uint8_t			fill04[ 0xF0 - 0xE4 - 4 ];

	uint32_t		l_fbc_clipmaxx;
	uint32_t		l_fbc_clipmaxy;

#define	L_FBC_CLIPMAXX		(0x0F0 / sizeof (uint32_t))
#define	L_FBC_CLIPMAXY		(0x0F4 / sizeof (uint32_t))

	uint8_t			fill05[ 0x100 - 0x0F4 - 4 ];

	uint32_t		l_fbc_fcolor;
	uint32_t		l_fbc_bcolor;
	struct l_fbc_rasterop	l_fbc_rasterop;
	uint32_t		l_fbc_planemask;
	uint32_t		l_fbc_pixelmask;

/* attribute registers */
#define	L_FBC_FCOLOR		(0x100 / sizeof (uint32_t))
#define	L_FBC_BCOLOR		(0x104 / sizeof (uint32_t))
#define	L_FBC_RASTEROP		(0x108 / sizeof (uint32_t))
#define	L_FBC_PLANEMASK		(0x10C / sizeof (uint32_t))
#define	L_FBC_PIXELMASK		(0x110 / sizeof (uint32_t))

	uint8_t 		fill06[ 0x11C - 0x110 - 4 ];

	union l_fbc_pattalign	l_fbc_pattalign;

#define	L_FBC_PATTALIGN		(0x11C / sizeof (uint32_t))

	uint32_t		l_fbc_pattern0;
	uint32_t		l_fbc_pattern1;
	uint32_t		l_fbc_pattern2;
	uint32_t		l_fbc_pattern3;
	uint32_t		l_fbc_pattern4;
	uint32_t		l_fbc_pattern5;
	uint32_t		l_fbc_pattern6;
	uint32_t		l_fbc_pattern7;

#define	L_FBC_PATTERN0		(0x120 / sizeof (uint32_t))
#define	L_FBC_PATTERN1		(0x124 / sizeof (uint32_t))
#define	L_FBC_PATTERN2		(0x128 / sizeof (uint32_t))
#define	L_FBC_PATTERN3		(0x12C / sizeof (uint32_t))
#define	L_FBC_PATTERN4		(0x130 / sizeof (uint32_t))
#define	L_FBC_PATTERN5		(0x134 / sizeof (uint32_t))
#define	L_FBC_PATTERN6		(0x138 / sizeof (uint32_t))
#define	L_FBC_PATTERN7		(0x13C / sizeof (uint32_t))

/* indexed address registers */

	uint8_t			fill07[ 0x800 - 0x13C - 4 ];

	uint32_t 		l_fbc_ipointabsx;
	uint32_t 		l_fbc_ipointabsy;
	uint32_t 		l_fbc_ipointabsz;

#define	L_FBC_IPOINTABSX	(0x800 / sizeof (uint32_t))
#define	L_FBC_IPOINTABSY	(0x804 / sizeof (uint32_t))
#define	L_FBC_IPOINTABSZ	(0x808 / sizeof (uint32_t))

	uint8_t 		fill08[ 0x810 - 0x808 - 4 ];

	uint32_t 		l_fbc_ipointrelx;
	uint32_t 		l_fbc_ipointrely;
	uint32_t 		l_fbc_ipointrelz;

#define	L_FBC_IPOINTRELX	(0x810 / sizeof (uint32_t))
#define	L_FBC_IPOINTRELY	(0x814 / sizeof (uint32_t))
#define	L_FBC_IPOINTRELZ	(0x818 / sizeof (uint32_t))

	uint8_t			fill09[ 0x830 - 0x818 - 4 ];

	uint32_t		l_fbc_ipointcolr;
	uint32_t		l_fbc_ipointcolg;
	uint32_t		l_fbc_ipointcolb;
	uint32_t		l_fbc_ipointcola;
	uint32_t		l_fbc_ilineabsx;
	uint32_t		l_fbc_ilineabsy;
	uint32_t		l_fbc_ilineabsz;

#define	L_FBC_IPOINTCOLR	(0x830 / sizeof (uint32_t))
#define	L_FBC_IPOINTCOLG	(0x834 / sizeof (uint32_t))
#define	L_FBC_IPOINTCOLB	(0x838 / sizeof (uint32_t))
#define	L_FBC_IPOINTCOLA	(0x83C / sizeof (uint32_t))
#define	L_FBC_ILINEABSX		(0x840 / sizeof (uint32_t))
#define	L_FBC_ILINEABSY		(0x844 / sizeof (uint32_t))
#define	L_FBC_ILINEABSZ		(0x848 / sizeof (uint32_t))

	uint8_t			fill10[ 0x850 - 0x848 - 4 ];

	uint32_t		l_fbc_ilinerelx;
	uint32_t		l_fbc_ilinerely;
	uint32_t		l_fbc_ilinerelz;

#define	L_FBC_ILINERELX		(0x850 / sizeof (uint32_t))
#define	L_FBC_ILINERELY		(0x854 / sizeof (uint32_t))
#define	L_FBC_ILINERELZ		(0x858 / sizeof (uint32_t))

	uint8_t			fill11[ 0x870 - 0x858 - 4 ];

	uint32_t		l_fbc_ilinecolr;
	uint32_t		l_fbc_ilinecolg;
	uint32_t		l_fbc_ilinecolb;
	uint32_t		l_fbc_ilinecola;

#define	L_FBC_ILINECOLR		(0x870 / sizeof (uint32_t))
#define	L_FBC_ILINECOLG		(0x874 / sizeof (uint32_t))
#define	L_FBC_ILINECOLB		(0x878 / sizeof (uint32_t))
#define	L_FBC_ILINECOLA		(0x87C / sizeof (uint32_t))

	uint32_t		l_fbc_itriabsx;
	uint32_t		l_fbc_itriabsy;
	uint32_t		l_fbc_itriabsz;

#define	L_FBC_ITRIABSX		(0x880 / sizeof (uint32_t))
#define	L_FBC_ITRIABSY		(0x884 / sizeof (uint32_t))
#define	L_FBC_ITRIABSZ		(0x888 / sizeof (uint32_t))

	uint8_t			fill12[ 0x890 - 0x888 - 4 ];

	uint32_t		l_fbc_itrirelx;
	uint32_t		l_fbc_itrirely;
	uint32_t		l_fbc_itrirelz;

#define	L_FBC_ITRIRELX		(0x890 / sizeof (uint32_t))
#define	L_FBC_ITRIRELY		(0x894 / sizeof (uint32_t))
#define	L_FBC_ITRIRELZ		(0x898 / sizeof (uint32_t))

	uint8_t			fill13[ 0x8B0 - 0x898 - 4 ];

	uint32_t		l_fbc_itricolr;
	uint32_t		l_fbc_itricolg;
	uint32_t		l_fbc_itricolb;
	uint32_t		l_fbc_itricola;
	uint32_t		l_fbc_iquadabsx;
	uint32_t		l_fbc_iquadabsy;
	uint32_t		l_fbc_iquadabsz;

#define	L_FBC_ITRICOLR		(0x8B0 / sizeof (uint32_t))
#define	L_FBC_ITRICOLG		(0x8B4 / sizeof (uint32_t))
#define	L_FBC_ITRICOLB		(0x8B8 / sizeof (uint32_t))
#define	L_FBC_ITRICOLA		(0x8BC / sizeof (uint32_t))
#define	L_FBC_IQUADABSX		(0x8C0 / sizeof (uint32_t))
#define	L_FBC_IQUADABSY		(0x8C4 / sizeof (uint32_t))
#define	L_FBC_IQUADABSZ		(0x8C8 / sizeof (uint32_t))

	uint8_t			fill14[ 0x8D0 - 0x8C8 - 4 ];

	uint32_t		l_fbc_iquadrelx;
	uint32_t		l_fbc_iquadrely;
	uint32_t		l_fbc_iquadrelz;

#define	L_FBC_IQUADRELX		(0x8D0 / sizeof (uint32_t))
#define	L_FBC_IQUADRELY		(0x8D4 / sizeof (uint32_t))
#define	L_FBC_IQUADRELZ		(0x8D8 / sizeof (uint32_t))

	uint8_t			fill15[ 0x8F0 - 0x8D8 - 4 ];

	uint32_t		l_fbc_iquadcolr;
	uint32_t		l_fbc_iquadcolg;
	uint32_t		l_fbc_iquadcolb;
	uint32_t		l_fbc_iquadcola;
	uint32_t		l_fbc_irectabsx;
	uint32_t		l_fbc_irectabsy;
	uint32_t		l_fbc_irectabsz;

#define	L_FBC_IQUADCOLR		(0x8F0 / sizeof (uint32_t))
#define	L_FBC_IQUADCOLG		(0x8F4 / sizeof (uint32_t))
#define	L_FBC_IQUADCOLB		(0x8F8 / sizeof (uint32_t))
#define	L_FBC_IQUADCOLA		(0x8FC / sizeof (uint32_t))
#define	L_FBC_IRECTABSX		(0x900 / sizeof (uint32_t))
#define	L_FBC_IRECTABSY		(0x904 / sizeof (uint32_t))
#define	L_FBC_IRECTABSZ		(0x908 / sizeof (uint32_t))

	uint8_t			fill17[ 0x910 - 0x908 - 4 ];

	uint32_t		l_fbc_irectrelx;
	uint32_t		l_fbc_irectrely;
	uint32_t		l_fbc_irectrelz;

#define	L_FBC_IRECTRELX		(0x910 / sizeof (uint32_t))
#define	L_FBC_IRECTRELY		(0x914 / sizeof (uint32_t))
#define	L_FBC_IRECTRELZ		(0x918 / sizeof (uint32_t))

	uint8_t			fill18[ 0x930 - 0x918 - 4 ];

	uint32_t		l_fbc_irectcolr;
	uint32_t		l_fbc_irectcolg;
	uint32_t		l_fbc_irectcolb;
	uint32_t		l_fbc_irectcola;

#define	L_FBC_IRECTCOLR		(0x930 / sizeof (uint32_t))
#define	L_FBC_IRECTCOLG		(0x934 / sizeof (uint32_t))
#define	L_FBC_IRECTCOLB		(0x938 / sizeof (uint32_t))
#define	L_FBC_IRECTCOLA		(0x93C / sizeof (uint32_t))

};

/*
 * FBC CLIPCHECK register bits.
 */
#define	CLIP_MASK	0x3
#define	CLIP_IN		0x0
#define	CLIP_LT		0x1
#define	CLIP_GT		0x2
#define	CLIP_BACK	0x3

#define	CLIP_X(bits, reg_num)	((bits) << (0+(2*(reg_num))))
#define	CLIP_Y(bits, reg_num)	((bits) << (8+(2*(reg_num))))
#define	CLIP_Z(bits, reg_num)	((bits) << (16+(2*(reg_num))))

/*
 * FBC STATUS, DRAWSTATUS, and BLITSTATUS register bits.
 */
#define	L_FBC_ACC_CLEAR		0x80000000	/* when writing STATUS */
#define	L_FBC_DRAW_EXCEPTION	0x80000000	/* when reading DRAWSTATUS */
#define	L_FBC_BLIT_EXCEPTION	0x80000000	/* when reading BLITSTATUS */
#define	L_FBC_TEC_EXCEPTION	0x40000000
#define	L_FBC_FULL		0x20000000
#define	L_FBC_BUSY		0x10000000
#define	L_FBC_UNSUPPORTED_ATTR	0x02000000
#define	L_FBC_HRMONO		0x01000000
#define	L_FBC_ACC_OVERFLOW	0x00200000
#define	L_FBC_ACC_PICK		0x00100000
#define	L_FBC_TEC_HIDDEN	0x00040000
#define	L_FBC_TEC_INTERSECT	0x00020000
#define	L_FBC_TEC_VISIBLE	0x00010000
#define	L_FBC_BLIT_HARDWARE	0x00008000
#define	L_FBC_BLIT_SOFTWARE	0x00004000
#define	L_FBC_BLIT_SRC_HID	0x00002000
#define	L_FBC_BLIT_SRC_INT	0x00001000
#define	L_FBC_BLIT_SRC_VIS	0x00000800
#define	L_FBC_BLIT_DST_HID	0x00000400
#define	L_FBC_BLIT_DST_INT	0x00000200
#define	L_FBC_BLIT_DST_VIS	0x00000100
#define	L_FBC_DRAW_HARDWARE	0x00000010
#define	L_FBC_DRAW_SOFTWARE	0x00000008
#define	L_FBC_DRAW_HIDDEN	0x00000004
#define	L_FBC_DRAW_INTERSECT	0x00000002
#define	L_FBC_DRAW_VISIBLE	0x00000001

/*
 * FBC/FHC CONFIG register
 */
#define	FHC_CONFIG_FBID_SHIFT		24
#define	FHC_CONFIG_FBID_MASK		255
#define	FHC_CONFIG_REV_SHIFT		20
#define	FHC_CONFIG_REV_MASK		15
#define	FHC_CONFIG_FROP_DISABLE		(1 << 19)
#define	FHC_CONFIG_ROW_DISABLE		(1 << 18)
#define	FHC_CONFIG_SRC_DISABLE		(1 << 17)
#define	FHC_CONFIG_DST_DISABLE		(1 << 16)
#define	FHC_CONFIG_RESET		(1 << 15)
#define	FHC_CONFIG_LITTLE_ENDIAN	(1 << 13)
#define	FHC_CONFIG_RES_MASK		(3 << 11)
#define	FHC_CONFIG_1024			(0 << 11)
#define	FHC_CONFIG_1152			(1 << 11)
#define	FHC_CONFIG_1280			(2 << 11)
#define	FHC_CONFIG_1600			(3 << 11)
#define	FHC_CONFIG_CPU_MASK		(3 << 9)
#define	FHC_CONFIG_CPU_SPARC		(0 << 9)
#define	FHC_CONFIG_CPU_68020		(1 << 9)
#define	FHC_CONFIG_CPU_386		(2 << 9)
#define	FHC_CONFIG_TEST			(1 << 8)
#define	FHC_CONFIG_TESTX_SHIFT		4
#define	FHC_CONFIG_TESTX_MASK		(15 << 4)
#define	FHC_CONFIG_TESTY_SHIFT		0
#define	FHC_CONFIG_TESTY_MASK		15

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CG6FBC_H */
