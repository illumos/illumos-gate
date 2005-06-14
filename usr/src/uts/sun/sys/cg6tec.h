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
 * Copyright (c) 1991,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_CG6TEC_H
#define	_SYS_CG6TEC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS-4.1  1.2 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * TEC register offsets from base address. These offsets are
 * u_intended to be added to a pointer-to-integer whose value is the
 * base address of the CG6 memory mapped register area.
 */

/* base for transform data registers */

#define	L_TEC_DATA_BASE		(0x100/sizeof (uint32_t))
#define	L_TEC_DATA00		(0x100/sizeof (uint32_t))
#define	L_TEC_DATA01		(0x104/sizeof (uint32_t))
#define	L_TEC_DATA02		(0x108/sizeof (uint32_t))
#define	L_TEC_DATA03		(0x10C/sizeof (uint32_t))
#define	L_TEC_DATA04		(0x110/sizeof (uint32_t))
#define	L_TEC_DATA05		(0x114/sizeof (uint32_t))
#define	L_TEC_DATA06		(0x118/sizeof (uint32_t))
#define	L_TEC_DATA07		(0x11C/sizeof (uint32_t))
#define	L_TEC_DATA08		(0x120/sizeof (uint32_t))
#define	L_TEC_DATA09		(0x124/sizeof (uint32_t))
#define	L_TEC_DATA10		(0x128/sizeof (uint32_t))
#define	L_TEC_DATA11		(0x12C/sizeof (uint32_t))
#define	L_TEC_DATA12		(0x130/sizeof (uint32_t))
#define	L_TEC_DATA13		(0x134/sizeof (uint32_t))
#define	L_TEC_DATA14		(0x138/sizeof (uint32_t))
#define	L_TEC_DATA15		(0x13C/sizeof (uint32_t))
#define	L_TEC_DATA16		(0x140/sizeof (uint32_t))
#define	L_TEC_DATA17		(0x144/sizeof (uint32_t))
#define	L_TEC_DATA18		(0x148/sizeof (uint32_t))
#define	L_TEC_DATA19		(0x14C/sizeof (uint32_t))
#define	L_TEC_DATA20		(0x150/sizeof (uint32_t))
#define	L_TEC_DATA21		(0x154/sizeof (uint32_t))
#define	L_TEC_DATA22		(0x158/sizeof (uint32_t))
#define	L_TEC_DATA23		(0x15C/sizeof (uint32_t))
#define	L_TEC_DATA24		(0x160/sizeof (uint32_t))
#define	L_TEC_DATA25		(0x164/sizeof (uint32_t))
#define	L_TEC_DATA26		(0x168/sizeof (uint32_t))
#define	L_TEC_DATA27		(0x16C/sizeof (uint32_t))
#define	L_TEC_DATA28		(0x170/sizeof (uint32_t))
#define	L_TEC_DATA29		(0x174/sizeof (uint32_t))
#define	L_TEC_DATA30		(0x178/sizeof (uint32_t))
#define	L_TEC_DATA31		(0x17C/sizeof (uint32_t))
#define	L_TEC_DATA32		(0x180/sizeof (uint32_t))
#define	L_TEC_DATA33		(0x184/sizeof (uint32_t))
#define	L_TEC_DATA34		(0x188/sizeof (uint32_t))
#define	L_TEC_DATA35		(0x18C/sizeof (uint32_t))
#define	L_TEC_DATA36		(0x190/sizeof (uint32_t))
#define	L_TEC_DATA37		(0x194/sizeof (uint32_t))
#define	L_TEC_DATA38		(0x198/sizeof (uint32_t))
#define	L_TEC_DATA39		(0x19C/sizeof (uint32_t))
#define	L_TEC_DATA40		(0x1A0/sizeof (uint32_t))
#define	L_TEC_DATA41		(0x1A4/sizeof (uint32_t))
#define	L_TEC_DATA42		(0x1A8/sizeof (uint32_t))
#define	L_TEC_DATA43		(0x1AC/sizeof (uint32_t))
#define	L_TEC_DATA44		(0x1B0/sizeof (uint32_t))
#define	L_TEC_DATA45		(0x1B4/sizeof (uint32_t))
#define	L_TEC_DATA46		(0x1B8/sizeof (uint32_t))
#define	L_TEC_DATA47		(0x1BC/sizeof (uint32_t))
#define	L_TEC_DATA48		(0x1C0/sizeof (uint32_t))
#define	L_TEC_DATA49		(0x1C4/sizeof (uint32_t))
#define	L_TEC_DATA50		(0x1C8/sizeof (uint32_t))
#define	L_TEC_DATA51		(0x1CC/sizeof (uint32_t))
#define	L_TEC_DATA52		(0x1D0/sizeof (uint32_t))
#define	L_TEC_DATA53		(0x1D4/sizeof (uint32_t))
#define	L_TEC_DATA54		(0x1D8/sizeof (uint32_t))
#define	L_TEC_DATA55		(0x1DC/sizeof (uint32_t))
#define	L_TEC_DATA56		(0x1E0/sizeof (uint32_t))
#define	L_TEC_DATA57		(0x1E4/sizeof (uint32_t))
#define	L_TEC_DATA58		(0x1E8/sizeof (uint32_t))
#define	L_TEC_DATA59		(0x1EC/sizeof (uint32_t))
#define	L_TEC_DATA60		(0x1F0/sizeof (uint32_t))
#define	L_TEC_DATA61		(0x1F4/sizeof (uint32_t))
#define	L_TEC_DATA62		(0x1F8/sizeof (uint32_t))
#define	L_TEC_DATA63		(0x1FC/sizeof (uint32_t))


/* matrix registers */

#define	L_TEC_MV_MATRIX		(0x000/sizeof (uint32_t))
#define	L_TEC_CLIPCHECK		(0x004/sizeof (uint32_t))
#define	L_TEC_VDC_MATRIX	(0x008/sizeof (uint32_t))


/* command register */

#define	L_TEC_COMMAND1		(0x0010/sizeof (uint32_t))
#define	L_TEC_COMMAND2		(0x0014/sizeof (uint32_t))
#define	L_TEC_COMMAND3		(0x0018/sizeof (uint32_t))
#define	L_TEC_COMMAND4		(0x001c/sizeof (uint32_t))


/* uint32_teger indexed address registers */

#define	L_TEC_IPOINTABSX	(0x800 / sizeof (uint32_t))
#define	L_TEC_IPOINTABSY	(0x804 / sizeof (uint32_t))
#define	L_TEC_IPOINTABSZ	(0x808 / sizeof (uint32_t))
#define	L_TEC_IPOINTABSW	(0x80C / sizeof (uint32_t))
#define	L_TEC_IPOINTRELX	(0x810 / sizeof (uint32_t))
#define	L_TEC_IPOINTRELY	(0x814 / sizeof (uint32_t))
#define	L_TEC_IPOINTRELZ	(0x818 / sizeof (uint32_t))
#define	L_TEC_IPOINTRELW	(0x81C / sizeof (uint32_t))

#define	L_TEC_ILINEABSX		(0x840 / sizeof (uint32_t))
#define	L_TEC_ILINEABSY		(0x844 / sizeof (uint32_t))
#define	L_TEC_ILINEABSZ		(0x848 / sizeof (uint32_t))
#define	L_TEC_ILINEABSW		(0x84C / sizeof (uint32_t))
#define	L_TEC_ILINERELX		(0x850 / sizeof (uint32_t))
#define	L_TEC_ILINERELY		(0x854 / sizeof (uint32_t))
#define	L_TEC_ILINERELZ		(0x858 / sizeof (uint32_t))
#define	L_TEC_ILINERELW		(0x85C / sizeof (uint32_t))

#define	L_TEC_ITRIABSX		(0x880 / sizeof (uint32_t))
#define	L_TEC_ITRIABSY		(0x884 / sizeof (uint32_t))
#define	L_TEC_ITRIABSZ		(0x888 / sizeof (uint32_t))
#define	L_TEC_ITRIABSW		(0x88C / sizeof (uint32_t))
#define	L_TEC_ITRIRELX		(0x890 / sizeof (uint32_t))
#define	L_TEC_ITRIRELY		(0x894 / sizeof (uint32_t))
#define	L_TEC_ITRIRELZ		(0x898 / sizeof (uint32_t))
#define	L_TEC_ITRIRELW		(0x89C / sizeof (uint32_t))

#define	L_TEC_IQUADABSX		(0x8C0 / sizeof (uint32_t))
#define	L_TEC_IQUADABSY		(0x8C4 / sizeof (uint32_t))
#define	L_TEC_IQUADABSZ		(0x8C8 / sizeof (uint32_t))
#define	L_TEC_IQUADABSW		(0x8CC / sizeof (uint32_t))
#define	L_TEC_IQUADRELX		(0x8D0 / sizeof (uint32_t))
#define	L_TEC_IQUADRELY		(0x8D4 / sizeof (uint32_t))
#define	L_TEC_IQUADRELZ		(0x8D8 / sizeof (uint32_t))
#define	L_TEC_IQUADRELW		(0x8DC / sizeof (uint32_t))

#define	L_TEC_IRECTABSX		(0x900 / sizeof (uint32_t))
#define	L_TEC_IRECTABSY		(0x904 / sizeof (uint32_t))
#define	L_TEC_IRECTABSZ		(0x908 / sizeof (uint32_t))
#define	L_TEC_IRECTABSW		(0x90C / sizeof (uint32_t))
#define	L_TEC_IRECTRELX		(0x910 / sizeof (uint32_t))
#define	L_TEC_IRECTRELY		(0x914 / sizeof (uint32_t))
#define	L_TEC_IRECTRELZ		(0x918 / sizeof (uint32_t))
#define	L_TEC_IRECTRELW		(0x91C / sizeof (uint32_t))

/* fixed pouint32_t indexed address registers */

#define	L_TEC_BPOINTABSX	(0xA00 / sizeof (uint32_t))
#define	L_TEC_BPOINTABSY	(0xA04 / sizeof (uint32_t))
#define	L_TEC_BPOINTABSZ	(0xA08 / sizeof (uint32_t))
#define	L_TEC_BPOINTABSW	(0xA0C / sizeof (uint32_t))
#define	L_TEC_BPOINTRELX	(0xA10 / sizeof (uint32_t))
#define	L_TEC_BPOINTRELY	(0xA14 / sizeof (uint32_t))
#define	L_TEC_BPOINTRELZ	(0xA18 / sizeof (uint32_t))
#define	L_TEC_BPOINTRELW	(0xA1C / sizeof (uint32_t))

#define	L_TEC_BLINEABSX		(0xA40 / sizeof (uint32_t))
#define	L_TEC_BLINEABSY		(0xA44 / sizeof (uint32_t))
#define	L_TEC_BLINEABSZ		(0xA48 / sizeof (uint32_t))
#define	L_TEC_BLINEABSW		(0xA4C / sizeof (uint32_t))
#define	L_TEC_BLINERELX		(0xA50 / sizeof (uint32_t))
#define	L_TEC_BLINERELY		(0xA54 / sizeof (uint32_t))
#define	L_TEC_BLINERELZ		(0xA58 / sizeof (uint32_t))
#define	L_TEC_BLINERELW		(0xA5C / sizeof (uint32_t))

#define	L_TEC_BTRIABSX		(0xA80 / sizeof (uint32_t))
#define	L_TEC_BTRIABSY		(0xA84 / sizeof (uint32_t))
#define	L_TEC_BTRIABSZ		(0xA88 / sizeof (uint32_t))
#define	L_TEC_BTRIABSW		(0xA8C / sizeof (uint32_t))
#define	L_TEC_BTRIRELX		(0xA90 / sizeof (uint32_t))
#define	L_TEC_BTRIRELY		(0xA94 / sizeof (uint32_t))
#define	L_TEC_BTRIRELZ		(0xA98 / sizeof (uint32_t))
#define	L_TEC_BTRIRELW		(0xA9C / sizeof (uint32_t))

#define	L_TEC_BQUADABSX		(0xAC0 / sizeof (uint32_t))
#define	L_TEC_BQUADABSY		(0xAC4 / sizeof (uint32_t))
#define	L_TEC_BQUADABSZ		(0xAC8 / sizeof (uint32_t))
#define	L_TEC_BQUADABSW		(0xACC / sizeof (uint32_t))
#define	L_TEC_BQUADRELX		(0xAD0 / sizeof (uint32_t))
#define	L_TEC_BQUADRELY		(0xAD4 / sizeof (uint32_t))
#define	L_TEC_BQUADRELZ		(0xAD8 / sizeof (uint32_t))
#define	L_TEC_BQUADRELW		(0xADC / sizeof (uint32_t))

#define	L_TEC_BRECTABSX		(0xB00 / sizeof (uint32_t))
#define	L_TEC_BRECTABSY		(0xB04 / sizeof (uint32_t))
#define	L_TEC_BRECTABSZ		(0xB08 / sizeof (uint32_t))
#define	L_TEC_BRECTABSW		(0xB0C / sizeof (uint32_t))
#define	L_TEC_BRECTRELX		(0xB10 / sizeof (uint32_t))
#define	L_TEC_BRECTRELY		(0xB14 / sizeof (uint32_t))
#define	L_TEC_BRECTRELZ		(0xB18 / sizeof (uint32_t))
#define	L_TEC_BRECTRELW		(0xB1C / sizeof (uint32_t))

/* floating pouint32_t indexed address registers */

#define	L_TEC_FPOINTABSX	(0xC00 / sizeof (uint32_t))
#define	L_TEC_FPOINTABSY	(0xC04 / sizeof (uint32_t))
#define	L_TEC_FPOINTABSZ	(0xC08 / sizeof (uint32_t))
#define	L_TEC_FPOINTABSW	(0xC0C / sizeof (uint32_t))
#define	L_TEC_FPOINTRELX	(0xC10 / sizeof (uint32_t))
#define	L_TEC_FPOINTRELY	(0xC14 / sizeof (uint32_t))
#define	L_TEC_FPOINTRELZ	(0xC18 / sizeof (uint32_t))
#define	L_TEC_FPOINTRELW	(0xC1C / sizeof (uint32_t))

#define	L_TEC_FLINEABSX		(0xC40 / sizeof (uint32_t))
#define	L_TEC_FLINEABSY		(0xC44 / sizeof (uint32_t))
#define	L_TEC_FLINEABSZ		(0xC48 / sizeof (uint32_t))
#define	L_TEC_FLINEABSW		(0xC4C / sizeof (uint32_t))
#define	L_TEC_FLINERELX		(0xC50 / sizeof (uint32_t))
#define	L_TEC_FLINERELY		(0xC54 / sizeof (uint32_t))
#define	L_TEC_FLINERELZ		(0xC58 / sizeof (uint32_t))
#define	L_TEC_FLINERELW		(0xC5C / sizeof (uint32_t))

#define	L_TEC_FTRIABSX		(0xC80 / sizeof (uint32_t))
#define	L_TEC_FTRIABSY		(0xC84 / sizeof (uint32_t))
#define	L_TEC_FTRIABSZ		(0xC88 / sizeof (uint32_t))
#define	L_TEC_FTRIABSW		(0xC8C / sizeof (uint32_t))
#define	L_TEC_FTRIRELX		(0xC90 / sizeof (uint32_t))
#define	L_TEC_FTRIRELY		(0xC94 / sizeof (uint32_t))
#define	L_TEC_FTRIRELZ		(0xC98 / sizeof (uint32_t))
#define	L_TEC_FTRIRELW		(0xC9C / sizeof (uint32_t))

#define	L_TEC_FQUADABSX		(0xCC0 / sizeof (uint32_t))
#define	L_TEC_FQUADABSY		(0xCC4 / sizeof (uint32_t))
#define	L_TEC_FQUADABSZ		(0xCC8 / sizeof (uint32_t))
#define	L_TEC_FQUADABSW		(0xCCC / sizeof (uint32_t))
#define	L_TEC_FQUADRELX		(0xCD0 / sizeof (uint32_t))
#define	L_TEC_FQUADRELY		(0xCD4 / sizeof (uint32_t))
#define	L_TEC_FQUADRELZ		(0xCD8 / sizeof (uint32_t))
#define	L_TEC_FQUADRELW		(0xCDC / sizeof (uint32_t))

#define	L_TEC_FRECTABSX		(0xD00 / sizeof (uint32_t))
#define	L_TEC_FRECTABSY		(0xD04 / sizeof (uint32_t))
#define	L_TEC_FRECTABSZ		(0xD08 / sizeof (uint32_t))
#define	L_TEC_FRECTABSW		(0xD0C / sizeof (uint32_t))
#define	L_TEC_FRECTRELX		(0xD10 / sizeof (uint32_t))
#define	L_TEC_FRECTRELY		(0xD14 / sizeof (uint32_t))
#define	L_TEC_FRECTRELZ		(0xD18 / sizeof (uint32_t))
#define	L_TEC_FRECTRELW		(0xD1C / sizeof (uint32_t))

/*
 * Generic unsigned types for bit fields
 */
typedef enum {
	L_TEC_UNUSED = 0
} l_tec_unused_t;

/*
 * typedefs for entering index registers
 */
typedef enum {			/* coordinate type of {pou_int,line,etc} */
	L_TEC_X = 0,
	L_TEC_Y = 1,
	L_TEC_Z = 2,
	L_TEC_W = 3,		/* used as index to store index writes in */
				/* tec_data array */
	L_TEC_X_MV = 4,
	L_TEC_Y_MV = 5,
	L_TEC_Z_MV = 6,
	L_TEC_W_MV = 7,		/* used as index to store xform results */
	L_TEC_X_VDC = 8,
	L_TEC_Y_VDC = 9,
	L_TEC_Z_VDC = 10,	/* used as index to store VDC multiply result */
	L_TEC_SCRATCH = 11	/* scratch register */
} l_tec_coord_t;

typedef enum {			/* index coordinate type */
	L_TEC_INT = 0,
	L_TEC_FRAC = 1,
	L_TEC_FLOAT = 2
} l_tec_type_t;

typedef enum {			/* index object type */
	L_TEC_POINT = 0,
	L_TEC_LINE = 1,
	L_TEC_TRI = 2,
	L_TEC_QUAD = 3,
	L_TEC_RECT = 4
} l_tec_object_t;

typedef enum {
	L_TEC_ABS = 0,
	L_TEC_REL = 1
} l_tec_mode_t;


/*
 * TEC MV_MATRIX register bits.
 */

typedef enum {
	L_TEC_MV_DIV_OFF = 0,
	L_TEC_MV_DIV_ON = 1
} l_tec_mv_div_t;

typedef enum {
	L_TEC_MV_AUTO_OFF = 0,
	L_TEC_MV_AUTO_ON = 1
} l_tec_mv_auto_t;

typedef enum {
	L_TEC_MV_H_FALSE = 0,
	L_TEC_MV_H_TRUE = 1
} l_tec_mv_h_t;

typedef enum {
	L_TEC_MV_Z_FALSE = 0, L_TEC_MV_Z_TRUE = 1
} l_tec_mv_z_t;

typedef enum {
	L_TEC_MV_I3 = 0, L_TEC_MV_I4 = 1
} l_tec_mv_i_t;

typedef enum {
	L_TEC_MV_J1 = 0, L_TEC_MV_J2 = 1, L_TEC_MV_J3 = 2, L_TEC_MV_J4 = 3
} l_tec_mv_j_t;

typedef struct l_tec_mv {
	l_tec_unused_t 	l_tec_mv_unused1	:16;	/* NOT USED */
	l_tec_mv_div_t	l_tec_mv_div 		: 1;	/* divide enable */
	l_tec_mv_auto_t	l_tec_mv_autoload 	: 1;	/* autoload enable */
	l_tec_mv_h_t	l_tec_mv_h 		: 1;	/* pou_int size */
	l_tec_mv_z_t	l_tec_mv_z 		: 1;	/* pou_int size */
	l_tec_unused_t	l_tec_mv_unused2	: 1;	/* NOT USED */
	l_tec_mv_i_t	l_tec_mv_i 		: 1;	/* matrix rows */
	l_tec_mv_j_t	l_tec_mv_j 		: 2;	/* matrix columns */
	l_tec_unused_t	l_tec_mv_unused3	: 2;	/* NOT USED */
	uint32_t	l_tec_mv_index 		: 6;	/* matrix start data */
							/* register */
} l_tec_mv_t;

/*
 * TEC CLIPCHECK bits.
 */

typedef enum {
	L_TEC_EXCEPTION_OFF = 0, L_TEC_EXCEPTION_ON = 1
} l_tec_clip_exception_t;

typedef enum {
	L_TEC_HIDDEN_OFF = 0, L_TEC_HIDDEN_ON = 1
} l_tec_clip_hidden_t;

typedef enum {
	L_TEC_INTERSECT_OFF = 0, L_TEC_INTERSECT_ON = 1
} l_tec_clip_u_intersect_t;

typedef enum {
	L_TEC_VISIBLE_OFF = 0, L_TEC_VISIBLE_ON = 1
} l_tec_clip_visible_t;

typedef enum {
	L_TEC_ACC_BACKSIDE_FALSE = 0,   L_TEC_ACC_BACKSIDE_TRUE = 1
} l_tec_clip_acc_backside_t;

typedef enum {
	L_TEC_ACC_LT_FALSE = 0, L_TEC_ACC_LT_TRUE = 1
} l_tec_clip_acc_lt_t;

typedef enum {
	L_TEC_ACC_INSIDE_FALSE = 0, L_TEC_ACC_INSIDE_TRUE = 1
} l_tec_clip_acc_inside_t;

typedef enum {
	L_TEC_ACC_GT_FALSE = 0, L_TEC_ACC_GT_TRUE = 1
} l_tec_clip_acc_gt_t;

typedef enum {
	L_TEC_LT_FALSE = 0, L_TEC_LT_TRUE = 1
} l_tec_clip_lt_t;

typedef enum {
	L_TEC_GT_FALSE = 0, L_TEC_GT_TRUE = 1
} l_tec_clip_gt_t;

typedef enum {
	L_TEC_CLIP_OFF = 0, L_TEC_CLIP_ON = 1
} l_tec_clip_enable_t;

typedef struct l_tec_clip {		/* big assumption here is compiler */
					/* assigns bit fields left to right */
	l_tec_clip_exception_t		l_tec_clip_exception		: 1;
	l_tec_clip_hidden_t		l_tec_clip_hidden		: 1;
	l_tec_clip_u_intersect_t	l_tec_clip_intersect		: 1;
	l_tec_clip_visible_t		l_tec_clip_visible		: 1;
	l_tec_unused_t			l_tec_clip_unused1		: 3;
	l_tec_clip_enable_t		l_tec_clip_enable		: 1;

	l_tec_clip_acc_backside_t	l_tec_clip_acc_z_backside	: 1;
	l_tec_clip_acc_lt_t		l_tec_clip_acc_z_lt_front	: 1;
	l_tec_clip_acc_inside_t		l_tec_clip_acc_z_inside		: 1;
	l_tec_clip_acc_gt_t		l_tec_clip_acc_z_gt_back	: 1;
	l_tec_clip_lt_t			l_tec_clip_z_lt_front		: 1;
	l_tec_clip_gt_t			l_tec_clip_z_gt_back		: 1;
	l_tec_clip_enable_t		l_tec_clip_front		: 1;
	l_tec_clip_enable_t		l_tec_clip_back			: 1;

	l_tec_clip_acc_backside_t	l_tec_clip_acc_y_backside	: 1;
	l_tec_clip_acc_lt_t		l_tec_clip_acc_y_lt_bottom	: 1;
	l_tec_clip_acc_inside_t		l_tec_clip_acc_y_inside		: 1;
	l_tec_clip_acc_gt_t		l_tec_clip_acc_y_gt_top		: 1;
	l_tec_clip_lt_t			l_tec_clip_y_lt_bottom		: 1;
	l_tec_clip_gt_t			l_tec_clip_y_gt_top		: 1;
	l_tec_clip_enable_t		l_tec_clip_bottom		: 1;
	l_tec_clip_enable_t		l_tec_clip_top			: 1;

	l_tec_clip_acc_backside_t	l_tec_clip_acc_x_backside	: 1;
	l_tec_clip_acc_lt_t		l_tec_clip_acc_x_lt_left	: 1;
	l_tec_clip_acc_inside_t		l_tec_clip_acc_x_inside		: 1;
	l_tec_clip_acc_gt_t		l_tec_clip_acc_x_gt_right	: 1;
	l_tec_clip_lt_t			l_tec_clip_x_lt_left		: 1;
	l_tec_clip_gt_t			l_tec_clip_x_gt_right		: 1;
	l_tec_clip_enable_t		l_tec_clip_left			: 1;
	l_tec_clip_enable_t		l_tec_clip_right		: 1;
} l_tec_clip_t;


/*
 * TEC VDC_MATRIX register bits.
 */

typedef enum {
	L_TEC_VDC_INT = 0, L_TEC_VDC_FIXED = 1, L_TEC_VDC_FLOAT = 2,
	L_TEC_VDC_INTRNL0 = 4, L_TEC_VDC_INTRNL1 = 5
}l_tec_vdc_type_t;

typedef enum {
	L_TEC_VDC_2D = 0, L_TEC_VDC_3D = 1
	}l_tec_vdc_k_t;

typedef enum {
	L_TEC_VDC_MUL_OFF = 0, L_TEC_VDC_MUL_ON = 1
	}l_tec_vdc_mul_t;


typedef struct l_tec_vdc {
	l_tec_unused_t	l_tec_vdc_unused1	: 16;	/* NOT USED */
	l_tec_vdc_type_t l_tec_vdc_type 	: 3;	/* reg. access type */
	l_tec_vdc_mul_t	l_tec_vdc_mul 		: 1;	/* enable VDC mult. */
	l_tec_unused_t	l_tec_vdc_unused2	: 3;	/* NOT USED */
	l_tec_vdc_k_t	l_tec_vdc_k 		: 1;	/* 2D/3D format */
	l_tec_unused_t	l_tec_vdc_unused3	: 2;	/* NOT USED */
	uint32_t	l_tec_vdc_index 	: 6;	/* matrix start data */
							/* register */
} l_tec_vdc_t;

/*
 * TEC COMMAND register bits.
 */

typedef enum {
	L_TEC_CMD_M1 = 0,
	L_TEC_CMD_M2 = 1,
	L_TEC_CMD_M3 = 2,
	L_TEC_CMD_M4 = 3
}l_tec_cmd_m_t;

typedef enum {
	L_TEC_CMD_N1 = 0,
	L_TEC_CMD_N2 = 1,
	L_TEC_CMD_N3 = 2,
	L_TEC_CMD_N4 = 3
}l_tec_cmd_n_t;

typedef enum {
	L_TEC_CMD_I_POS = 0,
	L_TEC_CMD_I_NEG = 1
}l_tec_cmd_i_t;

typedef struct l_tec_cmd {
	l_tec_cmd_m_t	l_tec_cmd_m : 2;	/* matrix A columns */
	l_tec_cmd_n_t	l_tec_cmd_n : 2;	/* matrix B columns */
	l_tec_cmd_i_t	l_tec_cmd_i11 : 1;	/* identity diagonal sign */
	l_tec_cmd_i_t	l_tec_cmd_i22 : 1;	/* identity diagonal sign */
	l_tec_cmd_i_t	l_tec_cmd_i33 : 1;	/* identity diagonal sign */
	l_tec_cmd_i_t	l_tec_cmd_i44 : 1;	/* identity diagonal sign */
	l_tec_unused_t	l_tec_cmd_unused1 : 2;	/* NOT USED */
	uint32_t	l_tec_cmd_Aindex : 6;	/* A matrix start data reg. */
	l_tec_unused_t	l_tec_cmd_unused2 : 2;	/* NOT USED */
	uint32_t	l_tec_cmd_Bindex : 6;	/* B matrix start data reg. */
	l_tec_unused_t	l_tec_cmd_unused3 : 2;	/* NOT USED */
	uint32_t	l_tec_cmd_Cindex : 6;	/* C matrix start data reg. */
} l_tec_cmd_t;

/*
 * TEC registers defined as a structure.
 */
struct tec {
#ifdef structures
	struct l_tec_mv		l_tec_mv;			/* 0 */
	struct l_tec_clip	l_tec_clip;			/* 1 */
	struct l_tec_vdc	l_tec_vdc;			/* 2 */
	uint32_t		l_tec_pad_3[4-3];
	struct l_tec_cmd	l_tec_command1;			/* 4 */
	struct l_tec_cmd	l_tec_command2;			/* 5 */
	struct l_tec_cmd	l_tec_command3;			/* 6 */
	struct l_tec_cmd	l_tec_command4;			/* 7 */
#else
	uint32_t 	l_tec_mv;				/* 0 */
	uint32_t 	l_tec_clip;				/* 1 */
	uint32_t 	l_tec_vdc;				/* 2 */
	uint32_t	l_tec_pad_3[4-3];
	uint32_t 	l_tec_command1;				/* 4 */
	uint32_t 	l_tec_command2;				/* 5 */
	uint32_t 	l_tec_command3;				/* 6 */
	uint32_t 	l_tec_command4;				/* 7 */
#endif
	uint32_t	l_tec_pad_8[64-8];
	uint32_t	l_tec_data00;				/* 64 */
	uint32_t	l_tec_data01;				/* 65 */
	uint32_t	l_tec_data02;				/* 66 */
	uint32_t	l_tec_data03;				/* 67 */
	uint32_t	l_tec_data04;				/* 68 */
	uint32_t	l_tec_data05;				/* 69 */
	uint32_t	l_tec_data06;				/* 70 */
	uint32_t	l_tec_data07;				/* 71 */
	uint32_t	l_tec_data08;				/* 72 */
	uint32_t	l_tec_data09;				/* 73 */
	uint32_t	l_tec_data10;				/* 74 */
	uint32_t	l_tec_data11;				/* 75 */
	uint32_t	l_tec_data12;				/* 76 */
	uint32_t	l_tec_data13;				/* 77 */
	uint32_t	l_tec_data14;				/* 78 */
	uint32_t	l_tec_data15;				/* 79 */
	uint32_t	l_tec_data16;				/* 80 */
	uint32_t	l_tec_data17;				/* 81 */
	uint32_t	l_tec_data18;				/* 82 */
	uint32_t	l_tec_data19;				/* 83 */
	uint32_t	l_tec_data20;				/* 84 */
	uint32_t	l_tec_data21;				/* 85 */
	uint32_t	l_tec_data22;				/* 86 */
	uint32_t	l_tec_data23;				/* 87 */
	uint32_t	l_tec_data24;				/* 88 */
	uint32_t	l_tec_data25;				/* 89 */
	uint32_t	l_tec_data26;				/* 90 */
	uint32_t	l_tec_data27;				/* 91 */
	uint32_t	l_tec_data28;				/* 92 */
	uint32_t	l_tec_data29;				/* 93 */
	uint32_t	l_tec_data30;				/* 94 */
	uint32_t	l_tec_data31;				/* 95 */
	uint32_t	l_tec_data32;				/* 96 */
	uint32_t	l_tec_data33;				/* 97 */
	uint32_t	l_tec_data34;				/* 98 */
	uint32_t	l_tec_data35;				/* 99 */
	uint32_t	l_tec_data36;				/* 100 */
	uint32_t	l_tec_data37;				/* 101 */
	uint32_t	l_tec_data38;				/* 102 */
	uint32_t	l_tec_data39;				/* 103 */
	uint32_t	l_tec_data40;				/* 104 */
	uint32_t	l_tec_data41;				/* 105 */
	uint32_t	l_tec_data42;				/* 106 */
	uint32_t	l_tec_data43;				/* 107 */
	uint32_t	l_tec_data44;				/* 108 */
	uint32_t	l_tec_data45;				/* 109 */
	uint32_t	l_tec_data46;				/* 110 */
	uint32_t	l_tec_data47;				/* 111 */
	uint32_t	l_tec_data48;				/* 112 */
	uint32_t	l_tec_data49;				/* 113 */
	uint32_t	l_tec_data50;				/* 114 */
	uint32_t	l_tec_data51;				/* 115 */
	uint32_t	l_tec_data52;				/* 116 */
	uint32_t	l_tec_data53;				/* 117 */
	uint32_t	l_tec_data54;				/* 118 */
	uint32_t	l_tec_data55;				/* 119 */
	uint32_t	l_tec_data56;				/* 120 */
	uint32_t	l_tec_data57;				/* 121 */
	uint32_t	l_tec_data58;				/* 122 */
	uint32_t	l_tec_data59;				/* 123 */
	uint32_t	l_tec_data60;				/* 124 */
	uint32_t	l_tec_data61;				/* 125 */
	uint32_t	l_tec_data62;				/* 126 */
	uint32_t	l_tec_data63;				/* 127 */
	uint32_t	l_tec_pad_128[512-128];
	uint32_t	l_tec_ipointabsx;			/* 512 */
	uint32_t	l_tec_ipointabsy;			/* 513 */
	uint32_t	l_tec_ipointabsz;			/* 514 */
	uint32_t	l_tec_ipointabsw;			/* 515 */
	uint32_t	l_tec_ipointrelx;			/* 516 */
	uint32_t	l_tec_ipointrely;			/* 517 */
	uint32_t	l_tec_ipointrelz;			/* 518 */
	uint32_t	l_tec_ipointrelw;			/* 519 */
	uint32_t	l_tec_pad_520[528-520];
	uint32_t	l_tec_ilineabsx;			/* 528 */
	uint32_t	l_tec_ilineabsy;			/* 529 */
	uint32_t	l_tec_ilineabsz;			/* 530 */
	uint32_t	l_tec_ilineabsw;			/* 531 */
	uint32_t	l_tec_ilinerelx;			/* 532 */
	uint32_t	l_tec_ilinerely;			/* 533 */
	uint32_t	l_tec_ilinerelz;			/* 534 */
	uint32_t	l_tec_ilinerelw;			/* 535 */
	uint32_t	l_tec_pad_536[544-536];
	uint32_t	l_tec_itriabsx;				/* 544 */
	uint32_t	l_tec_itriabsy;				/* 545 */
	uint32_t	l_tec_itriabsz;				/* 546 */
	uint32_t	l_tec_itriabsw;				/* 547 */
	uint32_t	l_tec_itrirelx;				/* 548 */
	uint32_t	l_tec_itrirely;				/* 549 */
	uint32_t	l_tec_itrirelz;				/* 550 */
	uint32_t	l_tec_itrirelw;				/* 551 */
	uint32_t	l_tec_pad_552[560-552];
	uint32_t	l_tec_iquadabsx;			/* 560 */
	uint32_t	l_tec_iquadabsy;			/* 561 */
	uint32_t	l_tec_iquadabsz;			/* 562 */
	uint32_t	l_tec_iquadabsw;			/* 563 */
	uint32_t	l_tec_iquadrelx;			/* 564 */
	uint32_t	l_tec_iquadrely;			/* 565 */
	uint32_t	l_tec_iquadrelz;			/* 566 */
	uint32_t	l_tec_iquadrelw;			/* 567 */
	uint32_t	l_tec_pad_568[576-568];
	uint32_t	l_tec_irectabsx;			/* 576 */
	uint32_t	l_tec_irectabsy;			/* 577 */
	uint32_t	l_tec_irectabsz;			/* 578 */
	uint32_t	l_tec_irectabsw;			/* 579 */
	uint32_t	l_tec_irectrelx;			/* 580 */
	uint32_t	l_tec_irectrely;			/* 581 */
	uint32_t	l_tec_irectrelz;			/* 582 */
	uint32_t	l_tec_irectrelw;			/* 583 */
	uint32_t	l_tec_pad_584[640-584];
	uint32_t	l_tec_bpointabsx;			/* 640 */
	uint32_t	l_tec_bpointabsy;			/* 641 */
	uint32_t	l_tec_bpointabsz;			/* 642 */
	uint32_t	l_tec_bpointabsw;			/* 643 */
	uint32_t	l_tec_bpointrelx;			/* 644 */
	uint32_t	l_tec_bpointrely;			/* 645 */
	uint32_t	l_tec_bpointrelz;			/* 646 */
	uint32_t	l_tec_bpointrelw;			/* 647 */
	uint32_t	l_tec_pad_648[656-648];
	uint32_t	l_tec_blineabsx;			/* 656 */
	uint32_t	l_tec_blineabsy;			/* 657 */
	uint32_t	l_tec_blineabsz;			/* 658 */
	uint32_t	l_tec_blineabsw;			/* 659 */
	uint32_t	l_tec_blinerelx;			/* 660 */
	uint32_t	l_tec_blinerely;			/* 661 */
	uint32_t	l_tec_blinerelz;			/* 662 */
	uint32_t	l_tec_blinerelw;			/* 663 */
	uint32_t	l_tec_pad_664[672-664];
	uint32_t	l_tec_btriabsx;				/* 672 */
	uint32_t	l_tec_btriabsy;				/* 673 */
	uint32_t	l_tec_btriabsz;				/* 674 */
	uint32_t	l_tec_btriabsw;				/* 675 */
	uint32_t	l_tec_btrirelx;				/* 676 */
	uint32_t	l_tec_btrirely;				/* 677 */
	uint32_t	l_tec_btrirelz;				/* 678 */
	uint32_t	l_tec_btrirelw;				/* 679 */
	uint32_t	l_tec_pad_680[688-680];
	uint32_t	l_tec_bquadabsx;			/* 688 */
	uint32_t	l_tec_bquadabsy;			/* 689 */
	uint32_t	l_tec_bquadabsz;			/* 690 */
	uint32_t	l_tec_bquadabsw;			/* 691 */
	uint32_t	l_tec_bquadrelx;			/* 692 */
	uint32_t	l_tec_bquadrely;			/* 693 */
	uint32_t	l_tec_bquadrelz;			/* 694 */
	uint32_t	l_tec_bquadrelw;			/* 695 */
	uint32_t	l_tec_pad_696[704-696];
	uint32_t	l_tec_brectabsx;			/* 704 */
	uint32_t	l_tec_brectabsy;			/* 705 */
	uint32_t	l_tec_brectabsz;			/* 706 */
	uint32_t	l_tec_brectabsw;			/* 707 */
	uint32_t	l_tec_brectrelx;			/* 708 */
	uint32_t	l_tec_brectrely;			/* 709 */
	uint32_t	l_tec_brectrelz;			/* 710 */
	uint32_t	l_tec_brectrelw;			/* 711 */
	uint32_t	l_tec_pad_712[768-712];
	uint32_t	l_tec_fpointabsx;			/* 768 */
	uint32_t	l_tec_fpointabsy;			/* 769 */
	uint32_t	l_tec_fpointabsz;			/* 770 */
	uint32_t	l_tec_fpointabsw;			/* 771 */
	uint32_t	l_tec_fpointrelx;			/* 772 */
	uint32_t	l_tec_fpointrely;			/* 773 */
	uint32_t	l_tec_fpointrelz;			/* 774 */
	uint32_t	l_tec_fpointrelw;			/* 775 */
	uint32_t	l_tec_pad_776[784-776];
	uint32_t	l_tec_flineabsx;			/* 784 */
	uint32_t	l_tec_flineabsy;			/* 785 */
	uint32_t	l_tec_flineabsz;			/* 786 */
	uint32_t	l_tec_flineabsw;			/* 787 */
	uint32_t	l_tec_flinerelx;			/* 788 */
	uint32_t	l_tec_flinerely;			/* 789 */
	uint32_t	l_tec_flinerelz;			/* 790 */
	uint32_t	l_tec_flinerelw;			/* 791 */
	uint32_t	l_tec_pad_792[800-792];
	uint32_t	l_tec_ftriabsx;				/* 800 */
	uint32_t	l_tec_ftriabsy;				/* 801 */
	uint32_t	l_tec_ftriabsz;				/* 802 */
	uint32_t	l_tec_ftriabsw;				/* 803 */
	uint32_t	l_tec_ftrirelx;				/* 804 */
	uint32_t	l_tec_ftrirely;				/* 805 */
	uint32_t	l_tec_ftrirelz;				/* 806 */
	uint32_t	l_tec_ftrirelw;				/* 807 */
	uint32_t	l_tec_pad_808[816-808];
	uint32_t	l_tec_fquadabsx;			/* 816 */
	uint32_t	l_tec_fquadabsy;			/* 817 */
	uint32_t	l_tec_fquadabsz;			/* 818 */
	uint32_t	l_tec_fquadabsw;			/* 819 */
	uint32_t	l_tec_fquadrelx;			/* 820 */
	uint32_t	l_tec_fquadrely;			/* 821 */
	uint32_t	l_tec_fquadrelz;			/* 822 */
	uint32_t	l_tec_fquadrelw;			/* 823 */
	uint32_t	l_tec_pad_824[832-824];
	uint32_t	l_tec_frectabsx;			/* 832 */
	uint32_t	l_tec_frectabsy;			/* 833 */
	uint32_t	l_tec_frectabsz;			/* 834 */
	uint32_t	l_tec_frectabsw;			/* 835 */
	uint32_t	l_tec_frectrelx;			/* 836 */
	uint32_t	l_tec_frectrely;			/* 837 */
	uint32_t	l_tec_frectrelz;			/* 838 */
	uint32_t	l_tec_frectrelw;			/* 839 */
};

#define	NUM_TEC_REGS	(sizeof (struct l_tec)/sizeof (uint_t))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CG6TEC_H */
