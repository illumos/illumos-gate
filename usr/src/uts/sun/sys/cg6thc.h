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
 * Copyright 1989, Sun Microsystems, Inc.
 */

#ifndef	_SYS_CG6THC_H
#define	_SYS_CG6THC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * TEC Hardware Configuration registers.
 *
 * Hardware register offsets from base address. These offsets are
 * intended to be added to a pointer-to-integer whose value is the
 * base address of the CG6 memory mapped register area.
 */

/* hardware configuration registers */

#define	L_THC_HCHS		(0x800 / sizeof (uint32_t))
#define	L_THC_HCHSDVB		(0x804 / sizeof (uint32_t))
#define	L_THC_HCHD		(0x808 / sizeof (uint32_t))
#define	L_THC_HCVS		(0x80C / sizeof (uint32_t))
#define	L_THC_HCVD		(0x810 / sizeof (uint32_t))
#define	L_THC_HCREFRESH		(0x814 / sizeof (uint32_t))
#define	L_THC_HCMISC		(0x818 / sizeof (uint32_t))

#define	THC_HCMISC_REV_SHIFT		16
#define	THC_HCMISC_REV_MASK		15
#define	THC_HCMISC_RESET		0x1000
#define	THC_HCMISC_VIDEO		0x0400
#define	THC_HCMISC_SYNC			0x0200
#define	THC_HCMISC_VSYNC		0x0100
#define	THC_HCMISC_SYNCEN		0x0080
#define	THC_HCMISC_CURSOR_RES		0x0040
#define	THC_HCMISC_INTEN		0x0020
#define	THC_HCMISC_INT			0x0010

#define	THC_HCMISC_INIT			0x009f
#define	THC_HCMISC_CLEAR_VBLANK_IRQ	0x008f

#define	thc_set_video(thc, on) \
	((thc)->l_thc_hcmisc = \
		(thc)->l_thc_hcmisc & ~THC_HCMISC_VIDEO | \
		((on) ? THC_HCMISC_VIDEO : 0))

#define	thc_get_video(thc) \
	((thc)->l_thc_hcmisc & THC_HCMISC_VIDEO)

#define	thc_int_enable(thc) \
	((thc)->l_thc_hcmisc |= THC_HCMISC_INTEN)

#define	thc_int_disable(thc) \
	((thc)->l_thc_hcmisc = \
		(thc)->l_thc_hcmisc & ~THC_HCMISC_INTEN | THC_HCMISC_INT)

#define	thc_int_pending(thc) \
	((thc)->l_thc_hcmisc & THC_HCMISC_INT)

/* cursor address register */
#define	L_THC_ADDRESS		(0x8FC / sizeof (uint32_t))

/* cursor data registers, plane A */
#define	L_THC_CURSORA00		(0x900 / sizeof (uint32_t))
#define	L_THC_CURSORA01		(0x904 / sizeof (uint32_t))
#define	L_THC_CURSORA02		(0x908 / sizeof (uint32_t))
#define	L_THC_CURSORA03		(0x90C / sizeof (uint32_t))
#define	L_THC_CURSORA04		(0x910 / sizeof (uint32_t))
#define	L_THC_CURSORA05		(0x914 / sizeof (uint32_t))
#define	L_THC_CURSORA06		(0x918 / sizeof (uint32_t))
#define	L_THC_CURSORA07		(0x91C / sizeof (uint32_t))
#define	L_THC_CURSORA08		(0x920 / sizeof (uint32_t))
#define	L_THC_CURSORA09		(0x924 / sizeof (uint32_t))
#define	L_THC_CURSORA10		(0x928 / sizeof (uint32_t))
#define	L_THC_CURSORA11		(0x92C / sizeof (uint32_t))
#define	L_THC_CURSORA12		(0x930 / sizeof (uint32_t))
#define	L_THC_CURSORA13		(0x934 / sizeof (uint32_t))
#define	L_THC_CURSORA14		(0x938 / sizeof (uint32_t))
#define	L_THC_CURSORA15		(0x93C / sizeof (uint32_t))
#define	L_THC_CURSORA16		(0x940 / sizeof (uint32_t))
#define	L_THC_CURSORA17		(0x944 / sizeof (uint32_t))
#define	L_THC_CURSORA18		(0x948 / sizeof (uint32_t))
#define	L_THC_CURSORA19		(0x94C / sizeof (uint32_t))
#define	L_THC_CURSORA20		(0x950 / sizeof (uint32_t))
#define	L_THC_CURSORA21		(0x954 / sizeof (uint32_t))
#define	L_THC_CURSORA22		(0x958 / sizeof (uint32_t))
#define	L_THC_CURSORA23		(0x95C / sizeof (uint32_t))
#define	L_THC_CURSORA24		(0x960 / sizeof (uint32_t))
#define	L_THC_CURSORA25		(0x964 / sizeof (uint32_t))
#define	L_THC_CURSORA26		(0x968 / sizeof (uint32_t))
#define	L_THC_CURSORA27		(0x96C / sizeof (uint32_t))
#define	L_THC_CURSORA28		(0x970 / sizeof (uint32_t))
#define	L_THC_CURSORA29		(0x974 / sizeof (uint32_t))
#define	L_THC_CURSORA30		(0x978 / sizeof (uint32_t))
#define	L_THC_CURSORA31		(0x97C / sizeof (uint32_t))

/* cursor data registers, plane B */
#define	L_THC_CURSORB00		(0x980 / sizeof (uint32_t))
#define	L_THC_CURSORB01		(0x984 / sizeof (uint32_t))
#define	L_THC_CURSORB02		(0x988 / sizeof (uint32_t))
#define	L_THC_CURSORB03		(0x98C / sizeof (uint32_t))
#define	L_THC_CURSORB04		(0x990 / sizeof (uint32_t))
#define	L_THC_CURSORB05		(0x994 / sizeof (uint32_t))
#define	L_THC_CURSORB06		(0x998 / sizeof (uint32_t))
#define	L_THC_CURSORB07		(0x99C / sizeof (uint32_t))
#define	L_THC_CURSORB08		(0x9A0 / sizeof (uint32_t))
#define	L_THC_CURSORB09		(0x9A4 / sizeof (uint32_t))
#define	L_THC_CURSORB10		(0x9A8 / sizeof (uint32_t))
#define	L_THC_CURSORB11		(0x9AC / sizeof (uint32_t))
#define	L_THC_CURSORB12		(0x9B0 / sizeof (uint32_t))
#define	L_THC_CURSORB13		(0x9B4 / sizeof (uint32_t))
#define	L_THC_CURSORB14		(0x9B8 / sizeof (uint32_t))
#define	L_THC_CURSORB15		(0x9BC / sizeof (uint32_t))
#define	L_THC_CURSORB16		(0x9C0 / sizeof (uint32_t))
#define	L_THC_CURSORB17		(0x9C4 / sizeof (uint32_t))
#define	L_THC_CURSORB18		(0x9C8 / sizeof (uint32_t))
#define	L_THC_CURSORB19		(0x9CC / sizeof (uint32_t))
#define	L_THC_CURSORB20		(0x9D0 / sizeof (uint32_t))
#define	L_THC_CURSORB21		(0x9D4 / sizeof (uint32_t))
#define	L_THC_CURSORB22		(0x9D8 / sizeof (uint32_t))
#define	L_THC_CURSORB23		(0x9DC / sizeof (uint32_t))
#define	L_THC_CURSORB24		(0x9E0 / sizeof (uint32_t))
#define	L_THC_CURSORB25		(0x9E4 / sizeof (uint32_t))
#define	L_THC_CURSORB26		(0x9E8 / sizeof (uint32_t))
#define	L_THC_CURSORB27		(0x9EC / sizeof (uint32_t))
#define	L_THC_CURSORB28		(0x9F0 / sizeof (uint32_t))
#define	L_THC_CURSORB29		(0x9F4 / sizeof (uint32_t))
#define	L_THC_CURSORB30		(0x9F8 / sizeof (uint32_t))
#define	L_THC_CURSORB31		(0x9FC / sizeof (uint32_t))

/*
 * THC Cursor ADDRESS register bits.
 */

struct l_thc_cursor {
	uint32_t	l_thc_cursor_x : 16;	/* X co-ordinate */
	uint32_t	l_thc_cursor_y : 16;	/* Y co-ordinate */
};

/*
 * THC Video Timing registers bits.
 */

struct l_thc_hchs {
	uint32_t	: 9;			/* not used */
	uint32_t	l_thc_hchs_hss : 7;	/* hor. sync start */
	uint32_t	: 9;			/* not used */
	uint32_t	l_thc_hchs_hse : 7;	/* hor. sync end */
};

struct l_thc_hchsdvs {
	uint32_t	: 9;			/* not used */
	uint32_t	l_thc_hchsdvs_hss : 7;	/* hor. sync end DVS */
	uint32_t	: 5;			/* not used */
	uint32_t	l_thc_hchsdvs_hse : 11;	/* current vert. line */
};

struct l_thc_hchd {
	uint32_t	: 9;			/* not used */
	uint32_t	l_thc_hchd_hds : 7;	/* hor. display start */
	uint32_t	: 9;			/* not used */
	uint32_t	l_thc_hchd_hde : 7;	/* hor. display end */
};

struct l_thc_hcvs {
	uint32_t	: 5;			/* not used */
	uint32_t	l_thc_hcvs_vss : 11;	/* vert. sync start */
	uint32_t	: 5;			/* not used */
	uint32_t	l_thc_hcvs_hse : 11;	/* vert. sync end */
};

struct l_thc_hcvd {
	uint32_t	: 5;			/* not used */
	uint32_t	l_thc_hcvd_vds : 11;	/* vert. display start */
	uint32_t	: 5;			/* not used */
	uint32_t	l_thc_hcvd_hde : 11;	/* vert. display end */
};

struct l_thc_hcr {
	uint32_t	: 21;			/* not used */
	uint32_t	l_thc_hcr_clk : 11;	/* refresh counter */
};

/*
 * THC HCMISC register bits.
 */

typedef enum {
	L_THC_HCMISC_VID_BLANK, L_THC_HCMISC_VID_DISPLAY
} l_thc_hcmisc_vid_t;

typedef enum {
	L_THC_HCMISC_INTR_IGNORE, L_THC_HCMISC_INTR_CLEAR,
	L_THC_HCMISC_INTR_SET
} l_thc_hcmisc_intr_t;

struct l_thc_hcmisc {
	uint32_t				: 12;	/* unused */
	uint32_t l_thc_hcmisc_rev		: 4;	/* chip revision */
	uint32_t				: 3;	/* unused */
	uint32_t l_thc_hcmisc_reset		: 1;	/* reset */
	uint32_t				: 1;	/* unused */
	l_thc_hcmisc_vid_t l_thc_hcmisc_vid	: 1;	/* enable video */
	uint32_t l_thc_hcmisc_sync		: 1;	/* sync */
	uint32_t l_thc_hcmisc_vsync		: 1;	/* vsync */
	uint32_t l_thc_hcmisc_ensync		: 1;	/* enable sync */
	uint32_t l_thc_hcmisc_cures		: 1;	/* cursor resolution */
	l_thc_hcmisc_intr_t l_thc_hcmisc_intr	: 2;	/* enable interrupt */
	uint32_t l_thc_hcmisc_cycles		: 4;	/* cycles before xfer */
};

/*
 * define THC registers as a structure.
 */

struct thc {
	uint32_t	l_thc_pad_0[512-0];
#ifdef structures
	struct l_thc_hchs	l_thc_hchs;		/* 512 */
	struct l_thc_hchsdvs	l_thc_hchsdvs;		/* 513 */
	struct l_thc_hchd	l_thc_hchd;		/* 514 */
	struct l_thc_hcvs	l_thc_hcvs;		/* 515 */
	struct l_thc_hcvd	l_thc_hcvd;		/* 516 */
	struct l_thc_hcr	l_thc_hcr;		/* 517 */
	struct l_thc_hcmisc	l_thc_hcmisc;		/* 518 */
	uint32_t	l_thc_pad_519[575-519];
	struct l_thc_cursor	l_thc_cursor;		/* 575 */
#else
	uint32_t 	l_thc_hchs;				/* 512 */
	uint32_t 	l_thc_hchsdvs;				/* 513 */
	uint32_t 	l_thc_hchd;				/* 514 */
	uint32_t 	l_thc_hcvs;				/* 515 */
	uint32_t 	l_thc_hcvd;				/* 516 */
	uint32_t 	l_thc_hcr;				/* 517 */
	uint32_t 	l_thc_hcmisc;				/* 518 */
	uint32_t	l_thc_pad_519[575-519];
	uint32_t 	l_thc_cursor;				/* 575 */
#endif
	uint32_t	l_thc_cursora00;			/* 576 */
	uint32_t	l_thc_cursora01;			/* 577 */
	uint32_t	l_thc_cursora02;			/* 578 */
	uint32_t	l_thc_cursora03;			/* 579 */
	uint32_t	l_thc_cursora04;			/* 580 */
	uint32_t	l_thc_cursora05;			/* 581 */
	uint32_t	l_thc_cursora06;			/* 582 */
	uint32_t	l_thc_cursora07;			/* 583 */
	uint32_t	l_thc_cursora08;			/* 584 */
	uint32_t	l_thc_cursora09;			/* 585 */
	uint32_t	l_thc_cursora10;			/* 586 */
	uint32_t	l_thc_cursora11;			/* 587 */
	uint32_t	l_thc_cursora12;			/* 588 */
	uint32_t	l_thc_cursora13;			/* 589 */
	uint32_t	l_thc_cursora14;			/* 590 */
	uint32_t	l_thc_cursora15;			/* 591 */
	uint32_t	l_thc_cursora16;			/* 592 */
	uint32_t	l_thc_cursora17;			/* 593 */
	uint32_t	l_thc_cursora18;			/* 594 */
	uint32_t	l_thc_cursora19;			/* 595 */
	uint32_t	l_thc_cursora20;			/* 596 */
	uint32_t	l_thc_cursora21;			/* 597 */
	uint32_t	l_thc_cursora22;			/* 598 */
	uint32_t	l_thc_cursora23;			/* 599 */
	uint32_t	l_thc_cursora24;			/* 600 */
	uint32_t	l_thc_cursora25;			/* 601 */
	uint32_t	l_thc_cursora26;			/* 602 */
	uint32_t	l_thc_cursora27;			/* 603 */
	uint32_t	l_thc_cursora28;			/* 604 */
	uint32_t	l_thc_cursora29;			/* 605 */
	uint32_t	l_thc_cursora30;			/* 606 */
	uint32_t	l_thc_cursora31;			/* 607 */
	uint32_t	l_thc_cursorb00;			/* 608 */
	uint32_t	l_thc_cursorb01;			/* 609 */
	uint32_t	l_thc_cursorb02;			/* 610 */
	uint32_t	l_thc_cursorb03;			/* 611 */
	uint32_t	l_thc_cursorb04;			/* 612 */
	uint32_t	l_thc_cursorb05;			/* 613 */
	uint32_t	l_thc_cursorb06;			/* 614 */
	uint32_t	l_thc_cursorb07;			/* 615 */
	uint32_t	l_thc_cursorb08;			/* 616 */
	uint32_t	l_thc_cursorb09;			/* 617 */
	uint32_t	l_thc_cursorb10;			/* 618 */
	uint32_t	l_thc_cursorb11;			/* 619 */
	uint32_t	l_thc_cursorb12;			/* 620 */
	uint32_t	l_thc_cursorb13;			/* 621 */
	uint32_t	l_thc_cursorb14;			/* 622 */
	uint32_t	l_thc_cursorb15;			/* 623 */
	uint32_t	l_thc_cursorb16;			/* 624 */
	uint32_t	l_thc_cursorb17;			/* 625 */
	uint32_t	l_thc_cursorb18;			/* 626 */
	uint32_t	l_thc_cursorb19;			/* 627 */
	uint32_t	l_thc_cursorb20;			/* 628 */
	uint32_t	l_thc_cursorb21;			/* 629 */
	uint32_t	l_thc_cursorb22;			/* 630 */
	uint32_t	l_thc_cursorb23;			/* 631 */
	uint32_t	l_thc_cursorb24;			/* 632 */
	uint32_t	l_thc_cursorb25;			/* 633 */
	uint32_t	l_thc_cursorb26;			/* 634 */
	uint32_t	l_thc_cursorb27;			/* 635 */
	uint32_t	l_thc_cursorb28;			/* 636 */
	uint32_t	l_thc_cursorb29;			/* 637 */
	uint32_t	l_thc_cursorb30;			/* 638 */
	uint32_t	l_thc_cursorb31;			/* 639 */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CG6THC_H */
