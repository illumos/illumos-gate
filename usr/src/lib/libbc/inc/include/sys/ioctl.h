/*
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Ioctl definitions
 */

#ifndef _sys_ioctl_h
#define _sys_ioctl_h

#include <sys/ttychars.h>
#include <sys/ttydev.h>
#include <sys/ttold.h>

#define	TANDEM		O_TANDEM
#define	CBREAK		O_CBREAK
#define	LCASE		O_LCASE
#define	ECHO		O_ECHO
#define	CRMOD		O_CRMOD
#define	RAW		O_RAW
#define	ODDP		O_ODDP
#define	EVENP		O_EVENP
#define	ANYP		O_ANYP
#define	NLDELAY		O_NLDELAY
#define		NL0		O_NL0
#define		NL1		O_NL1
#define		NL2		O_NL2
#define		NL3		O_NL3
#define	TBDELAY		O_TBDELAY
#define		TAB0		O_TAB0
#define		TAB1		O_TAB1
#define		TAB2		O_TAB2
#define	XTABS		O_XTABS
#define	CRDELAY		O_CRDELAY
#define		CR0		O_CR0
#define		CR1		O_CR1
#define		CR2		O_CR2
#define		CR3		O_CR3
#define	VTDELAY		O_VTDELAY
#define		FF0		O_FF0
#define		FF1		O_FF1
#define	BSDELAY		O_BSDELAY
#define		BS0		O_BS0
#define		BS1		O_BS1
#define 	ALLDELAY	O_ALLDELAY
#define	CRTBS		O_CRTBS
#define	PRTERA		O_PRTERA
#define	CRTERA		O_CRTERA
#define	TILDE		O_TILDE
#define	MDMBUF		O_MDMBUF
#define	LITOUT		O_LITOUT
#define	TOSTOP		O_TOSTOP
#define	FLUSHO		O_FLUSHO
#define	NOHANG		O_NOHANG
#define	L001000		O_L001000
#define	CRTKIL		O_CRTKIL
#define	PASS8		O_PASS8
#define	CTLECH		O_CTLECH
#define	PENDIN		O_PENDIN
#define	DECCTQ		O_DECCTQ
#define	NOFLSH		O_NOFLSH

#include <sys/filio.h>

#include <sys/sockio.h>

#endif /*!_sys_ioctl_h*/
