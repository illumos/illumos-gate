/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	__sys_ioccom_h
#define	__sys_ioccom_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Ioctl's have the command encoded in the lower word,
 * and the size of any in or out parameters in the upper
 * word.  The high 2 bits of the upper word are used
 * to encode the in/out status of the parameter; for now
 * we restrict parameters to at most 255 bytes.
 */
#define	_IOCPARM_MASK	0xff		/* parameters must be < 256 bytes */
#define	_IOC_VOID	0x20000000	/* no parameters */
#define	_IOC_OUT	0x40000000	/* copy out parameters */
#define	_IOC_IN		0x80000000	/* copy in parameters */
#define	_IOC_INOUT	(_IOC_IN|_IOC_OUT)

/* the 0x20000000 is so we can distinguish new ioctl's from old */
#define	_IO(x,y)	(_IOC_VOID|(x<<8)|y)
#define	_IOR(x,y,t)	(_IOC_OUT|((sizeof(t)&_IOCPARM_MASK)<<16)|(x<<8)|y)
#define	_IORN(x,y,t)	(_IOC_OUT|(((t)&_IOCPARM_MASK)<<16)|(x<<8)|y)
#define	_IOW(x,y,t)	(_IOC_IN|((sizeof(t)&_IOCPARM_MASK)<<16)|(x<<8)|y)
#define	_IOWN(x,y,t)	(_IOC_IN|(((t)&_IOCPARM_MASK)<<16)|(x<<8)|y)
/* this should be _IORW, but stdio got there first */
#define	_IOWR(x,y,t)	(_IOC_INOUT|((sizeof(t)&_IOCPARM_MASK)<<16)|(x<<8)|y)
#define	_IOWRN(x,y,t)	(_IOC_INOUT|(((t)&_IOCPARM_MASK)<<16)|(x<<8)|y)

/*
 * Registry of ioctl characters, culled from system sources
 *
 * char	file where defined		notes
 * ----	------------------		-----
 *   F	sun/fbio.h
 *   G	sun/gpio.h
 *   H	vaxif/if_hy.h
 *   M	sundev/mcpcmd.h			*overlap*
 *   M	sys/modem.h			*overlap*
 *   S	sys/stropts.h
 *   T	sys/termio.h			-no overlap-
 *   T	sys/termios.h			-no overlap-
 *   V	sundev/mdreg.h
 *   a	vaxuba/adreg.h
 *   d	sun/dkio.h			-no overlap with sys/des.h-
 *   d	sys/des.h			(possible overlap)
 *   d	vax/dkio.h			(possible overlap)
 *   d	vaxuba/rxreg.h			(possible overlap)
 *   f	sys/filio.h
 *   g	sunwindow/win_ioctl.h		-no overlap-
 *   g	sunwindowdev/winioctl.c		!no manifest constant! -no overlap-
 *   h	sundev/hrc_common.h
 *   i	sys/sockio.h			*overlap*
 *   i	vaxuba/ikreg.h			*overlap*
 *   k	sundev/kbio.h
 *   m	sundev/msio.h			(possible overlap)
 *   m	sundev/msreg.h			(possible overlap)
 *   m	sys/mtio.h			(possible overlap)
 *   n	sun/ndio.h
 *   p	net/nit_buf.h			(possible overlap)
 *   p	net/nit_if.h			(possible overlap)
 *   p	net/nit_pf.h			(possible overlap)
 *   p	sundev/fpareg.h			(possible overlap)
 *   p	sys/sockio.h			(possible overlap)
 *   p	vaxuba/psreg.h			(possible overlap)
 *   q	sun/sqz.h
 *   r	sys/sockio.h
 *   s	sys/sockio.h
 *   t	sys/ttold.h			(possible overlap)
 *   t	sys/ttycom.h			(possible overlap)
 *   v	sundev/vuid_event.h		*overlap*
 *   v	sys/vcmd.h			*overlap*
 *
 * End of Registry
 */

#endif /* !__sys_ioccom_h */
