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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _SYS_IOCCOM_H
#define	_SYS_IOCCOM_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Ioctl's have the command encoded in the lower word,
 * and the size of any in or out parameters in the upper
 * word.  The high 2 bits of the upper word are used
 * to encode the in/out status of the parameter; for now
 * we restrict parameters to at most 255 bytes.
 */
#define	IOCPARM_MASK	0xff		/* parameters must be < 256 bytes */
#define	IOC_VOID	0x20000000	/* no parameters */
#define	IOC_OUT		0x40000000	/* copy out parameters */
#define	IOC_IN		0x80000000	/* copy in parameters */
#define	IOC_INOUT	(IOC_IN|IOC_OUT)

/*
 * The 0x20000000 is so we can distinguish new ioctl's from old.
 */
#define	_IO(x, y)	(IOC_VOID|(x<<8)|y)
#define	_IOR(x, y, t) 							\
	    ((int)((uint32_t)						\
	    (IOC_OUT|(((sizeof (t))&IOCPARM_MASK)<<16)|(x<<8)|y)))

#define	_IORN(x, y, t)	((int)((uint32_t)(IOC_OUT|(((t)&IOCPARM_MASK)<<16)| \
	    (x<<8)|y)))

#define	_IOW(x, y, t)							\
	    ((int)((uint32_t)(IOC_IN|(((sizeof (t))&IOCPARM_MASK)<<16)|	\
	    (x<<8)|y)))

#define	_IOWN(x, y, t)	((int32_t)(uint32_t)(IOC_IN|(((t)&IOCPARM_MASK)<<16)| \
	    (x<<8)|y))

#define	_IOWR(x, y, t)							\
	    ((int)((uint32_t)(IOC_INOUT|(((sizeof (t))&IOCPARM_MASK)<<16)| \
	    (x<<8)|y)))

#define	_IOWRN(x, y, t)							\
	    ((int)((uint32_t)(IOC_INOUT|(((t)&IOCPARM_MASK)<<16)| \
	    (x<<8)|y)))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IOCCOM_H */
