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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _SYS_CONF_H
#define	_SYS_CONF_H


#include <sys/feature_tests.h>

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#include <sys/t_lock.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	FMNAMESZ	8 		/* used by struct fmodsw */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)

#ifdef _KERNEL

/*
 * XXX  Given that drivers need to include this file,
 *	<sys/systm.h> probably shouldn't be here, as
 *	it legitimizes (aka provides prototypes for)
 *	all sorts of functions that aren't in the DKI/SunDDI
 */
#include <sys/systm.h>
#include <sys/devops.h>
#include <sys/model.h>
#include <sys/types.h>
#include <sys/buf.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <vm/as.h>

typedef struct fmodsw {
	char			f_name[FMNAMESZ + 1];
	struct streamtab	*f_str;
	int			f_flag;
} fmodsw_t;

extern struct dev_ops **devopsp;
extern int devcnt;

/*
 * Return streams information for the driver specified by major number or
 *   NULL if device cb_ops structure is not present.
 */
#define	STREAMSTAB(maj)	(devopsp[(maj)] == NULL ? NULL : \
	(devopsp[(maj)]->devo_cb_ops == NULL ? \
	NULL : \
	devopsp[(maj)]->devo_cb_ops->cb_str))
#define	CBFLAG(maj)	(devopsp[(maj)]->devo_cb_ops->cb_flag)

extern int devi_identify(dev_info_t *);
extern int devi_probe(dev_info_t *);
extern int devi_attach(dev_info_t *, ddi_attach_cmd_t);
extern int devi_detach(dev_info_t *, ddi_detach_cmd_t);
extern int devi_reset(dev_info_t *, ddi_reset_cmd_t);
extern int devi_quiesce(dev_info_t *);

/*
 * The following [cb]dev_* functions are not part of the DDI, use
 * <sys/sunldi.h> defined interfaces instead.
 */
extern int dev_open(dev_t *, int, int, cred_t *);
extern int dev_lopen(dev_t *, int, int, cred_t *);
extern int dev_close(dev_t, int, int, cred_t *);
extern int dev_lclose(dev_t, int, int, cred_t *);

extern int dev_to_instance(dev_t);

extern int bdev_strategy(struct buf *);
extern int bdev_print(dev_t, caddr_t);
extern int bdev_dump(dev_t, caddr_t, daddr_t, int);
extern int bdev_size(dev_t);
extern uint64_t bdev_Size(dev_t);

extern int cdev_read(dev_t, struct uio *, cred_t *);
extern int cdev_write(dev_t, struct uio *, cred_t *);
extern int cdev_size(dev_t);
extern uint64_t cdev_Size(dev_t);
extern int cdev_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
extern int cdev_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off,
	size_t len, size_t *maplen, uint_t model);
extern int cdev_mmap(int (*)(dev_t, off_t, int),
    dev_t, off_t, int);
extern int cdev_segmap(dev_t, off_t, struct as *, caddr_t *,
    off_t, uint_t, uint_t, uint_t, cred_t *);
extern int cdev_poll(dev_t, short, int, short *, struct pollhead **);
extern int cdev_prop_op(dev_t, dev_info_t *, ddi_prop_op_t,
    int, char *, caddr_t, int *);

#endif /* _KERNEL */


/*
 * Device flags.
 *
 * Bit 0 to bit 15 are reserved for kernel.
 * Bit 16 to bit 31 are reserved for different machines.
 */

#define	D_NEW		0x00	/* new-style driver */
#define	_D_OLD		0x01	/* old-style driver (obsolete) */
#define	D_TAPE		0x08	/* Magtape device (no bdwrite when cooked) */

/*
 * MT-safety level (in DDI portion of flags).
 *
 * All drivers must be MT-safe, and must advertise this by specifying D_MP.
 *
 * The remainder of the flags apply only to STREAMS modules and drivers.
 *
 * A STREAMS driver or module can optionally select inner and outer perimeters.
 * The four mutually exclusive options that define the presence and scope
 * of the inner perimeter are:
 *	D_MTPERMOD - per module single threaded.
 *	D_MTQPAIR - per queue-pair single threaded.
 *	D_MTPERQ - per queue instance single threaded.
 *	(none of the above) - no inner perimeter restricting concurrency
 *
 * The presence	of the outer perimeter is declared with:
 *	D_MTOUTPERIM - a per-module outer perimeter. Can be combined with
 *		D_MTPERQ, D_MTQPAIR, and D_MP.
 *
 * The concurrency when entering the different STREAMS entry points can be
 * modified with:
 *	D_MTPUTSHARED - modifier for D_MTPERQ, D_MTQPAIR, and D_MTPERMOD
 *		specifying that the put procedures should not be
 *		single-threaded at the inner perimeter.
 *	_D_MTOCSHARED - EXPERIMENTAL - will be removed in a future release.
 *		Modifier for D_MTPERQ, D_MTQPAIR, and D_MTPERMOD
 *		specifying that the open and close procedures should not be
 *		single-threaded at the inner perimeter.
 *	_D_MTCBSHARED - EXPERIMENTAL - will be removed in a future release.
 *		Modifier for D_MTPERQ, D_MTQPAIR, and D_MTPERMOD
 *		specifying that the callback i.e qtimeout() procedures should
 *		not be single-threaded at the inner perimeter.
 *	_D_MTSVCSHARED - EXPERIMENTAL - will be removed in a future release.
 *		Modifier for D_MTPERMOD only. Specifies that the service
 *		procedure should not be single-threaded at the inner perimeter.
 *		However only a single instance of the service thread can run on
 *		any given queue.
 *	D_MTOCEXCL - modifier for D_MTOUTPERIM specifying that the open and
 *		close procedures should be single-threaded at the outer
 *		perimeter.
 */
#define	D_MTSAFE	0x0020	/* multi-threaded module or driver */
#define	_D_QNEXTLESS	0x0040	/* Unused, retained for source compatibility */
#define	_D_MTOCSHARED	0x0080	/* modify: open/close procedures are hot */
/* 0x100 - see below */
/* 0x200 - see below */
/* 0x400 - see below */
#define	D_MTOCEXCL	0x0800	/* modify: open/close are exclusive at outer */
#define	D_MTPUTSHARED	0x1000	/* modify: put procedures are hot */
#define	D_MTPERQ	0x2000	/* per queue instance single-threaded */
#define	D_MTQPAIR	0x4000	/* per queue-pair instance single-threaded */
#define	D_MTPERMOD	0x6000	/* per module single-threaded */
#define	D_MTOUTPERIM	0x8000	/* r/w outer perimeter around whole modules */
#define	_D_MTCBSHARED	0x10000	/* modify : callback procedures are hot */
#define	_D_MTSVCSHARED	0x20000	/* modify : service procedures are hot */

/* The inner perimeter scope bits */
#define	D_MTINNER_MASK	(D_MP|D_MTPERQ|D_MTQPAIR|D_MTPERMOD)

/* Inner perimeter modification bits */
#define	D_MTINNER_MOD	(D_MTPUTSHARED|_D_MTOCSHARED|_D_MTCBSHARED| \
    _D_MTSVCSHARED)

/* Outer perimeter modification bits */
#define	D_MTOUTER_MOD	(D_MTOCEXCL)

/* All the MT flags */
#define	D_MTSAFETY_MASK (D_MTINNER_MASK|D_MTOUTPERIM|D_MTPUTSHARED|\
			D_MTINNER_MOD|D_MTOUTER_MOD)

#define	D_MP		D_MTSAFE /* ddi/dki approved flag */

#define	D_64BIT		0x200	/* Driver supports 64-bit offsets, blk nos. */

#define	D_SYNCSTR	0x400	/* Module or driver has Synchronous STREAMS */
				/* extended qinit structure */

#define	D_DEVMAP	0x100	/* Use devmap framework to mmap device */

#define	D_HOTPLUG	0x4	/* Driver is hotplug capable */

#define	D_U64BIT	0x40000	/* Driver supports unsigned 64-bit uio offset */

#define	_D_DIRECT	0x80000	/* Private flag for transport modules */

#define	D_OPEN_RETURNS_EINTR	0x100000 /* EINTR expected from open(9E) */

#define	_D_SINGLE_INSTANCE	0x200000 /* Module may only be pushed once */

#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONF_H */
