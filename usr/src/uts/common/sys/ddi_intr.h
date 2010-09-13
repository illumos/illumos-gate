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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_DDI_INTR_H
#define	_SYS_DDI_INTR_H

/*
 * Sun DDI interrupt support definitions
 */

#include <sys/ddipropdefs.h>
#include <sys/rwlock.h>
#include <sys/processor.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Interrupt related definitions.
 */

/*
 * Returned by ddi_add_intr or ddi_add_fastintr in order to signal
 * the the caller requested interrupt number to be added does not
 * exist.
 */
#define	DDI_INTR_NOTFOUND	1	/* interrupt not found error */

/*
 * For use by driver interrupt service routines to return to the
 * system whether an interrupt was for the driver or not.
 */
#define	DDI_INTR_CLAIMED	1	/* returned when driver claims intr */
#define	DDI_INTR_UNCLAIMED	0	/* returned when driver does not */

/* Hardware interrupt types */
#define	DDI_INTR_TYPE_FIXED	0x1
#define	DDI_INTR_TYPE_MSI	0x2
#define	DDI_INTR_TYPE_MSIX	0x4

/* Hardware interrupt priority must be a number within these min/max values */
#define	DDI_INTR_PRI_MIN	1
#define	DDI_INTR_PRI_MAX	12

/* Soft priority must be a number within these min/max values */
#define	DDI_INTR_SOFTPRI_MIN	1
#define	DDI_INTR_SOFTPRI_MAX	9

/* Used in calls to allocate soft interrupt priority. */
#define	DDI_INTR_SOFTPRI_DEFAULT	DDI_INTR_SOFTPRI_MIN

/*
 * Interrupt flags specify certain capabilities for a given
 * interrupt (by type and inum).
 * RO/RW refer to use by ddi_intr_set_cap(9f)
 *
 * DDI_INTR_FLAG_MSI64 is an internal flag not exposed to leaf drivers.
 */
#define	DDI_INTR_FLAG_LEVEL	0x0001	/* (RW) level trigger */
#define	DDI_INTR_FLAG_EDGE	0x0002	/* (RW) edge triggered */
#define	DDI_INTR_FLAG_MASKABLE	0x0010	/* (RO) maskable */
#define	DDI_INTR_FLAG_PENDING	0x0020	/* (RO) int pending supported */
#define	DDI_INTR_FLAG_BLOCK	0x0100	/* (RO) requires block enable */
#define	DDI_INTR_FLAG_MSI64	0x0200	/* (RO) MSI/X supports 64 bit addr */

/*
 * Macro to be used while passing interrupt priority
 * for lock initialization.
 */
#define	DDI_INTR_PRI(pri)	(void *)((uintptr_t)(pri))

/*
 * Typedef for interrupt handles
 */
typedef struct __ddi_intr_handle *ddi_intr_handle_t;
typedef struct __ddi_softint_handle *ddi_softint_handle_t;

/*
 * Definition for behavior flag which is used with ddi_intr_alloc(9f).
 */
#define	DDI_INTR_ALLOC_NORMAL	0	/* Non-strict alloc */
#define	DDI_INTR_ALLOC_STRICT	1	/* Strict allocation */

/*
 * Typedef for driver's interrupt handler
 */
typedef uint_t (ddi_intr_handler_t)(caddr_t arg1, caddr_t arg2);

#endif	/* _KERNEL */
#include <sys/ddi_intr_impl.h>
#ifdef _KERNEL

/*
 * DDI interrupt function prototypes.
 *
 * New DDI interrupt interfaces.
 */

/*
 * ddi_intr_get_supported_types:
 *
 *	Return, as a bit mask, the hardware interrupt types supported by
 *	both the device and by the host in the integer pointed
 *	to be the 'typesp' argument.
 */
int	ddi_intr_get_supported_types(dev_info_t *dip, int *typesp);

/*
 * ddi_intr_get_nintrs:
 *
 * 	Return as an integer in the integer pointed to by the argument
 * 	*nintrsp*, the number of interrupts the device supports for the
 *	given interrupt type.
 */
int	ddi_intr_get_nintrs(dev_info_t *dip, int type, int *nintrsp);

/*
 * ddi_intr_get_navail:
 *
 * 	Return as an integer in the integer pointed to by the argument
 * 	*navailp*, the number of interrupts currently available for the
 *	given interrupt type.
 */
int	ddi_intr_get_navail(dev_info_t *dip, int type, int *navailp);

/*
 * Interrupt resource allocate/free functions
 */
int	ddi_intr_alloc(dev_info_t *dip, ddi_intr_handle_t *h_array,
	    int type, int inum, int count, int *actualp, int behavior);
int	ddi_intr_free(ddi_intr_handle_t h);

/*
 * Interrupt get/set capacity functions
 */
int	ddi_intr_get_cap(ddi_intr_handle_t h, int *flagsp);
int	ddi_intr_set_cap(ddi_intr_handle_t h, int flags);

/*
 * Interrupt priority management functions
 */
uint_t	ddi_intr_get_hilevel_pri(void);
int	ddi_intr_get_pri(ddi_intr_handle_t h, uint_t *prip);
int	ddi_intr_set_pri(ddi_intr_handle_t h, uint_t pri);

/*
 * Interrupt add/duplicate/remove functions
 */
int	ddi_intr_add_handler(ddi_intr_handle_t h,
	    ddi_intr_handler_t inthandler, void *arg1, void *arg2);
int	ddi_intr_dup_handler(ddi_intr_handle_t org, int vector,
	    ddi_intr_handle_t *dup);
int	ddi_intr_remove_handler(ddi_intr_handle_t h);


/*
 * Interrupt enable/disable/block_enable/block_disable functions
 */
int	ddi_intr_enable(ddi_intr_handle_t h);
int	ddi_intr_disable(ddi_intr_handle_t h);
int	ddi_intr_block_enable(ddi_intr_handle_t *h_array, int count);
int	ddi_intr_block_disable(ddi_intr_handle_t *h_array, int count);

/*
 * Interrupt set/clr mask functions
 */
int	ddi_intr_set_mask(ddi_intr_handle_t h);
int	ddi_intr_clr_mask(ddi_intr_handle_t h);

/*
 * Interrupt get pending function
 */
int	ddi_intr_get_pending(ddi_intr_handle_t h, int *pendingp);

/*
 * Interrupt resource management function
 */
int	ddi_intr_set_nreq(dev_info_t *dip, int nreq);

/*
 * Soft interrupt functions
 */
int	ddi_intr_add_softint(dev_info_t *dip, ddi_softint_handle_t *h,
	    int soft_pri, ddi_intr_handler_t handler, void *arg1);
int	ddi_intr_remove_softint(ddi_softint_handle_t h);
int	ddi_intr_trigger_softint(ddi_softint_handle_t h, void *arg2);
int	ddi_intr_get_softint_pri(ddi_softint_handle_t h, uint_t *soft_prip);
int	ddi_intr_set_softint_pri(ddi_softint_handle_t h, uint_t soft_pri);

/*
 * Old DDI interrupt interfaces.
 *
 * The following DDI interrupt interfaces are obsolete.
 * Use the above new DDI interrupt interfaces instead.
 */

/*
 * Return non-zero if the specified interrupt exists and the handler
 * will be restricted to using only certain functions because the
 * interrupt level is not blocked by the scheduler.  I.e., it cannot
 * signal other threads.
 */
int	ddi_intr_hilevel(dev_info_t *dip, uint_t inumber);

int	ddi_get_iblock_cookie(dev_info_t *dip, uint_t inumber,
	    ddi_iblock_cookie_t *iblock_cookiep);

/*
 * ddi_dev_nintrs
 *
 *	If the device has h/w interrupt(s), report
 *	how many of them that there are into resultp.
 *	Return DDI_FAILURE if the device has no interrupts.
 */
int	ddi_dev_nintrs(dev_info_t *dev, int *resultp);

/*
 * ddi_add_intr: Add an interrupt to the system.
 *
 *	The interrupt number "inumber" determines which interrupt will
 *	be added. The interrupt number is associated with interrupt
 *	information provided from self identifying devices or configuration
 *	information for non-self identifying devices. If only one interrupt
 *	is associated with the device then the interrupt number should be 0.
 *
 *	If successful, "*iblock_cookiep" will contain information necessary
 *	for initializing locks (mutex_init, cv_init, etc.) as well as for
 *	possible later removal of the interrupt from the system.
 *
 *	If successful, "*idevice_cookiep" will contain the correct programmable
 *	device interrupt value (see <sys/dditypes.h> in the form of the
 *	type ddi_idevice_cookie_t).
 *
 *	Either cookie pointer may be specified as a NULL pointer
 *	in which case no value will be returned.
 *
 *	The interrupt handler "int_handler" is the address of the routine
 *	to be called upon receipt of an appropriate interrupt. The
 *	interrupt handler should return DDI_INTR_CLAIMED if the
 *	interrupt was claimed, else DDI_INTR_UNCLAIMED. The argument
 *	"int_handler_arg" will be passed to the "int_handler"
 *	upon receipt of an appropriate interrupt.
 *
 *	If successful ddi_add_intr will return DDI_SUCCESS.
 *	If the interrupt information cannot be found it will
 *	return DDI_INTR_NOTFOUND.
 *
 */
int	ddi_add_intr(dev_info_t *dip, uint_t inumber,
	    ddi_iblock_cookie_t *iblock_cookiep,
	    ddi_idevice_cookie_t *idevice_cookiep,
	    uint_t (*int_handler)(caddr_t int_handler_arg),
	    caddr_t int_handler_arg);

/*
 * The following function is for Sun's internal use only at present
 */
int	ddi_add_fastintr(dev_info_t *dip, uint_t inumber,
	    ddi_iblock_cookie_t *iblock_cookiep,
	    ddi_idevice_cookie_t *idevice_cookiep,
	    uint_t (*hi_int_handler)(void));

/*
 * ddi_remove_intr:	Remove interrupt set up by ddi_add_intr.
 *
 *	This routine is intended to be used by drivers that are
 *	preparing to unload themselves "detach" from the system.
 */
void	ddi_remove_intr(dev_info_t *dip, uint_t inum,
	    ddi_iblock_cookie_t iblock_cookie);

/*
 * For use by ddi_add_softintr in order to specify a priority preference.
 */
#define	DDI_SOFTINT_FIXED	0	/* Fixed priority soft interrupt */
#define	DDI_SOFTINT_LOW		8	/* Low priority soft interrupt */
#define	DDI_SOFTINT_MED		128	/* Medium priority soft interrupt */
#define	DDI_SOFTINT_HIGH	256	/* High priority soft interrupt */


int	ddi_get_soft_iblock_cookie(dev_info_t *dip, int preference,
	    ddi_iblock_cookie_t *iblock_cookiep);

/*
 * ddi_add_softintr:	Add a "soft" interrupt to the system.
 *
 *	Like ddi_add_intr, only for system interrupts that you can trigger
 *	yourself. You specify a preference (see above) for the level you
 *	want. You get an identifier back which you can use to either trigger
 *	a soft interrupt or, later, remove it.
 */
int	ddi_add_softintr(dev_info_t *dip, int preference, ddi_softintr_t *idp,
	    ddi_iblock_cookie_t *iblock_cookiep,
	    ddi_idevice_cookie_t *idevice_cookiep,
	    uint_t (*int_handler)(caddr_t int_handler_arg),
	    caddr_t int_handler_arg);

void	ddi_remove_softintr(ddi_softintr_t id);

void	ddi_trigger_softintr(ddi_softintr_t id);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDI_INTR_H */
