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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/kobj.h>
#include <sys/membar.h>
#include <sys/dmv.h>
#include <sys/prom_debug.h>
#include <sys/machsystm.h>
#include <vm/vm_dep.h>

/*
 * Implementation of databearing mondo vector handler registration routines.
 * See PSARC 1998/222 for more details.
 */

/*
 * The dmv_interface_*_version variables are provided to protect a
 * driver against changes in the databearing mondo interfaces.
 *
 * The major version is incremented when an incompatible change
 * is made to an interface; for instance, a routine which used to take
 * 3 parameters now takes 4, or a routine which used have the semantics
 * "do X" now has the semantics "do Y".  Before calling any of the
 * databearing mondo routines, a driver must check the major version
 * it was compiled with (i.e., the constant DMV_INTERFACE_MAJOR_VERSION)
 * against the contents of dmv_interface_major_version.  If the two
 * are different, the driver must refuse to operate.
 *
 * The minor version is incremented when an upward-compatible change
 * is made to an interface; for instance, a routine now supports a new
 * flag bit (in an existing flags argument).  A client can use the
 * minor version to see whether a feature it depends on is available
 * in its environment; in order to enable this, the documentation
 * for new features should note which major and minor version the
 * feature first appears in.
 */

int dmv_interface_major_version = DMV_INTERFACE_MAJOR_VERSION;
int dmv_interface_minor_version = DMV_INTERFACE_MINOR_VERSION;

/*
 * These are where the number of hardware and software DMV inums are kept.
 * If they're zero, we use the platform's default values.  (These are not
 * patchable in /etc/system, since the dispatch table is allocated before
 * /etc/system is loaded; however, you could patch them by adb'ing unix.)
 */

uint_t dmv_hwint = 0;
uint_t dmv_swint = 0;
uint_t dmv_totalints = 0;

struct dmv_disp *dmv_dispatch_table = (struct dmv_disp *)0;

/*
 * dmv_disp_lock protects the dispatch table from being modified by two
 * threads concurrently.  It is not used to protect the table from being
 * modified while being used by the actual interrupt dispatch code; see
 * comments at the end of dmv.h for the rationale.
 */

kmutex_t dmv_disp_lock;

/*
 * dmv_add_intr is called to add a databearing mondo interrupt handler
 * for a real device to the system.  Only one handler may be registered
 * for a dmv_inum at any one time.
 *
 * Note that if a processor receives a databearing mondo interrupt
 * for which a handler has not been registered, the behavior is
 * undefined.  (Current practice for normal mondos which are unhandled
 * depends on whether DEBUG is on; a DEBUG kernel prints an error
 * and breaks to OBP, while a non-DEBUG kernel simply panics.  This
 * model will likely be followed for databearing mondos.)
 *
 * Parameters:
 *	dmv_inum	interrupt number for the device.
 *
 *	routine		pointer to the device's vectored interrupt
 *			handler.  This routine is subject to the
 *			constraints outlined below in "Handler
 *			Characteristics and Environment".
 *
 *	arg		argument which will be passed to the device's
 *			handler.
 *
 * Return value:	0 if the handler was added successfully, -1 if
 *			handler was already registered for the given
 *			dmv_inum.
 *
 * Handler Characteristics and Environment
 *
 *   Handler Entry:
 *
 *	On entry to the handler, the %g registers are set as follows:
 *
 *	%g1	The argument (arg) passed to dmv_add_intr().
 *	%g2	Word 0 of the incoming mondo vector.
 *
 *
 *   Handler Constraints:
 *
 *	While executing, the handler must obey the following rules:
 *
 *	1. The handler is limited to the use of registers %g1 through
 *	   %g7.
 *
 *	2. The handler may not modify %cwp (i.e., may not execute a
 *	   SAVE or RESTORE instruction).
 *
 *	3. The handler may not read or write the stack.
 *
 *	4. The handler may not call any other DDI or kernel routines.
 *
 *	5. The handler may not call any other routines inside the
 *	   handler's own driver, since this would modify %o7; however,
 *	   it is permissible to jump to a routine within the handler's
 *	   driver.
 *
 *	6. The handler may read the Incoming Interrupt Vector Data
 *	   registers, and the Interrupt Vector Receive register, but
 *	   must not modify these registers.  (Note: symbols for the
 *	   ASIs and addresses of these registers are in <sys/spitasi.h>
 *	   and <sys/intreg.h>.)
 *
 *	7. The handler may read or write driver-private data
 *	   structures; in order to protect against simultaneous
 *	   modification by other driver routines, nonblocking data
 *	   sharing algorithms must be used.  (For instance,
 *	   compare-and-swap could be used to update counters or add
 *	   entries to linked lists; producer-consumer queues are
 *	   another possibility.)
 *
 *	8. The handler should neither read nor write any other
 *	   processor register nor kernel data item which is not
 *	   explicitly mentioned in this list.  [Yes, this is rather
 *	   strict; the intent here is that as handler implementations
 *	   are done, and more experience is gained, additional items
 *	   may be permitted.]
 *
 *
 *   Handler Exit:
 *
 *	When the handler's processing is complete, the handler must
 *	exit by jumping to the label dmv_finish_intr.  At this time,
 *	the handler may optionally request the execution of a soft
 *	interrupt routine in order to do further processing at normal
 *	interrupt level.  It is strongly advised that drivers do
 *	minimal processing in their databearing mondo handlers;
 *	whenever possible, tasks should be postponed to a later
 *	soft interrupt routine.  (This is analogous to the DDI
 *	"high-level interrupt" concept, although a databearing mondo
 *	handler's environment is even more restrictive than that of
 *	a high-level interrupt routine.)
 *
 *	Soft interrupt routines should be registered by calling
 *	add_softintr(), which will return an interrupt number.  This
 *	interrupt number should be saved in a driver-private data
 *	structure for later use.
 *
 *	The contents of %g1 on entry to dmv_finish_intr determine
 *	whether a soft interrupt routine will be called, as follows:
 *
 *		If %g1 is less than zero, no interrupt will be queued.
 *
 *		Otherwise, %g1 is assumed to be an interrupt number
 *		obtained from add_softintr.  This interrupt routine
 *		will be executed in the normal way at the requested
 *		priority.  (Note that this routine may or may not
 *		execute on the same CPU as the current handler.)
 */

int
dmv_add_intr(int dmv_inum, void (*routine)(), void *arg)
{
	if (dmv_inum < 0 || dmv_inum >= dmv_hwint)
		return (-1);

	mutex_enter(&dmv_disp_lock);

	if (dmv_dispatch_table[dmv_inum].dmv_func != 0) {
		mutex_exit(&dmv_disp_lock);
		return (-1);
	}

	dmv_dispatch_table[dmv_inum].dmv_arg = arg;

	membar_sync();

	dmv_dispatch_table[dmv_inum].dmv_func = routine;

	mutex_exit(&dmv_disp_lock);
	return (0);
}

/*
 * dmv_add_softintr is called to add a databearing mondo interrupt
 * handler for a pseudo-device to the system.
 *
 * Parameters:
 *	routine		pointer to the device's vectored interrupt
 *			handler.  This routine is subject to the
 *			constraints outlined above in "Handler
 *			Characteristics and Environment".
 *
 *	arg		argument which will be passed to the device's
 *			handler.
 *
 * Return value:	dmv_inum allocated if one was available, -1 if
 *			all soft dmv_inums are already allocated
 */

int
dmv_add_softintr(void (*routine)(void), void *arg)
{
	int i;

	mutex_enter(&dmv_disp_lock);

	for (i = dmv_hwint; i < dmv_totalints; i++) {
		if (dmv_dispatch_table[i].dmv_func == 0) {

			dmv_dispatch_table[i].dmv_arg = arg;

			membar_sync();

			dmv_dispatch_table[i].dmv_func = routine;

			mutex_exit(&dmv_disp_lock);
			return (i);
		}
	}

	mutex_exit(&dmv_disp_lock);
	return (-1);
}

/*
 * dmv_rem_intr is called to remove a databearing interrupt handler
 * from the system.
 *
 * Parameters:
 *	dmv_inum	interrupt number for the device.
 *
 * Return value:	0 if the handler was removed successfully, -1
 *			if no handler was registered for the given
 *			dmv_inum.
 */

int
dmv_rem_intr(int dmv_inum)
{
	if (dmv_inum < 0 || dmv_inum >= (dmv_totalints))
		return (-1);

	mutex_enter(&dmv_disp_lock);

	if (dmv_dispatch_table[dmv_inum].dmv_func == 0) {
		mutex_exit(&dmv_disp_lock);
		return (-1);
	}

	dmv_dispatch_table[dmv_inum].dmv_func = 0;

	mutex_exit(&dmv_disp_lock);
	return (0);
}


/*
 * Allocate the dmv dispatch table from nucleus data memory.
 */
int
ndata_alloc_dmv(struct memlist *ndata)
{
	size_t alloc_sz;

	uint_t plat_hwint = 0;
	uint_t plat_swint = 0;

	void (*plat_dmv_params)(uint_t *, uint_t *);


	/*
	 * Get platform default values, if they exist
	 */

	plat_dmv_params = (void (*)(uint_t *, uint_t *))
	    kobj_getsymvalue("plat_dmv_params", 0);

	if (plat_dmv_params)
		(*plat_dmv_params)(&plat_hwint, &plat_swint);

	/*
	 * Set sizes to platform defaults if user hasn't set them
	 */

	if (dmv_hwint == 0)
		dmv_hwint = plat_hwint;

	if (dmv_swint == 0)
		dmv_swint = plat_swint;

	/*
	 * Allocate table if we need it
	 */
	dmv_totalints = dmv_hwint + dmv_swint;

	if (dmv_totalints != 0) {

		alloc_sz = sizeof (struct dmv_disp) * (dmv_totalints + 1);

		dmv_dispatch_table = ndata_alloc(ndata, alloc_sz,
		    sizeof (struct dmv_disp));

		if (dmv_dispatch_table == NULL)
			return (-1);

		bzero(dmv_dispatch_table, alloc_sz);
		/* use uintptr_t to suppress the gcc warning */
		PRM_DEBUG((uintptr_t)dmv_dispatch_table);
	}

	return (0);
}
