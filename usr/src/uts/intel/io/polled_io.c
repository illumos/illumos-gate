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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stropts.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
#include <sys/note.h>
#include <sys/consdev.h>
#include <sys/polled_io.h>

/*
 * consconfig is aware of which devices are the stdin and stout.  The
 * post-attach/pre-detach functions are an extension of consconfig because
 * they know about the dynamic changes to the stdin device.  Neither an
 * individual driver nor the DDI framework knows what device is really the
 * stdin.
 */
/*
 * Issues:
 *	o There are probably race conditions between vx_handler for "read"
 *	  being called by OBP and the update of the polled_input_t
 *	  structure.  We need to be careful how the structure is updated.
 *
 * Solaris/Intel note:  While OBP is not in the picture, there are probably
 * similar issues with kmdb.
 */

#if	defined(MAYBE_SOMETIME)
static void	polled_give_input(void);
static void	polled_take_input(void);
static void	polled_give_output(void);
static void	polled_take_output(void);

static void	polled_io_register(cons_polledio_t *,
			polled_io_console_type_t, int);

static void	polled_io_unregister(polled_io_console_type_t, int);


/*
 * Make the registered device become the console for OBP
 */
static int	polled_io_take_console(polled_io_console_type_t, int);

/*
 * Restore the old console device for OBP.
 */
static int	polled_io_release_console(polled_io_console_type_t, int);
#endif	/* MAYBE_SOMETIME */

static polled_device_t	polled_input_device;
static polled_device_t	polled_output_device;

/*
 * This routine is called to initialize polled I/O.  We insert our entry
 * points so that OBP will call into this code when the switch is thrown
 * in polled_io_take_console().
 */
void
polled_io_init(void)
{
	/*
	 * Initialize lock to protect multiple thread access to the
	 * polled_input_device structure.  This does not protect
	 * us from access in OBP mode.
	 */
	mutex_init(&polled_input_device.polled_device_lock,
		NULL, MUTEX_DRIVER, NULL);

	/*
	 * Initialize lock to protect multiple thread access to the
	 * polled_output_device structure.  This does not protect
	 * us from access in OBP mode.
	 */
	mutex_init(&polled_output_device.polled_device_lock,
		NULL, MUTEX_DRIVER, NULL);
}

/*
 * Register a device for input or output.  The polled_io structure
 * will be filled in with the callbacks that are appropriate for
 * that device.
 */
int
polled_io_register_callbacks(
cons_polledio_t			*polled_io,
int				flags
)
{
#if	defined(MAYBE_SOMETIME)
	/*
	 * If the input structure entries are filled in, then register this
	 * structure as an input device.
	 */
	if ((polled_io->cons_polledio_getchar != NULL) &&
		(polled_io->cons_polledio_ischar != NULL)) {

		polled_io_register(polled_io,
			POLLED_IO_CONSOLE_INPUT, flags);
	}

	/*
	 * If the output structure entries are filled in, then register this
	 * structure as an output device.
	 */
	if (polled_io->cons_polledio_putchar != NULL) {

		polled_io_register(polled_io,
			POLLED_IO_CONSOLE_OUTPUT, flags);
	}
#else
_NOTE(ARGUNUSED(flags))
	cons_polledio = polled_io;
#endif

	return (DDI_SUCCESS);
}

/*
 * Unregister a device for console input/output.
 */
int
polled_io_unregister_callbacks(
cons_polledio_t			*polled_io,
int				flags
)
{
#if	defined(MAYBE_SOMETIME)
	/*
	 * If polled_io is being used for input, then unregister it.
	 */
	if (polled_io == polled_input_device.polled_io) {

		polled_io_unregister(
			POLLED_IO_CONSOLE_INPUT, flags);
	}

	/*
	 * If polled_io is being used for output, then unregister it.
	 */
	if (polled_io == polled_output_device.polled_io) {

		polled_io_unregister(
			POLLED_IO_CONSOLE_OUTPUT, flags);
	}
#else
_NOTE(ARGUNUSED(polled_io,flags))
#endif	/* MAYBE_SOMETIME */

	return (DDI_SUCCESS);
}

/*
 * This routine is called when we are done handling polled io.  We will
 * remove all of our handlers and destroy any memory that we have allocated.
 */
void
polled_io_fini()
{
	/*
	 * Destroy the mutexes, we will not need them anymore.
	 */
	mutex_destroy(&polled_input_device.polled_device_lock);

	mutex_destroy(&polled_output_device.polled_device_lock);
}

#if	defined(MAYBE_SOMETIME)
/*
 * Generic internal routine for registering a polled input or output device.
 */
/* ARGSUSED */
static void
polled_io_register(
cons_polledio_t			*polled_io,
polled_io_console_type_t	type,
int				flags
)
{
	switch (type) {
	case POLLED_IO_CONSOLE_INPUT:
		/*
		 * Grab the device lock, because we are going to access
		 * protected structure entries.  We do this before the
		 * POLLED_IO_CONSOLE_OPEN_INPUT so that we serialize
		 * registration.
		 */
		mutex_enter(&polled_input_device.polled_device_lock);

		/*
		 * Save the polled_io pointers so that we can access
		 * them later.
		 */
		polled_input_device.polled_io = polled_io;

		mutex_exit(&polled_input_device.polled_device_lock);

		/*
		 * Tell the generic console framework to
		 * repoint OBP's stdin to this keyboard device.
		 */
		(void) polled_io_take_console(type, 0);

		break;

	case POLLED_IO_CONSOLE_OUTPUT:
		/*
		 * Grab the device lock, because we are going to access
		 * protected structure entries. We do this before the
		 * POLLED_IO_CONSOLE_OPEN_OUTPUT so that we serialize
		 * registration.
		 */
		mutex_enter(&polled_output_device.polled_device_lock);

		/*
		 * Save the polled_io pointers so that we can access
		 * them later.
		 */
		polled_input_device.polled_io = polled_io;

		mutex_exit(&polled_output_device.polled_device_lock);

		break;
	}
}

/*
 * Generic internal routine for unregistering a polled input or output device.
 */
/* ARGSUSED */
static void
polled_io_unregister(
polled_io_console_type_t	type,
int				flags
)
{
	switch (type) {
	case POLLED_IO_CONSOLE_INPUT:
		/*
		 * Tell the generic console framework to restore OBP's
		 * old stdin pointers.
		 */
		(void) polled_io_release_console(type, 0);

		/*
		 * Grab the device lock, because we are going to access
		 * protected structure entries.
		 */
		mutex_enter(&polled_input_device.polled_device_lock);

		/*
		 * We are closing the device, so get the value for the op
		 * pointer.  We use the polled_io structure to determine if
		 * there is a device registered,  so null the dev_ops
		 * structure.
		 */
		polled_input_device.polled_io = NULL;

		mutex_exit(&polled_input_device.polled_device_lock);

		break;

	case POLLED_IO_CONSOLE_OUTPUT:
		/*
		 * Grab the device lock, because we are going to access
		 * protected structure entries.
		 */
		mutex_enter(&polled_output_device.polled_device_lock);

		/*
		 * We are closing the device, so get the value for the op
		 * pointer.  We use the polled_io structure to determine if
		 * there is a device registered.
		 */
		polled_output_device.polled_io = NULL;

		mutex_exit(&polled_output_device.polled_device_lock);

		break;
	}
}

/*
 * This is the routine that is called to throw the switch from boot
 * ownership of stdout/stdin to the kernel.
 */
/* ARGSUSED */
static int
polled_io_take_console(
polled_io_console_type_t	type,
int				flags
)
{
	switch (type) {
	case POLLED_IO_CONSOLE_INPUT:
		/*
		 * Perhaps this should be where we switch *sysp
		 */
		break;

	case POLLED_IO_CONSOLE_OUTPUT:
		/*
		 * Perhaps this should be where we switch *sysp
		 */
		break;
	}

	return (DDI_SUCCESS);
}

/*
 * This routine gives control of console input/output back to ???.
 *
 * Solaris/Intel has nobody to give it back to.  Hope we don't get here!
 */
/* ARGSUSED */
static int
polled_io_release_console(
polled_io_console_type_t	type,
int				flags
)
{
	cmn_err(CE_WARN,
	    "polled_io_release_console:  nobody to hand console back to");

	return (DDI_SUCCESS);
}

/*
 * This is the routine that kmdb calls to save any state information
 * before using the input device.  This routine, and all of the
 * routines that it calls, are responsible for saving any state
 * information so that it can be restored when polled mode is over.
 */
static void
polled_give_input(void)
{
	cons_polledio_t		*polled_io;

	/*
	 * We check the dev_ops pointer to see if there is an
	 * input device that has been registered.
	 */
	polled_io = polled_input_device.polled_io;

	if (polled_io == NULL || polled_io->cons_polledio_enter == NULL) {
		return;
	}

	/*
	 * Call down to the lower layers to save the state.
	 */
	polled_io->cons_polledio_enter(
		polled_io->cons_polledio_argument);
}

/*
 * This is the routine that kmdb calls when it is giving up control of the
 * input device.  This routine, and the lower layer routines that it calls,
 * are responsible for restoring the controller state to the state it was
 * in before kmdb took control.
 */
static void
polled_take_input(void)
{
	cons_polledio_t		*polled_io;

	/*
	 * We check the dev_ops pointer to see if there is an
	 * input device that has been registered.
	 */
	polled_io = polled_input_device.polled_io;

	if (polled_io == NULL || polled_io->cons_polledio_exit == NULL) {
		return;
	}

	/*
	 * Call down to the lower layers to save the state.
	 */
	polled_io->cons_polledio_exit(
		polled_io->cons_polledio_argument);
}

/*
 * This is the routine that kmdb calls to save any state information
 * before using the output device.  This routine, and all of the
 * routines that it calls, are responsible for saving any state
 * information so that it can be restored when polled mode is over.
 */
static void
polled_give_output()
{
	cons_polledio_t		*polled_io;

	/*
	 * We check the dev_ops pointer to see if there is an
	 * output device that has been registered.
	 */
	polled_io = polled_output_device.polled_io;

	if (polled_io == NULL || polled_io->cons_polledio_enter == NULL) {
		return;
	}

	/*
	 * Call down to the lower layers to save the state.
	 */
	polled_io->cons_polledio_enter(
		polled_io->cons_polledio_argument);
}

/*
 * This is the routine that kmdb calls when it is giving up control of the
 * output device.  This routine, and the lower layer routines that it calls,
 * are responsible for restoring the controller state to the state it was
 * in before kmdb took control.
 */
static void
polled_take_output(void)
{
	cons_polledio_t		*polled_io;

	/*
	 * We check the dev_ops pointer to see if there is an
	 * output device that has been registered.
	 */
	polled_io = polled_output_device.polled_io;

	if (polled_io == NULL || polled_io->cons_polledio_exit == NULL) {
		return;
	}

	/*
	 * Call down to the lower layers to save the state.
	 */
	polled_io->cons_polledio_exit(
		polled_io->cons_polledio_argument);
}
#endif	/* MAYBE_SOMETIME */
