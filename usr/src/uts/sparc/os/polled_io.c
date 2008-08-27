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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This code sets up the callbacks(vx_handlers) so that the firmware may call
 * into the kernel for console input and/or output while in the debugger.
 * The callbacks that execute in debug mode must be careful to not
 * allocate memory, access mutexes, etc. because most kernel services are
 * not available during this mode.
 *
 * This code, and the underlying code that supports the polled input, is very
 * hard to debug.  In order to get the code to execute, polled input must
 * provide input to the debugger.  If anything goes wrong with the code, then
 * it is hard to debug the debugger.  If there are any problems to debug,
 * the following is useful:
 *
 * set the polled_debug variable in /etc/system
 *	set polled_debug=1
 *
 * This variable will register the callbacks but will not throw the switch
 * in the firmware.  The callbacks can be executed by hand from the firmware.
 * Boot the system and drop down to the firmware.
 *
 *	ok " /os-io" select-dev
 *
 * The following will cause the polled_give_input to execute:
 *	ok take
 *
 * The following will cause the polled_take_input to execute:
 *	ok give
 *
 * The following will cause polled_read to execute:
 *	ok read
 */

#include <sys/stropts.h>
#include <v9/sys/prom_isa.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
#include <sys/note.h>
#include <sys/consdev.h>
#include <sys/polled_io.h>
#include <sys/kdi.h>
#ifdef sun4v
#include <sys/ldoms.h>
#endif

/*
 * Internal Functions
 */
static void	polled_give_input(cell_t *cif);
static void	polled_read(cell_t *cif);
static void	polled_take_input(cell_t *cif);

static void	polled_write(cell_t *cif);
static void	polled_io_register(cons_polledio_t *,
			polled_io_console_type_t, int);
static int	polled_io_take_console(polled_io_console_type_t, int);
static int	polled_io_release_console(polled_io_console_type_t, int);

/*
 * State information regarding the input/output device
 */
static polled_device_t	polled_input_device;
static polled_device_t	polled_output_device;
static int polled_vx_handlers_init = 0;

extern void	add_vx_handler(char *name, int flag, void (*func)(cell_t *));

/*
 * This is a useful flag for debugging the entry points.   This flag
 * allows us to exercise the entry points from the firmware without
 * switching the firmware's notion of the input device.
 */
int	polled_debug = 0;

/*
 * This routine is called to initialize polled I/O.  We insert our entry
 * points so that the firmware will call into this code
 * when the switch is thrown in polled_io_take_console().
 */
void
polled_io_init(void)
{

	/*
	 * Only do the initialization once
	 */
	if (polled_vx_handlers_init != 0)
		return;
#ifdef sun4v
	if (!domaining_enabled()) {
#endif
	/*
	 * Add the vx_handlers for the different functions that
	 * need to be accessed from firmware.
	 */
	add_vx_handler("enter-input", 1, polled_give_input);

	add_vx_handler("read", 1, polled_read);

	add_vx_handler("exit-input", 1, polled_take_input);

	add_vx_handler("write", 1, polled_write);
#ifdef sun4v
	}
#endif

	/*
	 * Initialize lock to protect multiple thread access to the
	 * polled_input_device structure.  This does not protect
	 * us from access in debug mode.
	 */
	mutex_init(&polled_input_device.polled_device_lock,
	    NULL, MUTEX_DRIVER, NULL);

	/*
	 * Initialize lock to protect multiple thread access to the
	 * polled_output_device structure.  This does not protect
	 * us from access in debug mode.
	 */
	mutex_init(&polled_output_device.polled_device_lock,
	    NULL, MUTEX_DRIVER, NULL);

	polled_vx_handlers_init = 1;
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
	/*
	 * If the input structure entries aren't filled in, then register this
	 * structure as an input device.
	 */
	if ((polled_io->cons_polledio_getchar != NULL) &&
	    (polled_io->cons_polledio_ischar != NULL)) {

		polled_io_register(polled_io, POLLED_IO_CONSOLE_INPUT, flags);
	}

	/*
	 * If the output structure entries aren't filled in, then register this
	 * structure as an output device.
	 */
	if (polled_io->cons_polledio_putchar != NULL) {

		polled_io_register(polled_io, POLLED_IO_CONSOLE_OUTPUT, flags);
	}

	cons_polledio = polled_io;

	return (DDI_SUCCESS);
}

/*
 * Sends string through the polled output interfaces when the
 * system is panicing.
 */
void
polled_io_cons_write(uchar_t *text, size_t len)
{
	cons_polledio_t *pio = polled_output_device.polled_io;
	int i;

	for (i = 0; i < len; i++)
		pio->cons_polledio_putchar(
		    pio->cons_polledio_argument, text[i]);
}

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


		if (!polled_debug) {
			/*
			 * Tell the generic console framework to
			 * repoint firmware's stdin to this keyboard device.
			 */
			(void) polled_io_take_console(type, 0);
		}

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
		polled_output_device.polled_io = polled_io;

		mutex_exit(&polled_output_device.polled_device_lock);

		if (!polled_debug) {
			/*
			 * Tell the generic console framework to
			 * repoint firmware's stdout to the framebuffer.
			 */
			(void) polled_io_take_console(type, 0);
		}

		break;
	}
}

/*
 * This is the routine that is called to throw the switch from the
 * firmware's ownership of stdout/stdin to the kernel.
 */
/* ARGSUSED */
static int
polled_io_take_console(
polled_io_console_type_t	type,
int				flags
)
{

#ifdef sun4v
	if (domaining_enabled())
		return (DDI_SUCCESS);
#endif

	switch (type) {
	case POLLED_IO_CONSOLE_INPUT:
		/*
		 * Call into firmware to switch to the kernel I/O handling.
		 * We will save the old value of stdin so that we can
		 * restore it if the device is released.
		 */
#ifdef DEBUG_OBP
		/*
		 * This code is useful to trace through
		 * what the prom is doing
		 */
		prom_interpret(
		    "stdin @ swap ! trace-on \" /os-io\" input trace-off",
		    (uintptr_t)&polled_input_device.polled_old_handle,
		    0, 0, 0, 0);
#endif

		prom_interpret(
		    "stdin @ swap ! \" /os-io\" open-dev stdin !",
		    (uintptr_t)&polled_input_device.polled_old_handle,
		    0, 0, 0, 0);

		break;

	case POLLED_IO_CONSOLE_OUTPUT:
		/*
		 * Call into firmware to switch to the kernel I/O handling.
		 * We will save the old value of stdout so that we can
		 * restore it if the device is released.
		 */
		prom_interpret("stdout @ swap ! \" /os-io\" open-dev stdout !",
		    (uintptr_t)&polled_output_device.polled_old_handle,
		    0, 0, 0, 0);

		break;
	}

	return (DDI_SUCCESS);
}

/*
 * This is the routine that the firmware calls to save any state information
 * before using the input device.  This routine, and all of the
 * routines that it calls, are responsible for saving any state
 * information so that it can be restored when debug mode is over.
 *
 * WARNING: This routine runs in debug mode.
 */
static void
polled_give_input(cell_t *cif)
{
	cons_polledio_t		*polled_io;
	uint_t			out_args;

	/*
	 * Calculate the offset of the return arguments
	 */
	out_args = CIF_MIN_SIZE + p1275_cell2uint(cif[CIF_NUMBER_IN_ARGS]);

	/*
	 * There is one argument being passed back to firmware.
	 */
	cif[CIF_NUMBER_OUT_ARGS] = p1275_uint2cell((uint_t)1);
	cif[out_args] = p1275_uint2cell(CIF_SUCCESS);

	/*
	 * We check to see if there is an
	 * input device that has been registered.
	 */
	polled_io = polled_input_device.polled_io;

	if (polled_io == NULL) {
		return;
	}

	/*
	 * Call down to the lower layers to save the state.
	 */
	polled_io->cons_polledio_enter(polled_io->cons_polledio_argument);
}

/*
 * This is the routine that the firmware calls
 * when it wants to read a character.
 * We will call to the lower layers to see if there is any input data
 * available.
 *
 * WARNING: This routine runs in debug mode.
 */
static void
polled_read(cell_t *cif)
{
	uint_t				actual;
	cons_polledio_t			*polled_io;
	uint_t				in_args;
	uint_t				out_args;
	uchar_t				*buffer;
	uint_t				buflen;
	uchar_t				key;

	/*
	 * The number of arguments passed in by the firmware
	 */
	in_args = p1275_cell2uint(cif[CIF_NUMBER_IN_ARGS]);

	/*
	 * Calculate the location of the first out arg.  This location is
	 * CIF_MIN_SIZE plus the in argument locations.
	 */
	out_args = CIF_MIN_SIZE + in_args;

	/*
	 * The firmware should pass in a pointer to a buffer, and the
	 * number of characters it expects or expects to write.
	 * If 2 arguments are not passed in, then return an error.
	 */
	if (in_args != 2) {

		/*
		 * Tell firmware how many arguments we are passing back.
		 */
		cif[CIF_NUMBER_OUT_ARGS] = p1275_uint2cell((uint_t)1);

		/*
		 * Tell the firmware that we cannot give it any characters.
		 */
		cif[out_args] = p1275_uint2cell(CIF_FAILURE);

		return;
	}

	/*
	 * Get the address of where to copy the characters into.
	 */
	buffer = (uchar_t *)(uintptr_t)p1275_cell2uint(cif[CIF_MIN_SIZE+0]);

	/*
	 * Get the length of the buffer that we can copy characters into.
	 */
	buflen = p1275_cell2uint(cif[CIF_MIN_SIZE+1]);

	/*
	 * Make sure there is enough room in the buffer to copy the
	 * characters into.
	 */
	if (buflen == 0) {

		/*
		 * Tell the OBP that we cannot give it any characters.
		 */
		cif[CIF_NUMBER_OUT_ARGS] = p1275_uint2cell((uint_t)1);

		/*
		 * Tell the firmware that we cannot give it any characters.
		 */
		cif[out_args] = p1275_uint2cell(CIF_FAILURE);

		return;
	}

	/*
	 * Pass back whether or not the operation was a success or
	 * failure plus the actual number of bytes in the buffer.
	 * Tell firmware how many arguments we are passing back.
	 */
	cif[CIF_NUMBER_OUT_ARGS] = p1275_uint2cell((uint_t)2);

	/*
	 * Initialize the cif to be "no characters"
	 */
	cif[out_args+0] = p1275_uint2cell(CIF_SUCCESS);
	cif[out_args+1] = p1275_uint2cell(CIF_NO_CHARACTERS);

	/*
	 * We check to see if there is an
	 * input device that has been registered.
	 */
	polled_io = polled_input_device.polled_io;

	if (polled_io == NULL ||
	    polled_io->cons_polledio_ischar == NULL) {

		/*
		 * The cif structure is already set up to return
		 * no characters.
		 */

		return;
	}

	actual = 0;

	/*
	 * Obtain the characters
	 */
	while (polled_io->cons_polledio_ischar(
	    polled_io->cons_polledio_argument) == B_TRUE) {

		/*
		 * Make sure that we don't overrun the buffer.
		 */
		if (actual == buflen) {

			break;
		}

		/*
		 * Call down to the device to copy the input data into the
		 * buffer.
		 */
		key = polled_io->cons_polledio_getchar(
		    polled_io->cons_polledio_argument);

		*(buffer + actual) = key;

		actual++;
	}

	/*
	 * There is a special return code when there is no data.
	 */
	if (actual == 0) {

		/*
		 * The cif structure is already set up to return
		 * no characters.
		 */

		return;
	}

	/*
	 * Tell firmware how many characters we are sending it.
	 */
	cif[out_args+0] = p1275_uint2cell((uint_t)CIF_SUCCESS);
	cif[out_args+1] = p1275_uint2cell((uint_t)actual);
}

/*
 * This is the routine that firmware calls when it is giving up control of the
 * input device.  This routine, and the lower layer routines that it calls,
 * are responsible for restoring the controller state to the state it was
 * in before firmware took control.
 *
 * WARNING: This routine runs in debug mode.
 */
static void
polled_take_input(cell_t *cif)
{
	cons_polledio_t		*polled_io;
	uint_t			out_args;

	/*
	 * Calculate the offset of the return arguments
	 */
	out_args = CIF_MIN_SIZE + p1275_cell2uint(cif[CIF_NUMBER_IN_ARGS]);

	/*
	 * There is one argument being passed back to firmware.
	 */
	cif[CIF_NUMBER_OUT_ARGS] = p1275_uint2cell((uint_t)1);
	cif[out_args] = p1275_uint2cell(CIF_SUCCESS);

	/*
	 * We check the pointer to see if there is an
	 * input device that has been registered.
	 */
	polled_io = polled_input_device.polled_io;

	if (polled_io == NULL) {
		return;
	}

	/*
	 * Call down to the lower layers to save the state.
	 */
	polled_io->cons_polledio_exit(polled_io->cons_polledio_argument);
}

/*
 * This is the routine that the firmware calls when
 * it wants to write a character.
 *
 * WARNING: This routine runs in debug mode.
 */
static void
polled_write(cell_t *cif)
{
	cons_polledio_t			*polled_io;
	uint_t				in_args;
	uint_t				out_args;
	uchar_t				*buffer;
	uint_t				buflen;

	/*
	 * The number of arguments passed in by the firmware
	 */
	in_args = p1275_cell2uint(cif[CIF_NUMBER_IN_ARGS]);

	/*
	 * Calculate the location of the first out arg.  This location is
	 * CIF_MIN_SIZE (name + no. in args + no. out args) plus the
	 * in argument locations.
	 */
	out_args = CIF_MIN_SIZE + in_args;

	/*
	 * The firmware should pass in a pointer to a buffer, and the
	 * number of characters it expects or expects to write.
	 * If 2 arguments are not passed in, then return an error.
	 */
	if (in_args != 2) {

		/*
		 * Tell firmware how many arguments we are passing back.
		 */
		cif[CIF_NUMBER_OUT_ARGS] = p1275_uint2cell((uint_t)1);


		/*
		 * Tell the firmware that we cannot give it any characters.
		 */
		cif[out_args] = p1275_uint2cell(CIF_FAILURE);

		return;
	}

	/*
	 * Get the address of where to copy the characters into.
	 */
	buffer = (uchar_t *)(uintptr_t)p1275_cell2uint(cif[CIF_MIN_SIZE+0]);

	/*
	 * Get the length of the buffer that we can copy characters into.
	 */
	buflen = p1275_cell2uint(cif[CIF_MIN_SIZE+1]);

	/*
	 * Make sure there is enough room in the buffer to copy the
	 * characters into.
	 */
	if (buflen == 0) {

		/*
		 * Tell the OBP that we cannot give it any characters.
		 */
		cif[CIF_NUMBER_OUT_ARGS] = p1275_uint2cell((uint_t)1);

		/*
		 * Tell the firmware that we cannot give it any characters.
		 */
		cif[out_args] = p1275_uint2cell(CIF_FAILURE);

		return;
	}


	/*
	 * Tell the firmware how many arguments we are passing back.
	 */
	cif[CIF_NUMBER_OUT_ARGS] = p1275_uint2cell((uint_t)2);

	/*
	 * Initialize the cif to success
	 */
	cif[out_args+0] = p1275_uint2cell(CIF_SUCCESS);
	cif[out_args+1] = p1275_uint2cell(0);

	/*
	 * We check the pointer to see if there is an
	 * input device that has been registered.
	 */
	polled_io = polled_output_device.polled_io;

	if (polled_io == NULL) {

		/*
		 * The cif is already initialized
		 */
		return;
	}

	polled_io_cons_write(buffer, (size_t)buflen);

	/*
	 * Tell the firmware how many characters we are sending it.
	 */
	cif[out_args+0] = p1275_uint2cell((uint_t)CIF_SUCCESS);
	cif[out_args+1] = p1275_uint2cell((uint_t)buflen);
}
