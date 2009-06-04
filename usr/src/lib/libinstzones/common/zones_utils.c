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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



/*
 * Module:	zones.c
 * Group:	libinstzones
 * Description:	Provide "zones" interface for install consolidation code
 *
 * Public Methods:
 *
 *  _z_close_file_descriptors - close a file descriptor "a_fd" not in the
 *	list "a_fds"
 *  _z_echo - Output an interactive message if interaction is enabled
 *  _z_echoDebug - Output a debugging message if debugging is enabled
 *  _z_get_inherited_dirs - return array of directories inherited by
 *	specified zone
 *  _z_is_directory - determine if specified path exists and is a directory
 *  _z_program_error - Output an error message to the appropriate destinations
 *  _z_pluginCatchSigint - SIGINT/SIGHUP interrupt handler
 *  _z_running_in_global_zone - Determine if this process is running in the
 *	global zone
 *  _z_zones_are_implemented - Determine if zones are supported by the
 *	current system
 *  _z_brands_are_implemented - determine if branded zones are implemented on
 *		this system
 */

/*
 * System includes
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stropts.h>
#include <libintl.h>
#include <locale.h>
#include <assert.h>
#include <dlfcn.h>

/*
 * local includes
 */

#include "instzones_lib.h"
#include "zones_strings.h"

/*
 * Private structures
 */

/*
 * these dynamic libraries are required in order to use the branded zones
 * functionality.  If these libraries are not available at runtime,
 * then the zones we find are assumed to be native zones.
 */

#define	BRAND1_LIBRARY	"libbrand.so.1"
#define	BRAND_LIBRARY	"libbrand.so"

/*
 * Library Function Prototypes
 */

/*
 * Local Function Prototypes
 */

static void	error_and_exit(int error_num);

static void 	(*fatal_err_func)() = &error_and_exit;

/* ----------------------- private functions -------------------------- */
/*
 * error_and_exit()
 *	Abort routine. An exit code of '2' is used by all applications
 *	to indicate a non-recoverable fatal error.
 * Parameters:
 *	error_num - error index number:
 *			ERR_MALLOC_FAIL
 * Return:
 *	none
 * Status:
 *	private
 */
static void
error_and_exit(int error_num)
{
	if (error_num == ERR_MALLOC_FAIL)
		(void) fprintf(stderr, "Allocation of memory failed\n");
	else
		(void) fprintf(stderr, "ERROR: code %d\n", error_num);
	exit(2);
}

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	_z_close_file_descriptors
 * Description:	close a file descriptor "a_fd" not in the list "a_fds"
 *		This function is called from the fdwalk() library function.
 *		If the file descriptor passed in is NOT in the list passed in,
 *		the file is closed.
 * Arguments:	a_fds - [RO, *RO] - (void *)
 *			Pointer to list of file descriptors to keep open
 *		a_fd - [RO, *RO] - (int)
 *			File descriptor to check
 * Returns:	int
 *			0 - success
 */

int
_z_close_file_descriptors(void *a_fds, int a_fd)
{
	int	*fds;
	int	i;

	/* do not close standard input, output, or error file descriptors */

	if (a_fd == STDIN_FILENO || a_fd == STDOUT_FILENO ||
	    a_fd == STDERR_FILENO) {
		return (0);
	}

	/* if no file descriptor retention list, close this file */

	if (a_fds == (void *)NULL) {
		(void) close(a_fd);
		return (0);
	}

	/*
	 * retention list provided, skip this descriptor if its in the list
	 */

	fds = (int *)a_fds;

	for (i = 0; fds[i] != -1; i++) {
		if (fds[i] == a_fd) {
			return (0);
		}
	}

	/* this descriptor not in retention list - close this file */

	(void) close(a_fd);

	return (0);
}

/*
 * Name:	_z_echo
 * Synopsis:	Output an interactive message if interaction is enabled
 * Description:	Main method for outputting an interactive message; call to
 *		output interactive message if interation has not been disabled
 *		by a previous call to echoSetFlag(0).
 * Arguments:	format - [RO, RO*] (char *)
 *			printf-style format for debugging message to be output
 *		VARG_LIST - [RO] (?)
 *			arguments as appropriate to 'format' specified
 * Returns:	void
 */

/*PRINTFLIKE1*/
void
_z_echo(char *a_format, ...)
{
	va_list ap;
	char	message[MAX_MESSAGE_SIZE];

	/* entry assertions */

	assert(a_format != NULL);

	/* return if no progerr function registered */

	if (_z_global_data._z_echo == NULL) {
		return;
	}

	/* capture message */

	va_start(ap, a_format);
	(void) vsnprintf(message, sizeof (message), a_format, ap);
	va_end(ap);

	/* pass message to registered function */

	(_z_global_data._z_echo)("%s", message);
}

/*
 * Name:	_z_echoDebug
 * Synopsis:	Output a debugging message if debugging is enabled
 * Description:	Main method for outputting a debugging message; call to
 *		output debugging message if debugging has been enabled
 *		by a previous call to _z_echoDebugSetFlag(1).
 * Arguments:	format - [RO, RO*] (char *)
 *			printf-style format for debugging message to be output
 *		VARG_LIST - [RO] (?)
 *			arguments as appropriate to 'format' specified
 * Returns:	void
 * NOTE:	format of message will be:
 *			# [ aaa bbb ccc ] message
 *		where:	aaa - process i.d.
 *			bbb - zone i.d.
 *			ccc - name of program
 * 		for example:
 *			# [ 25685   0 pkgadd     ] unable to get package list
 */

/*PRINTFLIKE1*/
void
_z_echoDebug(char *a_format, ...)
{
	va_list ap;
	char	message[MAX_MESSAGE_SIZE];

	/* entry assertions */

	assert(a_format != NULL);

	/* return if no progerr function registered */

	if (_z_global_data._z_echo_debug == NULL) {
		return;
	}

	/* capture message */

	va_start(ap, a_format);
	(void) vsnprintf(message, sizeof (message), a_format, ap);
	va_end(ap);

	/* pass message to registered function */

	(_z_global_data._z_echo_debug)("%s", message);
}

/*
 * Name:	_z_get_inherited_dirs
 * Description:	return array of directories inherited by specified zone
 * Arguments:	a_zoneName - [RO, *RO] - (char *)
 *			Pointer to string representing the name of the zone
 *			to return the list of inherited directories for
 * Returns:	char **
 *			!= NULL - list of inherited directories, terminated
 *					by a NULL pointer
 *			== NULL - error - unable to retrieve list
 */

char **
_z_get_inherited_dirs(char *a_zoneName)
{
	char			**dirs = NULL;
	int			err;
	int			numIpdents = 0;
	struct zone_fstab	lookup;
	zone_dochandle_t	handle = NULL;

	/* entry assertions */

	assert(a_zoneName != NULL);
	assert(*a_zoneName != '\0');

	/* initialize the zone configuration interface handle */

	handle = zonecfg_init_handle();
	if (handle == NULL) {
		_z_program_error(ERR_PKGDIR_NOHANDLE,
		    zonecfg_strerror(Z_NOMEM));
		return (NULL);
	}

	/* get handle to configuration information for the specified zone */

	err = zonecfg_get_handle(a_zoneName, handle);
	if (err != Z_OK) {
		/* If there was no zone before, that's OK */
		if (err != Z_NO_ZONE) {
			_z_program_error(ERR_PKGDIR_GETHANDLE,
			    zonecfg_strerror(err));
			zonecfg_fini_handle(handle);
			return (NULL);
		}
	}
	assert(handle != NULL);

	/* get handle to non-global zone ipd enumerator */

	err = zonecfg_setipdent(handle);
	if (err != Z_OK) {
		_z_program_error(ERR_PKGDIR_SETIPDENT, zonecfg_strerror(err));
		zonecfg_fini_handle(handle);
		return (NULL);
	}

	/* enumerate the non-global zone ipd's */

	while (zonecfg_getipdent(handle, &lookup) == Z_OK) {
		dirs = _z_realloc(dirs, sizeof (char **)*(numIpdents+1));
		dirs[numIpdents++] = strdup(lookup.zone_fs_dir);
	}

	if (dirs != NULL) {
		dirs = _z_realloc(dirs, sizeof (char **)*(numIpdents+1));
		dirs[numIpdents] = NULL;
	}

	/* toss non-global zone ipd enumerator handle */

	(void) zonecfg_endipdent(handle);

	return (dirs);
}

/*
 * Name:	_z_is_directory
 * Description:	determine if specified path exists and is a directory
 * Arguments:	path - pointer to string representing the path to verify
 * returns: 0 - directory exists
 *	    1 - directory does not exist or is not a directory
 * NOTE:	errno is set appropriately
 */

int
_z_is_directory(char *path)
{
	struct stat statbuf;

	/* entry assertions */

	assert(path != NULL);
	assert(*path != '\0');

	/* return error if path does not exist */

	if (stat(path, &statbuf) != 0) {
		return (1);
	}

	/* return error if path is not a directory */

	if ((statbuf.st_mode & S_IFMT) != S_IFDIR) {
		errno = ENOTDIR;
		return (1);
	}

	/* path exists and is a directory */

	return (0);
}

/*
 * Name:	_z_pluginCatchSigint
 * Synopsis:	SIGINT/SIGHUP interrupt handler
 * Description:	Catch the "SIGINT" and "SIGHUP" signals:
 *		-> increment _z_SigReceived global variable
 *		-> propagate signal to "_z_ChildProcessId" if registered (!= -1)
 * Arguments:	signo - [RO, *RO] - (int)
 *			Signal number that was caught
 * Returns:	void
 */

void
_z_sig_trap(int a_signo)
{
	/* bump signals received count */

	_z_global_data._z_SigReceived++;

	/* if child process registered, propagate signal to child */

	if (_z_global_data._z_ChildProcessId > 0) {
		(void) kill(_z_global_data._z_ChildProcessId, a_signo);
	}
}

/*
 * Name:	_z_program_error
 * Description:	Output an error message to the appropriate destinations
 * Arguments:	format - [RO, RO*] (char *)
 *			printf-style format for debugging message to be output
 *		VARG_LIST - [RO] (?)
 *			arguments as appropriate to 'format' specified
 * Returns:	void
 * NOTE:	format of message will be:
 *			[aaa: ] ERROR: message
 *		where:	aaa - program name (if set)
 *			message - results of format and arguments
 * 		for example:
 *			ERROR: unable to get package list
 */

/*PRINTFLIKE1*/
void
_z_program_error(char *a_format, ...)
{
	va_list ap;
	char	message[MAX_MESSAGE_SIZE];

	/* entry assertions */

	assert(a_format != NULL);

	/* return if no progerr function registered */

	if (_z_global_data._z_progerr == NULL) {
		return;
	}

	/* capture message */

	va_start(ap, a_format);
	(void) vsnprintf(message, sizeof (message), a_format, ap);
	va_end(ap);

	/* pass message to registered function */

	(_z_global_data._z_progerr)(MSG_PROG_ERR, message);
}

/*
 * Name:	_z_running_in_global_zone
 * Synopsis:	Determine if this process is running in the global zone
 * Arguments:	void
 * Returns:	boolean_t
 *			== B_TRUE - this process is running in the global zone
 *			== B_FALSE - this process is running in a nonglobal zone
 */

boolean_t
_z_running_in_global_zone(void)
{
	zoneid_t	zoneid = (zoneid_t)-1;

	/*
	 * if zones are not implemented, there is no way to tell if zones
	 * are supported or not - in this case, we can only be running in the
	 * global zone (since non-global zones cannot exist) so return TRUE
	 */

	if (z_zones_are_implemented() == B_FALSE) {
		return (B_TRUE);
	}

	/* get the zone i.d. of the current zone */

	zoneid = getzoneid();

	/* return TRUE if this is the global zone i.d. */

	if (zoneid == GLOBAL_ZONEID) {
		return (B_TRUE);
	}

	/* return FALSE - not in the global zone */

	return (B_FALSE);
}

/*
 * Name:	_z_zones_are_implemented
 * Synopsis:	Determine if zones are supported by the current system
 * Arguments:	void
 * Returns:	boolean_t
 *			== B_TRUE - zones are supported
 *			== B_FALSE - zones are not supported
 */

boolean_t
_z_zones_are_implemented(void)
{
	void	*libptr = NULL;

	/* locate zone cfg library */

	libptr = dlopen(ZONECFG_LIBRARY, RTLD_NOW|RTLD_GLOBAL);
	if (libptr == (void *)NULL) {
		_z_echoDebug(DBG_LIBRARY_NOT_FOUND, ZONECFG_LIBRARY, dlerror());
		libptr = dlopen(ZONECFG1_LIBRARY, RTLD_NOW|RTLD_GLOBAL);
	}

	/* return false if library not available */

	if (libptr == (void *)NULL) {
		_z_echoDebug(DBG_LIBRARY_NOT_FOUND, ZONECFG1_LIBRARY,
		    dlerror());
		return (B_FALSE);
	}

	/* library available - close handle */

	(void) dlclose(libptr);

	/* locate contract filesystem library */

	libptr = dlopen(CONTRACT_LIBRARY, RTLD_NOW|RTLD_GLOBAL);
	if (libptr == (void *)NULL) {
		_z_echoDebug(DBG_LIBRARY_NOT_FOUND, CONTRACT_LIBRARY,
		    dlerror());
		libptr = dlopen(CONTRACT1_LIBRARY, RTLD_NOW|RTLD_GLOBAL);
	}

	/* return false if library not available */

	if (libptr == (void *)NULL) {
		_z_echoDebug(DBG_LIBRARY_NOT_FOUND, CONTRACT1_LIBRARY,
		    dlerror());
		return (B_FALSE);
	}

	/* library available - close handle */

	(void) dlclose(libptr);

	/* return success */

	return (B_TRUE);
}

boolean_t
_z_brands_are_implemented(void)
{
	void	*libptr;

	/* locate brand library */

	libptr = dlopen(BRAND_LIBRARY, RTLD_NOW|RTLD_GLOBAL);
	if (libptr == NULL) {
		_z_echoDebug(DBG_LIBRARY_NOT_FOUND, BRAND_LIBRARY, dlerror());
		libptr = dlopen(BRAND1_LIBRARY, RTLD_NOW|RTLD_GLOBAL);
	}

	/* return false if library not available */

	if (libptr == NULL) {
		_z_echoDebug(DBG_LIBRARY_NOT_FOUND, BRAND1_LIBRARY, dlerror());
		return (B_FALSE);
	}

	/* library available - close handle */

	(void) dlclose(libptr);

	/* return success */

	return (B_TRUE);
}

/*
 * z_calloc()
 * 	Allocate 'size' bytes from the heap using calloc()
 * Parameters:
 *	size	- number of bytes to allocate
 * Return:
 *	NULL	- calloc() failure
 *	void *	- pointer to allocated structure
 * Status:
 *	public
 */
void *
_z_calloc(size_t size)
{
	void *	tmp;

	if ((tmp = (void *) malloc(size)) == NULL) {
		fatal_err_func(ERR_MALLOC_FAIL);
		return (NULL);
	}

	(void) memset(tmp, 0, size);
	return (tmp);
}

/*
 * z_malloc()
 * 	Alloc 'size' bytes from heap using malloc()
 * Parameters:
 *	size	- number of bytes to malloc
 * Return:
 *	NULL	- malloc() failure
 *	void *	- pointer to allocated structure
 * Status:
 *	public
 */
void *
_z_malloc(size_t size)
{
	void *tmp;

	if ((tmp = (void *) malloc(size)) == NULL) {
		fatal_err_func(ERR_MALLOC_FAIL);
		return (NULL);
	} else
		return (tmp);
}

/*
 * _z_realloc()
 *	Calls realloc() with the specfied parameters. _z_realloc()
 *	checks for realloc failures and adjusts the return value
 *	automatically.
 * Parameters:
 *	ptr	- pointer to existing data block
 * 	size	- number of bytes additional
 * Return:
 *	NULL	- realloc() failed
 *	void *	- pointer to realloc'd structured
 * Status:
 *	public
 */
void *
_z_realloc(void *ptr, size_t size)
{
	void *tmp;

	if ((tmp = (void *)realloc(ptr, size)) == (void *)NULL) {
		fatal_err_func(ERR_MALLOC_FAIL);
		return ((void *)NULL);
	} else
		return (tmp);
}

/*
 * z_strdup()
 *	Allocate space for the string from the heap, copy 'str' into it,
 *	and return a pointer to it.
 * Parameters:
 *	str	- string to duplicate
 * Return:
 *	NULL	- duplication failed or 'str' was NULL
 * 	char *	- pointer to newly allocated/initialized structure
 * Status:
 *	public
 */
void *
_z_strdup(char *str)
{
	char *tmp;

	if (str == NULL)
		return ((char *)NULL);

	if ((tmp = strdup(str)) == NULL) {
		fatal_err_func(ERR_MALLOC_FAIL);
		return ((char *)NULL);
	} else
		return (tmp);
}
