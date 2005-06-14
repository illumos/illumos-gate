#ifndef homedir_h
#define homedir_h

/*
 * Copyright (c) 2000, 2001, 2002, 2003, 2004 by Martin C. Shepherd.
 * 
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, provided that the above
 * copyright notice(s) and this permission notice appear in all copies of
 * the Software and that both the above copyright notice(s) and this
 * permission notice appear in supporting documentation.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL
 * INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * Except as contained in this notice, the name of a copyright holder
 * shall not be used in advertising or otherwise to promote the sale, use
 * or other dealings in this Software without prior written authorization
 * of the copyright holder.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

typedef struct HomeDir HomeDir;

/*
 * The following constructor and destructor functions create and
 * delete the resources needed to look up home directories.
 */
HomeDir *_new_HomeDir(void);
HomeDir *_del_HomeDir(HomeDir *home);

/*
 * Return the home directory of a specified user, or NULL if unknown.
 */
const char *_hd_lookup_home_dir(HomeDir *home, const char *user);

/*
 * Get the description of the that occured when _hd_lookup_home_dir() was
 * last called.
 */
const char *_hd_last_home_dir_error(HomeDir *home);

/*
 * The _hd_scan_user_home_dirs() function calls a user-provided function
 * for each username known by the system, passing the function both
 * the name and the home directory of the user.
 *
 * The following macro can be used to declare both pointers and
 * prototypes for the callback functions. The 'data' argument is
 * a copy of the 'data' argument passed to _hd_scan_user_home_dirs()
 * and is intended for the user of _hd_scan_user_home_dirs() to use
 * to pass anonymous context data to the callback function.
 * The username and home directories are passed to the callback function
 * in the *usrnam and *homedir arguments respectively.
 * To abort the scan, and have _hd_scan_user_home_dirs() return 1, the
 * callback function can return 1. A description of up to maxerr
 * characters before the terminating '\0', can be written to errmsg[].
 * This can then be examined by calling _hd_last_home_dir_error().
 * To indicate success and continue the scan, the callback function
 * should return 0. _hd_scan_user_home_dirs() returns 0 on successful
 * completion of the scan, or 1 if an error occurred or a call to the
 * callback function returned 1.
 */
#define HOME_DIR_FN(fn) int (fn)(void *data, const char *usrnam, const char *homedir, char *errmsg, int maxerr)

int _hd_scan_user_home_dirs(HomeDir *home, const char *prefix, void *data,
			    HOME_DIR_FN(*callback_fn));

#endif
