/*
 *  mpprime.c
 *
 *  Utilities for finding and working with prime and pseudo-prime
 *  integers
 *
 * ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the MPI Arbitrary Precision Integer Arithmetic library.
 *
 * The Initial Developer of the Original Code is
 * Michael J. Fromberger.
 * Portions created by the Initial Developer are Copyright (C) 1997
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Netscape Communications Corporation
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Sun elects to use this software under the MPL license.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mpi-priv.h"
#include "mpprime.h"
#include "mplogic.h"
#ifndef _KERNEL
#include <stdlib.h>
#include <string.h>
#else
#include <sys/random.h>
#endif

#define SMALL_TABLE 0 /* determines size of hard-wired prime table */

#ifndef _KERNEL
#define RANDOM() rand()
#else
#define RANDOM() foo_rand()

static int
foo_rand()
{
	int r;
	random_get_pseudo_bytes((uchar_t *)&r, sizeof (r));
	return (r);
}
#endif

/*
  mpp_random(a)

  Assigns a random value to a.  This value is generated using the
  standard C library's rand() function, so it should not be used for
  cryptographic purposes, but it should be fine for primality testing,
  since all we really care about there is good statistical properties.

  As many digits as a currently has are filled with random digits.
 */

mp_err  mpp_random(mp_int *a)

{
  mp_digit  next = 0;
  unsigned int       ix, jx;

  ARGCHK(a != NULL, MP_BADARG);

  for(ix = 0; ix < USED(a); ix++) {
    for(jx = 0; jx < sizeof(mp_digit); jx++) {
      next = (next << CHAR_BIT) | (RANDOM() & UCHAR_MAX);
    }
    DIGIT(a, ix) = next;
  }

  return MP_OKAY;

} /* end mpp_random() */

/* }}} */

/* {{{ mpp_random_size(a, prec) */

mp_err  mpp_random_size(mp_int *a, mp_size prec)
{
  mp_err   res;

  ARGCHK(a != NULL && prec > 0, MP_BADARG);
  
  if((res = s_mp_pad(a, prec)) != MP_OKAY)
    return res;

  return mpp_random(a);

} /* end mpp_random_size() */
