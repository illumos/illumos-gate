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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


#include <signal.h>

#include <bsd/bsd.h>

/* External references.
 */

/* Forward references.
 */

/* Static data.
 */

extern SIG_PF
bsd_signal (int Signal, SIG_PF Handler)
{
  auto SIG_PF                   previous_handler;
#ifdef sun
  previous_handler = sigset (Signal, Handler);
#else
  auto struct sigaction         new_action;
  auto struct sigaction         old_action;

  new_action.sa_flags = SA_SIGINFO;
  new_action.sa_handler = (void (*) ()) Handler;
  (void) sigemptyset (&new_action.sa_mask);
  (void) sigaddset (&new_action.sa_mask, Signal);

  (void) sigaction (Signal, &new_action, &old_action);

  previous_handler = (SIG_PF) old_action.sa_handler;
#endif
  return previous_handler;
}

extern void
bsd_signals (void)
{
  static int                    initialized = 0;

  if (initialized == 0)
    {
      initialized = 1;
    }

  return;
}
