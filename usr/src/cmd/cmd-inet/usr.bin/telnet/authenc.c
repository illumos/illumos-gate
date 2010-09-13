/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Miscellaneous routines needed by the telnet client for authentication
 * and / or encryption.
 */

/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static char sccsid[] = "@(#)authenc.c	8.1 (Berkeley) 6/6/93";
#endif /* not lint */

#include <sys/types.h>
#include <arpa/telnet.h>

#include "general.h"
#include "ring.h"
#include "externs.h"
#include "defines.h"
#include "types.h"

char *RemoteHostName = NULL;
char *UserNameRequested = NULL;

#define	MAXNETDATA	16

/*
 * Get ready to do authentication and encryption by calling their
 * init routines, and clearing the user name variable
 */
/* ARGSUSED */
void
auth_encrypt_init(char *local, char *remote, char *name)
{
	RemoteHostName = remote;

	auth_init(name);

	encrypt_init(name);

	if (UserNameRequested) {
		free(UserNameRequested);
		UserNameRequested = NULL;
	}
}

/*
 * Set the user name variable.  This is the user name used from now
 * on for authentication and encryption
 */
void
auth_encrypt_user(char *name)
{
	if (UserNameRequested)
		free(UserNameRequested);
	UserNameRequested = name ? strdup(name) : NULL;
}

int
net_write(unsigned char *str, int len)
{
	if (NETROOM() > len) {
		ring_supply_data(&netoring, str, len);
		if (str[0] == IAC && str[1] == SE)
			printsub('>', &str[2], len - 2);
		return (len);
	}
	return (0);
}

void
net_encrypt(void)
{
	if (encrypt_output)
		ring_encrypt(&netoring, encrypt_output);
	else
		ring_clearto(&netoring);
}

/*
 * Spin to wait for authentication to complete
 * This allows for a timeout
 */
void
telnet_spin(void)
{
	extern boolean_t scheduler_lockout_tty;

	scheduler_lockout_tty = B_TRUE;
	(void) Scheduler(0);
	scheduler_lockout_tty = B_FALSE;
}


/*
 * Used to print out unsigned chars as decimals for debugging options
 */
void
printd(unsigned char *data, int cnt)
{
	cnt = (cnt < MAXNETDATA) ? cnt:MAXNETDATA;
	while (cnt-- > 0)
		(void) printf(" %02x", *data++);
}
