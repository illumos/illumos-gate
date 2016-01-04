/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file performs some of the things login(1) normally does.  We cannot
 * easily use something like login -p -h host -f user, because there are
 * several different logins around, and it is hard to determined what kind of
 * login the current system has.  Also, we want to be able to execute commands
 * on a tty.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
 * Copyright (c) 1999 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "includes.h"
RCSID("$OpenBSD: sshlogin.c,v 1.5 2002/08/29 15:57:25 stevesk Exp $");

#include "loginrec.h"
#include "log.h"
#include "buffer.h"
#include "servconf.h"
#include "canohost.h"
#include "packet.h"

extern u_int utmp_len;
extern ServerOptions options;

/*
 * Records that the user has logged in.  If only these parts of operating
 * systems were more standardized.
 */
void
record_login(pid_t pid, const char *ttyname, const char *progname,
		const char *user)
{
  struct logininfo *li;
  static int initialized = 0;
  static socklen_t fromlen;
  static struct sockaddr_storage from;
  static const char *remote_name_or_ip;

  if (pid == 0)
    pid = getpid();
  /*
   * Get IP address of client. If the connection is not a socket, let
   * the address be 0.0.0.0.
   */
  if (!initialized) {
    (void) memset(&from, 0, sizeof(from));
    if (packet_connection_is_on_socket()) {
      fromlen = sizeof(from);
      if (getpeername(packet_get_connection_in(),
          (struct sockaddr *) &from, &fromlen) < 0) {
        debug("getpeername: %.100s", strerror(errno));
        fatal_cleanup();
      }
    }
    remote_name_or_ip = get_remote_name_or_ip(utmp_len,
      options.verify_reverse_mapping);

    initialized = 1;
  }

  li = login_alloc_entry(pid, user, remote_name_or_ip, ttyname, progname);
  login_set_addr(li, (struct sockaddr*) &from, sizeof(struct sockaddr));
  (void) login_login(li);
  login_free_entry(li);
}

/* Records that the user has logged out. */
void
record_logout(pid_t pid, const char *ttyname, const char *progname,
		const char *user)
{
  struct logininfo *li;

  li = login_alloc_entry(pid, user, NULL, ttyname, progname);
  (void) login_logout(li);
  login_free_entry(li);
}
