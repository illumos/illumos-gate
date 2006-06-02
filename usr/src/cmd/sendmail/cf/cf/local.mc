divert(-1)
#
# Copyright (c) 1983 Eric P. Allman
# Copyright (c) 1988, 1993
#	The Regents of the University of California.  All rights reserved.
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
#  This is a configuration file for SunOS 5.8 (a.k.a. Solaris 8) and later
#  subsidiary machines.  It has support for local and SMTP mail.  The
#  confFALLBACK_SMARTHOST macro is enabled, which means that messages will
#  be sent to that host (which is set to mailhost.$m [$m is the local domain])
#  if MX records are unavailable.  A short-cut rule is also defined, which
#  says if the recipient host is in the local domain, send to it directly
#  instead of the smart host.
#
#  Furthermore, this configuration file defines IPv4 localhost-binding
#  addresses for the MTA and MSA daemons causing the daemons to listen to
#  traffic from the local-host only.
#
#  This configuration file will be chosen by the sendmail start method if
#  the config/local_only property of svc:/network/smtp:sendmail is set to
#  "true". To have the daemons listen to external connections, set
#  config/local_only to "false" and restart sendmail.
#
#  If you want to customize this file in any other way, copy it to a name
#  appropriate for your environment and do the modifications there.

divert(0)dnl
VERSIONID(`%W% (Sun) %G%')
OSTYPE(`solaris8')dnl
DOMAIN(`solaris-generic')dnl
define(`confFALLBACK_SMARTHOST', `mailhost$?m.$m$.')dnl
FEATURE(`no_default_msa')dnl
DAEMON_OPTIONS(`NAME=NoMTA4, Family=inet, Addr=127.0.0.1')dnl
DAEMON_OPTIONS(`Name=MSA4,   Family=inet, Addr=127.0.0.1, Port=587, M=E')dnl
MAILER(`local')dnl
MAILER(`smtp')dnl

LOCAL_NET_CONFIG
R$* < @ $* .$m. > $*	$#esmtp $@ $2.$m $: $1 < @ $2.$m. > $3
