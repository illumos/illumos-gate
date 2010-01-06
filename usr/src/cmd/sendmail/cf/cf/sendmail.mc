divert(-1)
#
# Copyright (c) 1983 Eric P. Allman
# Copyright (c) 1988, 1993
#	The Regents of the University of California.  All rights reserved.
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#  This is a configuration file for SunOS 5.8 (a.k.a. Solaris 8) and later
#  subsidiary machines.  It has support for local and SMTP mail.  The
#  confFALLBACK_SMARTHOST macro is enabled, which means that messages will
#  be sent to that host (which is set to mailhost.$m [$m is the local domain])
#  if MX records are unavailable.  A short-cut rule is also defined, which
#  says if the recipient host is in the local domain, send to it directly
#  instead of the smart host.
#
#  If you want to customize this further, copy it to a name appropriate
#  for your environment and do the modifications there.
#

divert(0)dnl
VERSIONID(`sendmail.mc (Sun)')
OSTYPE(`solaris8')dnl
DOMAIN(`solaris-generic')dnl
define(`confFALLBACK_SMARTHOST', `mailhost$?m.$m$.')dnl
MAILER(`local')dnl
MAILER(`smtp')dnl

LOCAL_NET_CONFIG
R$* < @ $* .$m. > $*	$#esmtp $@ $2.$m $: $1 < @ $2.$m. > $3
