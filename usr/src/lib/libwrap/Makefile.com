#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2011 Nexenta Systems, Inc. All rights reserved.
#

LIBRARY =	libwrap.a
MAJOR =		.1
MINOR =		.0
VERS =		$(MAJOR)$(MINOR)
OBJECTS =	hosts_access.o options.o shell_cmd.o rfc931.o eval.o \
		hosts_ctl.o refuse.o percent_x.o clean_exit.o \
		fromhost.o fix_options.o socket.o tli.o workarounds.o \
		update.o misc.o diag.o percent_m.o libvars.o

include ../../Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)
SONAME =	$(LIBRARY:.a=.so)$(MAJOR)
ROOTLINKS +=	$(ROOTLIBDIR)/$(LIBLINKS)$(MAJOR)
ROOTLINKS64 +=	$(ROOTLIBDIR64)/$(LIBLINKS)$(MAJOR)
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

MAPFILES =	../mapfile-vers

LDLIBS +=	-lsocket -lnsl -lc

CPPFLAGS +=	$(NETGROUP) $(TLI) $(ALWAYS_HOSTNAME) $(AUTH) \
		$(STYLE) $(TABLES) $(DOT) $(BUGS) \
		-DRFC931_TIMEOUT=$(RFC931_TIMEOUT) \
		-I$(SRCDIR) 
CFLAGS +=	$(CCVERBOSE)

CERRWARN +=	-erroff=E_FUNC_EXPECTS_TO_RETURN_VALUE
CERRWARN +=	-erroff=E_IMPLICIT_DECL_FUNC_RETURN_INT
CERRWARN +=	-erroff=E_OLD_STYLE_DECL_HIDES_PROTO

CERRWARN +=	-_gcc=-Wno-return-type
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

$(ROOTLIBDIR)/$(LIBLINKS)$(MAJOR): $(ROOTLIBDIR)/$(LIBLINKS)$(VERS)
	$(INS.liblink)

$(ROOTLIBDIR64)/$(LIBLINKS)$(MAJOR): $(ROOTLIBDIR64)/$(LIBLINKS)$(VERS)
	$(INS.liblink64)

include ../../Makefile.targ


# The rest of this file contains definitions more-or-less directly from the
# original Makefile of the tcp_wrappers distribution.

##############################
# System parameters appropriate for Solaris 9 and later

TLI		= -DTLI
BUGS		= -DGETPEERNAME_BUG -DBROKEN_FGETS -DLIBC_CALLS_STRTOK
NETGROUP	= -DNETGROUP

##############################
# Start of the optional stuff.

###########################################
# Optional: Turning on language extensions
#
# Instead of the default access control language that is documented in
# the hosts_access.5 document, the wrappers can be configured to
# implement an extensible language documented in the hosts_options.5
# document.  This language is implemented by the "options.c" source
# module, which also gives hints on how to add your own extensions.
# Uncomment the next definition to turn on the language extensions
# (examples: allow, deny, banners, twist and spawn).
# 
STYLE	= -DPROCESS_OPTIONS	# Enable language extensions.

###########################
# Optional: Reduce DNS load
#
# When looking up the address for a host.domain name, the typical DNS
# code will first append substrings of your own domain, so it tries
# host.domain.your.own.domain, then host.domain.own.domain, and then
# host.domain. The APPEND_DOT feature stops this waste of cycles. It is
# off by default because it causes problems on sites that don't use DNS
# and with Solaris < 2.4. APPEND_DOT will not work with hostnames taken
# from /etc/hosts or from NIS maps. It does work with DNS through NIS.
#
# DOT= -DAPPEND_DOT

##################################################
# Optional: Always attempt remote username lookups
#
# By default, the wrappers look up the remote username only when the
# access control rules require them to do so.
#
# Username lookups require that the remote host runs a daemon that
# supports an RFC 931 like protocol.  Remote user name lookups are not
# possible for UDP-based connections, and can cause noticeable delays
# with connections from non-UNIX PCs.  On some systems, remote username
# lookups can trigger a kernel bug, causing loss of service. The README
# file describes how to find out if your UNIX kernel has that problem.
# 
# Uncomment the following definition if the wrappers should always
# attempt to get the remote user name. If this is not enabled you can
# still do selective username lookups as documented in the hosts_access.5
# and hosts_options.5 manual pages (`nroff -man' format).
#
#AUTH	= -DALWAYS_RFC931
#
# The default username lookup timeout is 10 seconds. This may not be long
# enough for slow hosts or networks, but is enough to irritate PC users.

RFC931_TIMEOUT = 10

########################################################
# Optional: Changing the access control table pathnames
#
# The HOSTS_ALLOW and HOSTS_DENY macros define where the programs will
# look for access control information. Watch out for the quotes and
# backslashes when you make changes.

TABLES	= -DHOSTS_DENY=\"/etc/hosts.deny\" -DHOSTS_ALLOW=\"/etc/hosts.allow\"

########################################
# Optional: turning off hostname lookups
#
# By default, the software always attempts to look up the client
# hostname.  With selective hostname lookups, the client hostname
# lookup is postponed until the name is required by an access control
# rule or by a %letter expansion.
# 
# In order to perform selective hostname lookups, disable paranoid
# mode (see previous section) and comment out the following definition.

ALWAYS_HOSTNAME= -DALWAYS_HOSTNAME

## End configuration options
############################
