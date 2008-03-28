#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG =		safe_finger tcpd tcpdchk tcpdmatch try-from

include ../Makefile.cmd

ERROFF =	-erroff=E_FUNC_HAS_NO_RETURN_STMT \
		-erroff=E_IMPLICIT_DECL_FUNC_RETURN_INT \
		-_gcc=-Wno-return-type -_gcc=-Wno-implicit
CFLAGS +=	$(CCVERBOSE) $(ERROFF)
CPPFLAGS +=	$(ACCESS) $(PARANOID) $(NETGROUP) $(TLI) \
		$(UMASK) $(STYLE) $(TABLES) $(KILL_OPT) $(BUGS) \
		-DRFC931_TIMEOUT=$(RFC931_TIMEOUT) \
		-DFACILITY=$(FACILITY) -DSEVERITY=$(SEVERITY) \
		-DREAL_DAEMON_DIR=\"$(REAL_DAEMON_DIR)\" \
		-I../../lib/libwrap
tcpd tcpdmatch try-from := \
	LDLIBS += -lwrap
tcpdchk := \
	LDLIBS += -lwrap -lnsl

# Various components must export interfaces, but also contain name-space
# clashes with system libraries.
MAPFILE.INT.D =	$(MAPFILE.NGB) mapfile-intf-tcpdchk
MAPFILE.INT.M =	$(MAPFILE.NGB) mapfile-intf-tcpdmatch
MAPFILE.INT.F =	$(MAPFILE.NGB) mapfile-intf-tryfrom

tcpdchk :=	LDFLAGS +=$(MAPFILE.INT.D:%=-M%)
tcpdmatch :=	LDFLAGS +=$(MAPFILE.INT.M:%=-M%)
try-from :=	LDFLAGS +=$(MAPFILE.INT.F:%=-M%)

# SRCONLY files are not used for building but are included in the source code
# package SUNWtcpdS for consistency and completeness with respect to the
# public tcp_wrappers distribution.
SRCONLY =	BLURB Banners.Makefile CHANGES DISCLAIMER Makefile \
		Makefile.dist Makefile.org README README.IRIX README.NIS \
		README.ipv6 hosts_access.c.org misc.c.org miscd.c myvsyslog.c \
		ncr.c printf.ck ptx.c rfc931.c.org scaffold.c.org \
		socket.c.diff socket.c.org strcasecmp.c tags tcpd.h.org \
		tcpdchk.c.org tcpdmatch.c.org tli-sequent.c tli-sequent.h \
		tli.c.org update.c.org vfprintf.c

MANDIRS =	man3 man4 man1m
MANPAGES =	man3/hosts_access.3 man3/libwrap.3 man4/hosts_access.4 \
		man4/hosts_options.4 man4/hosts.allow.4 man4/hosts.deny.4 \
		man1m/tcpd.1m man1m/tcpdchk.1m man1m/tcpdmatch.1m
DISTFILES =	environ.c fakelog.c hosts_access.3 hosts_access.4 \
		hosts_options.4 inetcf.c inetcf.h safe_finger.c scaffold.c \
		scaffold.h tcpd.1m tcpd.c tcpdchk.1m tcpdchk.c tcpdmatch.1m \
		tcpdmatch.c try-from.c README.sfw $(SRCONLY)

ROOTSRC =	$(ROOT)/usr/share/src/tcp_wrappers
$(ROOTSRC) :=	OWNER = root
$(ROOTSRC) :=	GROUP = bin
ROOTMAN = $(ROOT)/usr/share/man
ROOTMANPAGES = $(MANPAGES:%=$(ROOTMAN)/%)
ROOTMANDIRS = $(MANDIRS:%=$(ROOTMAN)/%)
ROOTSRCFILES = $(DISTFILES:%=$(ROOTSRC)/%)

.KEEP_STATE:

all: $(PROG) THIRDPARTYLICENSE

install: all $(ROOTUSRSBINPROG) $(ROOTMANPAGES) $(ROOTSRCFILES)

clean:
	$(RM) *.o
	$(RM) -r sunman

lint:	lint_PROG

# These Solaris-specific man page aliases are installed verbatim.
sunman/libwrap.3: libwrap.3
	mkdir -p sunman; cat libwrap.3 > $@
sunman/hosts.allow.4: hosts.allow.4
	mkdir -p sunman; cat hosts.allow.4 > $@
sunman/hosts.deny.4: hosts.deny.4
	mkdir -p sunman; cat hosts.deny.4 > $@

# The rest of the man pages are in the form provided in the original
# distribution, but get edited and renamed to follow Solaris man page
# conventions.  E.g. tcpd.8 gets installed as /usr/share/man/man1m/tcpd.1m.
# Create temporary copies in the sunman directory with modified names
# and contents.  The sed program man.sed contains the content edits.

sunman/%.1m: %.8
	mkdir -p sunman; sed -f man.sed < $< > $@
sunman/%.4: %.5
	mkdir -p sunman; sed -f man.sed < $< > $@
sunman/%.3: %.3
	mkdir -p sunman; sed -f man.sed < $< > $@

$(ROOTMANPAGES) := FILEMODE = 0444
$(ROOTMANPAGES): $(ROOTMANDIRS) $(ROOT)/usr/share/man
$(ROOTMANDIRS): $(ROOTMAN)
	$(INS.dir)
$(ROOTMAN):
	$(INS.dir)
$(ROOTMAN1M)/% $(ROOTMAN3)/% $(ROOTMAN)/man4/%: sunman/%
	$(INS.file)

$(ROOTSRCFILES) := FILEMODE = 0444
$(ROOTSRCFILES): $(ROOTSRC)
$(ROOTSRC): 
	$(INS.dir)
$(ROOTSRC)/%: %.sfwsrc
	$(INS.rename)
$(ROOTSRC)/%: sunman/%
	$(INS.file)
$(ROOTSRC)/%: %
	$(INS.file)

$(ROOT)/usr/share: $(ROOT)/usr
	$(INS.dir)
$(ROOT)/usr: $(ROOT)
	$(INS.dir)

TCPDMATCH_OBJ = tcpdmatch.o fakelog.o inetcf.o scaffold.o

tcpdmatch: $(TCPDMATCH_OBJ) $(LIB) $(MAPFILE.INTF.M)
	$(LINK.c) -o $@ $(TCPDMATCH_OBJ) $(LDLIBS)
	$(POST_PROCESS)

try-from: try-from.o fakelog.o $(LIB) $(MAPFILE.INTF.F)
	$(LINK.c) -o $@ try-from.o fakelog.o $(LDLIBS)
	$(POST_PROCESS)

TCPDCHK_OBJ = tcpdchk.o fakelog.o inetcf.o scaffold.o

tcpdchk: $(TCPDCHK_OBJ) $(LIB) $(MAPFILE.INTF.C)
	$(LINK.c) -o $@ $(TCPDCHK_OBJ) $(LDLIBS)
	$(POST_PROCESS)

THIRDPARTYLICENSE: DISCLAIMER
	$(GREP) -v '\*\*\*\*' DISCLAIMER > $@

CLOBBERFILES += THIRDPARTYLICENSE

include ../Makefile.targ

# The rest of this file contains definitions more-or-less directly from the
# original Makefile of the tcp_wrappers distribution.

##############################
# System parameters appropriate for Solaris 9

REAL_DAEMON_DIR	= /usr/sbin
TLI		= -DTLI
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

################################################################
# Optional: Changing the default disposition of logfile records
#
# By default, logfile entries are written to the same file as used for
# sendmail transaction logs. See your /etc/syslog.conf file for actual
# path names of logfiles. The tutorial section in the README file
# gives a brief introduction to the syslog daemon.
# 
# Change the FACILITY definition below if you disagree with the default
# disposition. Some syslog versions (including Ultrix 4.x) do not provide
# this flexibility.
# 
# If nothing shows up on your system, it may be that the syslog records
# are sent to a dedicated loghost. It may also be that no syslog daemon
# is running at all. The README file gives pointers to surrogate syslog
# implementations for systems that have no syslog library routines or
# no syslog daemons. When changing the syslog.conf file, remember that
# there must be TABs between fields.
#
# The LOG_XXX names below are taken from the /usr/include/syslog.h file.

FACILITY= LOG_MAIL	# LOG_MAIL is what most sendmail daemons use

# The syslog priority at which successful connections are logged.

SEVERITY= LOG_INFO	# LOG_INFO is normally not logged to the console

######################################################
# Optional: Changing the default file protection mask
#
# On many systems, network daemons and other system processes are started
# with a zero umask value, so that world-writable files may be produced.
# It is a good idea to edit your /etc/rc* files so that they begin with
# an explicit umask setting.  On our site we use `umask 022' because it
# does not break anything yet gives adequate protection against tampering.
# 
# The following macro specifies the default umask for processes run under
# control of the daemon wrappers. Comment it out only if you are certain
# that inetd and its children are started with a safe umask value.

UMASK	= -DDAEMON_UMASK=022

#######################################
# Optional: Turning off access control
#
# By default, host access control is enabled.  To disable host access
# control, comment out the following definition.  Host access control
# can also be turned off at runtime by providing no or empty access
# control tables.

ACCESS	= -DHOSTS_ACCESS

####################################################
# Optional: dealing with host name/address conflicts
#
# By default, the software tries to protect against hosts that claim to
# have someone elses host name. This is relevant for network services
# whose authentication depends on host names, such as rsh and rlogin.
#
# With paranoid mode on, connections will be rejected when the host name
# does not match the host address. Connections will also be rejected when
# the host name is available but cannot be verified.
#
# Comment out the following definition if you want more control over such
# requests. When paranoid mode is off and a host name double check fails,
# the client can be matched with the PARANOID access control pattern.
#
# Paranoid mode implies hostname lookup. In order to disable hostname
# lookups altogether, see the next section.

PARANOID= -DPARANOID

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

#############################################
# Optional: Turning on host ADDRESS checking
#
# Optionally, the software tries to protect against hosts that pretend to
# have someone elses host address. This is relevant for network services
# whose authentication depends on host names, such as rsh and rlogin,
# because the network address is used to look up the remote host name.
# 
# The protection is to refuse TCP connections with IP source routing
# options.
#
# This feature cannot be used with SunOS 4.x because of a kernel bug in
# the implementation of the getsockopt() system call. Kernel panics have
# been observed for SunOS 4.1.[1-3]. Symptoms are "BAD TRAP" and "Data
# fault" while executing the tcp_ctloutput() kernel function.
#
# Reportedly, Sun patch 100804-03 or 101790 fixes this for SunOS 4.1.x.
#
# Uncomment the following macro definition if your getsockopt() is OK.
#
# -DKILL_IP_OPTIONS is not needed on modern UNIX systems that can stop
# source-routed traffic in the kernel. Examples: 4.4BSD derivatives,
# Solaris 2.x, and Linux. See your system documentation for details.
#
# KILL_OPT= -DKILL_IP_OPTIONS

## End configuration options
############################
