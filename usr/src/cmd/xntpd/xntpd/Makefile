#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG=		xntpd
MANIFEST=	ntp.xml
SVCMETHOD=	xntp

include ../../Makefile.cmd

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)

include ../Makefile.cmd

.KEEP_STATE:

.PARALLEL:

CLOBBERFILES = $(ROOTINETLIBPROG)

all:	$(PROG)

check:	$(CHKMANIFEST)

install: all $(ROOTINETLIBPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

lint:
# lint:	lint_PROG

include ../../Makefile.targ

#
# xntpd - NTP daemon
#
LIBNTP=		../$(LIBNTP_A)
LIBPARSE=	../$(LIBPARSE_A)
LINTLIB=	../$(LLIBNTP_A)
LIBS += 	-lscf -lmd
LDLIBS +=	$(LIBNTP) $(LIBPARSE) $(LIBS)
LDFLAGS +=	$(MAPFILE.NGB:%=-M%)
#
SOURCE=	ntp_config.c ntp_control.c ntp_io.c ntp_leap.c \
	ntp_loopfilter.c ntp_monitor.c ntp_peer.c ntp_proto.c \
	ntp_refclock.c ntp_request.c ntp_restrict.c ntp_timer.c \
	ntp_unixclock.c ntp_util.c ntp_intres.c ntp_filegen.c ntpd.c \
	refclock_conf.c refclock_chu.c refclock_local.c \
	refclock_pst.c refclock_wwvb.c refclock_arc.c \
	refclock_mx4200.c refclock_as2201.c \
	refclock_tpro.c refclock_leitch.c refclock_arbiter.c \
	refclock_irig.c refclock_msfees.c \
	refclock_trak.c refclock_datum.c refclock_acts.c \
	refclock_heath.c refclock_nmea.c \
	refclock_atom.c refclock_ptbacts.c refclock_usno.c \
	refclock_true.c refclock_hpgps.c

REFCLK_OBJS= refclock_conf.o refclock_chu.o refclock_local.o \
	refclock_pst.o refclock_wwvb.o refclock_arc.o \
	refclock_mx4200.o refclock_as2201.o \
	refclock_tpro.o refclock_leitch.o refclock_arbiter.o \
	refclock_irig.o refclock_msfees.o \
	refclock_trak.o refclock_datum.o refclock_acts.o \
	refclock_heath.o refclock_nmea.o \
	refclock_atom.o refclock_ptbacts.o refclock_usno.o \
	refclock_true.o refclock_hpgps.o

OBJS=	ntp_config.o ntp_control.o ntp_io.o ntp_leap.o \
	ntp_loopfilter.o ntp_monitor.o ntp_peer.o ntp_proto.o \
	ntp_refclock.o ntp_request.o ntp_restrict.o ntp_timer.o \
	ntp_unixclock.o ntp_util.o ntp_intres.o ntp_filegen.o ntpd.o \
	version.o $(REFCLK_OBJS)


$(REFCLK_OBJS) :=	CFLAGS += $(CLOCKDEFS)

$(PROG): $(OBJS) $(LIBNTP) $(LIBPARSE) $(MAPFILE.NGB)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

lint:
	$(LINT.c) -x -u $(DEFS) $(INCL) $(LLIBNTP) $(SOURCE) >lint.errs

clean:
	$(RM) $(OBJS) lint.errs
