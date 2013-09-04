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

#
#  Makefile for configuration files.
#
#  Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
#  Use is subject to license terms.
#
#	@(#)Makefile	8.15 (Berkeley) 3/29/98
#

#
#  Create configuration files using "m4 ../m4/cf.m4 file.mc > file.cf"
#  of "/usr/ccs/bin/make file.cf"; these may be easier than tweaking the
#  Makefile.  Also, updates will over-write any changes to the Makefile.
#  You do need to have a fairly modern M4 available (GNU m4 works).  On
#  Solaris, use /usr/ccs/bin/m4.
#

M4=	/usr/ccs/bin/m4
CFDIR=	..
MV=	/usr/bin/mv
RM=	/usr/bin/rm -f

.SUFFIXES:  .mc .cf

.mc.cf:
	test ! -f $@ || $(MV) $@ $@.prev
	$(M4) ${CFDIR}/m4/cf.m4 $*.mc > $@

ALL=	sendmail.cf submit.cf

all: $(ALL)

clean cleandir:
	$(RM) $(ALL)

depend install: 

# this is overkill, but....
M4FILES=\
	${CFDIR}/domain/generic.m4 \
	${CFDIR}/domain/solaris-antispam.m4 \
	${CFDIR}/domain/solaris-generic.m4 \
	${CFDIR}/feature/accept_unqualified_senders.m4 \
	${CFDIR}/feature/accept_unresolvable_domains.m4 \
	${CFDIR}/feature/access_db.m4 \
	${CFDIR}/feature/allmasquerade.m4 \
	${CFDIR}/feature/always_add_domain.m4 \
	${CFDIR}/feature/badmx.m4 \
	${CFDIR}/feature/bestmx_is_local.m4 \
	${CFDIR}/feature/bitdomain.m4 \
	${CFDIR}/feature/blacklist_recipients.m4 \
	${CFDIR}/feature/block_bad_helo.m4 \
	${CFDIR}/feature/compat_check.m4 \
	${CFDIR}/feature/conncontrol.m4 \
	${CFDIR}/feature/delay_checks.m4 \
	${CFDIR}/feature/dnsbl.m4 \
	${CFDIR}/feature/domaintable.m4 \
	${CFDIR}/feature/enhdnsbl.m4 \
	${CFDIR}/feature/generics_entire_domain.m4 \
	${CFDIR}/feature/genericstable.m4 \
	${CFDIR}/feature/greet_pause.m4 \
	${CFDIR}/feature/ldap_routing.m4 \
	${CFDIR}/feature/limited_masquerade.m4 \
	${CFDIR}/feature/local_lmtp.m4 \
	${CFDIR}/feature/local_no_masquerade.m4 \
	${CFDIR}/feature/local_procmail.m4 \
	${CFDIR}/feature/lookupdotdomain.m4 \
	${CFDIR}/feature/loose_relay_check.m4 \
	${CFDIR}/feature/mailertable.m4 \
	${CFDIR}/feature/masquerade_entire_domain.m4 \
	${CFDIR}/feature/masquerade_envelope.m4 \
	${CFDIR}/feature/msp.m4 \
	${CFDIR}/feature/mtamark.m4 \
	${CFDIR}/feature/no_default_msa.m4 \
	${CFDIR}/feature/nocanonify.m4 \
	${CFDIR}/feature/notsticky.m4 \
	${CFDIR}/feature/nouucp.m4 \
	${CFDIR}/feature/preserve_local_plus_detail.m4 \
	${CFDIR}/feature/preserve_luser_host.m4 \
	${CFDIR}/feature/promiscuous_relay.m4 \
	${CFDIR}/feature/queuegroup.m4 \
	${CFDIR}/feature/ratecontrol.m4 \
	${CFDIR}/feature/redirect.m4 \
	${CFDIR}/feature/relay_based_on_MX.m4 \
	${CFDIR}/feature/relay_entire_domain.m4 \
	${CFDIR}/feature/relay_hosts_only.m4 \
	${CFDIR}/feature/relay_local_from.m4 \
	${CFDIR}/feature/relay_mail_from.m4 \
	${CFDIR}/feature/require_rdns.m4 \
	${CFDIR}/feature/smrsh.m4 \
	${CFDIR}/feature/stickyhost.m4 \
	${CFDIR}/feature/use_client_ptr.m4 \
	${CFDIR}/feature/use_ct_file.m4 \
	${CFDIR}/feature/use_cw_file.m4 \
	${CFDIR}/feature/uucpdomain.m4 \
	${CFDIR}/feature/virtuser_entire_domain.m4 \
	${CFDIR}/feature/virtusertable.m4 \
	${CFDIR}/m4/cf.m4 \
	${CFDIR}/m4/cfhead.m4 \
	${CFDIR}/m4/proto.m4 \
	${CFDIR}/m4/version.m4 \
	${CFDIR}/mailer/local.m4 \
	${CFDIR}/mailer/smtp.m4 \
	${CFDIR}/mailer/uucp.m4 \
	${CFDIR}/ostype/solaris2.m4 \
	${CFDIR}/ostype/solaris2.ml.m4 \
	${CFDIR}/ostype/solaris2.pre5.m4 \
	${CFDIR}/ostype/solaris8.m4

$(ALL):  $(M4FILES)
