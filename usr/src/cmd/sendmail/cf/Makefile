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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/sendmail/cf/Makefile
#

include		../../Makefile.cmd

CFS=		sendmail.cf submit.cf

SUBCFS=		cf/sendmail.cf cf/submit.cf

COMMONM4FILES=	m4/version.m4 m4/cf.m4 m4/cfhead.m4 m4/proto.m4 \
		ostype/solaris8.m4 domain/solaris-generic.m4 \
		mailer/local.m4 mailer/smtp.m4

ROOTETCMAIL = $(ROOTETC)/mail

ROOTETCMAILFILES=$(CFS:%=$(ROOTETCMAIL)/%)

ROOTETCMAILCF =	$(ROOTETCMAIL)/cf

BUILDPARTS =	$(ROOTETCMAILCF)/README \
		$(ROOTETCMAILCF)/cf/Makefile \
		$(ROOTETCMAILCF)/cf/sendmail.cf \
		$(ROOTETCMAILCF)/cf/sendmail.mc \
		$(ROOTETCMAILCF)/cf/submit.cf \
		$(ROOTETCMAILCF)/cf/submit.mc \
		$(ROOTETCMAILCF)/domain/generic.m4 \
		$(ROOTETCMAILCF)/domain/solaris-antispam.m4 \
		$(ROOTETCMAILCF)/domain/solaris-generic.m4 \
		$(ROOTETCMAILCF)/feature/accept_unqualified_senders.m4 \
		$(ROOTETCMAILCF)/feature/accept_unresolvable_domains.m4 \
		$(ROOTETCMAILCF)/feature/access_db.m4 \
		$(ROOTETCMAILCF)/feature/allmasquerade.m4 \
		$(ROOTETCMAILCF)/feature/always_add_domain.m4 \
		$(ROOTETCMAILCF)/feature/badmx.m4 \
		$(ROOTETCMAILCF)/feature/bestmx_is_local.m4 \
		$(ROOTETCMAILCF)/feature/bitdomain.m4 \
		$(ROOTETCMAILCF)/feature/blacklist_recipients.m4 \
		$(ROOTETCMAILCF)/feature/block_bad_helo.m4 \
		$(ROOTETCMAILCF)/feature/compat_check.m4 \
		$(ROOTETCMAILCF)/feature/conncontrol.m4 \
		$(ROOTETCMAILCF)/feature/delay_checks.m4 \
		$(ROOTETCMAILCF)/feature/dnsbl.m4 \
		$(ROOTETCMAILCF)/feature/domaintable.m4 \
		$(ROOTETCMAILCF)/feature/enhdnsbl.m4 \
		$(ROOTETCMAILCF)/feature/generics_entire_domain.m4 \
		$(ROOTETCMAILCF)/feature/genericstable.m4 \
		$(ROOTETCMAILCF)/feature/greet_pause.m4 \
		$(ROOTETCMAILCF)/feature/ldap_routing.m4 \
		$(ROOTETCMAILCF)/feature/limited_masquerade.m4 \
		$(ROOTETCMAILCF)/feature/local_lmtp.m4 \
		$(ROOTETCMAILCF)/feature/local_no_masquerade.m4 \
		$(ROOTETCMAILCF)/feature/local_procmail.m4 \
		$(ROOTETCMAILCF)/feature/lookupdotdomain.m4 \
		$(ROOTETCMAILCF)/feature/loose_relay_check.m4 \
		$(ROOTETCMAILCF)/feature/mailertable.m4 \
		$(ROOTETCMAILCF)/feature/masquerade_entire_domain.m4 \
		$(ROOTETCMAILCF)/feature/masquerade_envelope.m4 \
		$(ROOTETCMAILCF)/feature/msp.m4 \
		$(ROOTETCMAILCF)/feature/mtamark.m4 \
		$(ROOTETCMAILCF)/feature/no_default_msa.m4 \
		$(ROOTETCMAILCF)/feature/nocanonify.m4 \
		$(ROOTETCMAILCF)/feature/notsticky.m4 \
		$(ROOTETCMAILCF)/feature/nouucp.m4 \
		$(ROOTETCMAILCF)/feature/nullclient.m4 \
		$(ROOTETCMAILCF)/feature/preserve_local_plus_detail.m4 \
		$(ROOTETCMAILCF)/feature/preserve_luser_host.m4 \
		$(ROOTETCMAILCF)/feature/promiscuous_relay.m4 \
		$(ROOTETCMAILCF)/feature/queuegroup.m4 \
		$(ROOTETCMAILCF)/feature/ratecontrol.m4 \
		$(ROOTETCMAILCF)/feature/redirect.m4 \
		$(ROOTETCMAILCF)/feature/relay_based_on_MX.m4 \
		$(ROOTETCMAILCF)/feature/relay_entire_domain.m4 \
		$(ROOTETCMAILCF)/feature/relay_hosts_only.m4 \
		$(ROOTETCMAILCF)/feature/relay_local_from.m4 \
		$(ROOTETCMAILCF)/feature/relay_mail_from.m4 \
		$(ROOTETCMAILCF)/feature/require_rdns.m4 \
		$(ROOTETCMAILCF)/feature/smrsh.m4 \
		$(ROOTETCMAILCF)/feature/stickyhost.m4 \
		$(ROOTETCMAILCF)/feature/use_client_ptr.m4 \
		$(ROOTETCMAILCF)/feature/use_ct_file.m4 \
		$(ROOTETCMAILCF)/feature/use_cw_file.m4 \
		$(ROOTETCMAILCF)/feature/uucpdomain.m4 \
		$(ROOTETCMAILCF)/feature/virtuser_entire_domain.m4 \
		$(ROOTETCMAILCF)/feature/virtusertable.m4 \
		$(ROOTETCMAILCF)/m4/cf.m4 \
		$(ROOTETCMAILCF)/m4/cfhead.m4 \
		$(ROOTETCMAILCF)/m4/proto.m4 \
		$(ROOTETCMAILCF)/m4/version.m4 \
		$(ROOTETCMAILCF)/mailer/local.m4 \
		$(ROOTETCMAILCF)/mailer/procmail.m4 \
		$(ROOTETCMAILCF)/mailer/smtp.m4 \
		$(ROOTETCMAILCF)/mailer/uucp.m4 \
		$(ROOTETCMAILCF)/ostype/solaris2.m4 \
		$(ROOTETCMAILCF)/ostype/solaris2.ml.m4 \
		$(ROOTETCMAILCF)/ostype/solaris2.pre5.m4 \
		$(ROOTETCMAILCF)/ostype/solaris8.m4 \
		$(ROOTETCMAILCF)/sh/makeinfo.sh

SCRIPTS=	$(ROOTUSRSBIN)/check-hostname \
		$(ROOTUSRSBIN)/check-permissions

.PARALLEL:	$(BUILDPARTS) $(CFS)

FILEMODE=	444
M4FLAGS=	-DSUN_HIDE_INTERNAL_DETAILS

$(BUILDPARTS) := OWNER=root
$(BUILDPARTS) := GROUP=mail

.KEEP_STATE:

all:		$(CFS)

%.cf:	cf/%.cf
	$(CP) $< $@

cf/%.cf:	cf/%.mc $(COMMONM4FILES)
	cd cf; pwd; $(M4) $(M4FLAGS) ../m4/cf.m4 $(<F) > $(@F)

install:	all $(ROOTETCMAILFILES) $(BUILDPARTS) $(SCRIPTS) .WAIT links

clean:
	$(RM) $(CFS) $(SUBCFS)

clobber: 	clean

lint:

$(ROOTETCMAIL)/%.cf: %.cf
	$(INS.file)

$(ROOTETCMAILCF)/%:	%
	$(INS.file)

$(ROOTUSRSBIN)/check-%:	sh/check-%.sh
	$(INS.rename)
	$(CHMOD) +x $@

links:
	$(RM) $(ROOTLIB)/mail
	$(SYMLINK) ../../etc/mail/cf $(ROOTLIB)/mail
	$(RM) $(ROOTETCMAILCF)/sh/check-hostname
	$(SYMLINK) ../../../../usr/sbin/check-hostname $(ROOTETCMAILCF)/sh/check-hostname
	$(RM) $(ROOTETCMAILCF)/sh/check-permissions
	$(SYMLINK) ../../../../usr/sbin/check-permissions $(ROOTETCMAILCF)/sh/check-permissions
	$(RM) $(ROOTETCMAIL)/main.cf
	$(SYMLINK) sendmail.cf $(ROOTETCMAIL)/main.cf
	$(RM) $(ROOTETCMAIL)/subsidiary.cf
	$(SYMLINK) sendmail.cf $(ROOTETCMAIL)/subsidiary.cf
	$(RM) $(ROOTETCMAILCF)/cf/main.cf
	$(SYMLINK) sendmail.cf $(ROOTETCMAILCF)/cf/main.cf
	$(RM) $(ROOTETCMAILCF)/cf/main.mc
	$(SYMLINK) sendmail.mc $(ROOTETCMAILCF)/cf/main.mc
	$(RM) $(ROOTETCMAILCF)/cf/subsidiary.cf
	$(SYMLINK) sendmail.cf $(ROOTETCMAILCF)/cf/subsidiary.cf
	$(RM) $(ROOTETCMAILCF)/cf/subsidiary.mc
	$(SYMLINK) sendmail.mc $(ROOTETCMAILCF)/cf/subsidiary.mc
