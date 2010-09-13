#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#ident	"%W%	%E% SMI"
#
# Copyright (c) 1999-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
# cmd/cmd-inet/usr.sadm/dhcpmgr/help/Makefile


include $(SRC)/cmd/Makefile.cmd

SUBDIRS =	art

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint
_msg	:=	TARGET= _msg

HELPFILES= 	dhcp_addr_create.html \
		dhcp_addr_del.html \
		dhcp_addr_dup.html \
		dhcp_addr_how.html \
		dhcp_addr_mod.html \
		dhcp_addr_multi.html \
		dhcp_addr_ref.html \
		dhcp_addr_rel.html \
		dhcp_addr_view.html \
		dhcp_addr_wiz.html \
		dhcp_config_wiz.html \
		dhcp_convert_wiz.html \
		dhcp_export_wiz.html \
		dhcp_import_wiz.html \
		dhcp_macro_create.html \
		dhcp_macro_del.html \
		dhcp_macro_dup.html \
		dhcp_macro_how.html \
		dhcp_macro_mod.html \
		dhcp_macro_ref.html \
		dhcp_macro_view.html \
		dhcp_macros_about.html \
		dhcp_main_hlp.html \
		dhcp_main_how.html \
		dhcp_main_idx.html \
		dhcp_main_menus.html \
		dhcp_main_top.html \
		dhcp_net_del.html \
		dhcp_net_ref.html \
		dhcp_net_wiz.html \
		dhcp_option_create.html \
		dhcp_option_del.html \
		dhcp_option_dup.html \
		dhcp_option_how.html \
		dhcp_option_mod.html \
		dhcp_option_ref.html \
		dhcp_option_tags.html \
		dhcp_option_view.html \
		dhcp_relay_choose.html \
		dhcp_relay_config.html \
		dhcp_relay_dis.html \
		dhcp_relay_enable.html \
		dhcp_relay_how.html \
		dhcp_relay_ref.html \
		dhcp_relay_serv.html \
		dhcp_relay_unconfig.html \
		dhcp_server_serv.html \
		dhcp_server_unconfig.html \
		dhcp_solaris_about.html

ROOTHELPDIR=    $(ROOT)/usr/sadm/admin/dhcpmgr/help

ROOTDIRS= 	$(ROOTHELPDIR)

IHELPFILES=	$(HELPFILES:%=$(ROOTHELPDIR)/%)

MSGDIR=		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr/client/help
MSGDIRS =       $(ROOT)/usr/share/lib/locale \
                $(ROOT)/usr/share/lib/locale/com \
                $(ROOT)/usr/share/lib/locale/com/sun \
		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr \
		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr/client \
		$(MSGDIR)

MSGFILES=	$(HELPFILES)
MSGS=		$(MSGFILES:%=$(MSGDIR)/%)

FILEMODE= 0444

$(ROOTHELPDIR)/%: %
	$(INS.file)

.KEEP_STATE:

all: $(HELPFILES) $(SUBDIRS)

install: all $(ROOTDIRS) $(IHELPFILES) $(SUBDIRS)

clean clobber lint:

_msg: $(MSGDIRS) $(MSGS) $(SUBDIRS)

$(MSGDIR)/%: %
	$(INS.file)

$(MSGDIRS):
	$(INS.dir)

$(ROOTDIRS):
	$(INS.dir)

$(SUBDIRS): 	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
