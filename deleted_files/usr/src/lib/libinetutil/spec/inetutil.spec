#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libinetutil/spec/inetutil.spec

function        octet_to_hexascii
include		<sys/types.h>
include		<netinet/in.h>
include         <libinetutil.h>
declaration     int octet_to_hexascii(const void *nump, uint_t nlen, \
		    char *bufp, uint_t *blen)
version         SUNWprivate_1.1
end

function        hexascii_to_octet
include		<sys/types.h>
include		<netinet/in.h>
include         <libinetutil.h>
declaration     int hexascii_to_octet(const char *asp, uint_t alen, \
		    void *bufp, uint_t *blen)
version         SUNWprivate_1.1
end

function        get_netmask4
include		<sys/types.h>
include		<netinet/in.h>
include         <libinetutil.h>
declaration	void get_netmask4(const struct in_addr *np, struct in_addr *sp)
version         SUNWprivate_1.1
end

function	ifaddrlist
include		<libinetutil.h>
declaration	int ifaddrlist(struct ifaddrlist **, int, char *);
version         SUNWprivate_1.1
end

function        ifparse_ifspec
include         <libinetutil.h>
declaration	boolean_t ifparse_ifspec(const char *ifname, ifspec_t *ifsp)
version         SUNWprivate_1.1
end

function        iu_tq_create
include         <libinetutil.h>
declaration	iu_tq_t *iu_tq_create(void)
version         SUNWprivate_1.1
end

function        iu_tq_destroy
include         <libinetutil.h>
declaration	void iu_tq_destroy(iu_tq_t *tq)
version         SUNWprivate_1.1
end

function        iu_schedule_timer
include         <libinetutil.h>
declaration	iu_timer_id_t iu_schedule_timer(iu_tq_t *tq, uint32_t sec, iu_tq_callback_t *callback, void *arg)
version         SUNWprivate_1.1
end

function        iu_schedule_timer_ms
include         <libinetutil.h>
declaration	iu_timer_id_t iu_schedule_timer_ms(iu_tq_t *tq, uint64_t ms, iu_tq_callback_t *callback, void *arg)
version         SUNWprivate_1.1
end

function        iu_adjust_timer
include         <libinetutil.h>
declaration	int iu_adjust_timer(iu_tq_t *tq, iu_timer_id_t timer_id, uint32_t sec)
version         SUNWprivate_1.1
end

function        iu_cancel_timer
include         <libinetutil.h>
declaration	int iu_cancel_timer(iu_tq_t *tq, iu_timer_id_t timer_id, void **arg)
version         SUNWprivate_1.1
end

function        iu_expire_timers
include         <libinetutil.h>
declaration	int iu_expire_timers(iu_tq_t *tq)
version         SUNWprivate_1.1
end

function        iu_earliest_timer
include         <libinetutil.h>
declaration	int iu_earliest_timer(iu_tq_t *tq)
version         SUNWprivate_1.1
end

function        iu_eh_create
include         <libinetutil.h>
declaration	iu_eh_t *iu_eh_create(void)
version         SUNWprivate_1.1
end

function        iu_eh_destroy
include         <libinetutil.h>
declaration	void iu_eh_destroy(iu_eh_t *eh)
version         SUNWprivate_1.1
end

function        iu_register_event
include         <libinetutil.h>
declaration	iu_event_id_t iu_register_event(iu_eh_t *eh, int fd, short events, iu_eh_callback_t *callback, void *arg)
version         SUNWprivate_1.1
end

function        iu_unregister_event
include         <libinetutil.h>
declaration	int iu_unregister_event(iu_eh_t *eh, iu_event_id_t event_id, void **arg)
version         SUNWprivate_1.1
end

function        iu_handle_events
include         <libinetutil.h>
declaration	int iu_handle_events(iu_eh_t *eh, iu_tq_t *tq)
version         SUNWprivate_1.1
end

function        iu_stop_handling_events
include         <libinetutil.h>
declaration	void iu_stop_handling_events(iu_eh_t *eh, unsigned int reason)
version         SUNWprivate_1.1
end

function        iu_eh_register_signal
include         <libinetutil.h>
declaration	int iu_eh_register_signal(iu_eh_t *eh, int sig, iu_eh_sighandler_t *handler, void *data)
version         SUNWprivate_1.1
end

function        iu_eh_unregister_signal
include         <libinetutil.h>
declaration	int iu_eh_unregister_signal(iu_eh_t *eh, int sig, void **datap)
version         SUNWprivate_1.1
end
