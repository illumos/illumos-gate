#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#

function	dlpi_mac_type
include		<libdlpi.h>
declaration	const char *dlpi_mac_type(uint_t)
version		SUNWprivate_1.1
end

function	dlpi_open
include		<libdlpi.h>
declaration	int dlpi_open(const char *)
version		SUNWprivate_1.1
end

function	dlpi_close
include		<libdlpi.h>
declaration	int dlpi_close(int)
version		SUNWprivate_1.1
end

function	dlpi_info
include		<libdlpi.h>
declaration	int dlpi_info(int, int, dl_info_ack_t *, \
			union DL_qos_types *, union DL_qos_types *, \
			uint8_t *, size_t *, uint8_t *, size_t *)
version		SUNWprivate_1.1
end

function	dlpi_attach
include		<libdlpi.h>
declaration	int dlpi_attach(int, int, uint_t)
version		SUNWprivate_1.1
end

function	dlpi_detach
include		<libdlpi.h>
declaration	int dlpi_detach(int, int)
version		SUNWprivate_1.1
end

function	dlpi_bind
include		<libdlpi.h>
declaration	int dlpi_bind(int, int, uint_t, uint16_t, boolean_t, \
			uint32_t *, uint32_t *, uint8_t *, size_t *)
version		SUNWprivate_1.1
end

function	dlpi_unbind
include		<libdlpi.h>
declaration	int dlpi_unbind(int, int)
version		SUNWprivate_1.1
end

function	dlpi_enabmulti
include		<libdlpi.h>
declaration	int dlpi_enabmulti(int, int, uint8_t *, size_t)
version		SUNWprivate_1.1
end

function	dlpi_disabmulti
include		<libdlpi.h>
declaration	int dlpi_disabmulti(int, int, uint8_t *, size_t)
version		SUNWprivate_1.1
end

function	dlpi_promiscon
include		<libdlpi.h>
declaration	int dlpi_promiscon(int, int, uint_t)
version		SUNWprivate_1.1
end

function	dlpi_promiscoff
include		<libdlpi.h>
declaration	int dlpi_promiscoff(int, int, uint_t)
version		SUNWprivate_1.1
end

function	dlpi_phys_addr
include		<libdlpi.h>
declaration	int dlpi_phys_addr(int, int, uint_t, uint8_t *, size_t *)
version		SUNWprivate_1.1
end

function	dlpi_set_phys_addr
include		<libdlpi.h>
declaration	int dlpi_set_phys_addr(int, int, uint8_t *, size_t)
version		SUNWprivate_1.1
end

function        dlpi_passive
include         <libdlpi.h>
declaration     void dlpi_passive(int, int)
version         SUNWprivate_1.1
end

function	dlpi_if_open
include		<libdlpi.h>
declaration	int dlpi_if_open(const char *, dlpi_if_attr_t *, boolean_t)
version		SUNWprivate_1.1
end

function	dlpi_if_parse
include		<libdlpi.h>
declaration	int dlpi_if_parse(const char *, char *, int *)
version		SUNWprivate_1.1
end
