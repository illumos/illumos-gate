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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libzoneinfo/spec/zoneinfo.spec

function	get_tz_continents
include		<libzoneinfo.h>
declaration	int get_tz_continents(struct tz_continent **)
version		SUNWprivate_1.1
end		

function	get_tz_countries
include		<libzoneinfo.h>
declaration	int get_tz_countries(struct tz_country **, struct tz_continent *);
version		SUNWprivate_1.1
end		

function	get_timezones_by_country
include		<libzoneinfo.h>
declaration	int get_timezones_by_country(struct tz_timezone **, struct tz_country *);
version		SUNWprivate_1.1
end		

function	conv_gmt
include		<libzoneinfo.h>
declaration	char *conv_gmt(int seconds, int flag);
version		SUNWprivate_1.1
end		

function	get_system_tz
include		<libzoneinfo.h>
declaration	char *get_system_tz(char *root);
version		SUNWprivate_1.1
end		

function	set_system_tz
include		<libzoneinfo.h>
declaration	int set_system_tz(char *tz, char *root);
version		SUNWprivate_1.1
end		

function	free_tz_continents
include		<libzoneinfo.h>
declaration	int free_tz_continents(struct tz_continent *cont);
version		SUNWprivate_1.1
end		

function	free_tz_countries
include		<libzoneinfo.h>
declaration	int free_tz_countries(struct tz_country *country);
version		SUNWprivate_1.1
end		

function	free_timezones
include		<libzoneinfo.h>
declaration	int free_timezones(struct tz_timezone *timezone);
version		SUNWprivate_1.1
end		

function	isvalid_tz
include		<libzoneinfo.h>
declaration	int isvalid_tz(char *timezone, char *root, int flag);
version		SUNWprivate_1.1
end		

