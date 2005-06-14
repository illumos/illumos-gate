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
# lib/libplot/plot/spec/plot.spec

function	arc
include		<plot.h>
declaration	void arc(short x0, short y0, short x1, short y1, \
		    short x2, short y2)
version		SUNW_1.1
end		

function	box
include		<plot.h>
declaration	void box(short x0, short y0, short x1, short y1)
version		SUNW_1.1
end		

function	circle
include		<plot.h>
declaration	void circle(short x, short y, short r)
version		SUNW_1.1
end		

function	closepl
include		<plot.h>
declaration	void closepl(void)
version		SUNW_1.1
end		

function	closevt
include		<plot.h>
declaration	void closevt(void)
version		SUNW_1.1
end		

function	cont
include		<plot.h>
declaration	void cont(short x, short y)
version		SUNW_1.1
end		

function	dot
include		<plot.h>
declaration	void dot(short xi, short yi, short dx, short n, short pat[])
version		SUNWprivate_1.1
end		

function	erase
include		<plot.h>
declaration	void erase(void)
version		SUNW_1.1
end		

function	label
include		<plot.h>
declaration	void label(char *s)
version		SUNW_1.1
end		

function	line
include		<plot.h>
declaration	void line(short x0, short y0, short x1, short y1)
version		SUNW_1.1
end		

function	linemod
include		<plot.h>
declaration	void linemod(char *s)
version		SUNW_1.1
end		

function	move
include		<plot.h>
declaration	void move(short x, short y)
version		SUNW_1.1
end		

function	openpl
include		<plot.h>
declaration	void openpl(void)
version		SUNW_1.1
end		

function	openvt
include		<plot.h>
declaration	void openvt(void)
version		SUNW_1.1
end		

function	point
include		<plot.h>
declaration	void point(short x, short y)
version		SUNW_1.1
end		

function	space
include		<plot.h>
declaration	void space(short x0, short y0, short x1, short y1)
version		SUNW_1.1
end		

function	putsi
version		SUNWprivate_1.1
end		

function	_lib_version
version		SUNWprivate_1.1
end		

