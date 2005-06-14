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
# lib/libeti/panel/spec/panel.spec

function	bottom_panel
include		<panel.h>
declaration	int bottom_panel(PANEL *panel)
version		SUNW_1.1
end		

function	del_panel
include		<panel.h>
declaration	int del_panel(PANEL *panel)
version		SUNW_1.1
end		

function	hide_panel
include		<panel.h>
declaration	int hide_panel(PANEL *panel)
version		SUNW_1.1
end		

function	move_panel
include		<panel.h>
declaration	int move_panel(PANEL *panel, int starty, int startx)
version		SUNW_1.1
end		

function	new_panel
include		<panel.h>
declaration	PANEL *new_panel(WINDOW *win)
version		SUNW_1.1
end		

function	panel_above
include		<panel.h>
declaration	PANEL *panel_above(PANEL *panel)
version		SUNW_1.1
end		

function	panel_below
include		<panel.h>
declaration	PANEL *panel_below(PANEL *panel)
version		SUNW_1.1
end		

function	panel_hidden
include		<panel.h>
declaration	int panel_hidden(PANEL *panel)
version		SUNW_1.1
end		

function	panel_userptr
include		<panel.h>
declaration	char * panel_userptr(PANEL *panel)
version		SUNW_1.1
end		

function	panel_window
include		<panel.h>
declaration	WINDOW *panel_window(PANEL *panel)
version		SUNW_1.1
end		

function	set_panel_userptr
include		<panel.h>
declaration	int set_panel_userptr(PANEL *panel, char *ptr)
version		SUNW_1.1
end		

function	show_panel
include		<panel.h>
declaration	int show_panel(PANEL *panel)
version		SUNW_1.1
end		

function	replace_panel
include		<panel.h>
declaration	int replace_panel(PANEL *panel, WINDOW *win)
version		SUNW_1.1
end		

function	top_panel
include		<panel.h>
declaration	int top_panel(PANEL *panel)
version		SUNW_1.1
end		

function	update_panels
include		<panel.h>
declaration	void update_panels(void)
version		SUNW_1.1
end		

function	_Bottom_panel
version		SUNWprivate_1.1
end		

function	_Panel_cnt
version		SUNWprivate_1.1
end		

function	_Top_panel
version		SUNWprivate_1.1
end		

function	_alloc_overlap
version		SUNWprivate_1.1
end		

function	_free_overlap
version		SUNWprivate_1.1
end		

function	_intersect_panel
version		SUNWprivate_1.1
end		

function	_lib_version
version		SUNWprivate_1.1
end		

function	_remove_overlap
version		SUNWprivate_1.1
end		

function	_unlink_obs
version		SUNWprivate_1.1
end		

