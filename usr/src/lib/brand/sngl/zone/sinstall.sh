#!/bin/ksh -p
#
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2014 Joyent, Inc.  All rights reserved.
#

# Does this brand support reprovisioning?
# jst_reprovision="yes"

# Is a template image optional?
# jst_tmplopt="yes"

. /usr/lib/brand/jcommon/libhooks.ksh

function jcommon_attach_hook
{
	jattach_zone_final_setup
}

. /usr/lib/brand/jcommon/cinstall
