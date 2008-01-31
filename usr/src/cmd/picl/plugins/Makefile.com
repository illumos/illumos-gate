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

# There should be a mapfile here
MAPFILES =

CPPFLAGS	+= -I$(SRC)/lib/libpicl -I$(SRC)/lib/libpicltree
CPPFLAGS	+= -I$(SRC)/cmd/picl/plugins/inc
CFLAGS		+= $(CCVERBOSE)

# Some picl plugins have dependencies to which they make no reference.  These
# dependencies are expected to be loaded so that their .init's fire and thus
# populate the picl database before the dependency itself adds to the database.
# Turn off lazy loading so that all plugin dependencies are loaded.  
DYNFLAGS	+= $(ZNOLAZYLOAD)

ROOTLIBDIR := DIRMODE=	0755
ROOTLIBDIR := OWNER=		root
ROOTLIBDIR := GROUP=		sys

FILEMODE=	0755
DIRMODE=	0755
OWNER=		root
GROUP=		sys

ROOT_PLATFORM := DIRMODE= 0755
ROOT_PLATFORM := OWNER= root
ROOT_PLATFORM := GROUP= sys

ROOT_PLAT_LIBDIR = $(ROOT_PLATFORM)/lib
ROOT_PLAT_LIBDIR := DIRMODE= 0755
ROOT_PLAT_LIBDIR := OWNER= root
ROOT_PLAT_LIBDIR := GROUP= bin

ROOT_PLAT_PICLDIR = $(ROOT_PLAT_LIBDIR)/picl
ROOT_PLAT_PICLDIR := DIRMODE= 0755
ROOT_PLAT_PICLDIR := OWNER= root
ROOT_PLAT_PICLDIR := GROUP= sys

ROOT_PLAT_PLUGINDIR = $(ROOT_PLAT_PICLDIR)/plugins
ROOT_PLAT_PLUGINDIR := DIRMODE= 0755
ROOT_PLAT_PLUGINDIR := OWNER= root
ROOT_PLAT_PLUGINDIR := GROUP= sys

USR_LIB_PICLDIR = $(ROOT)/usr/lib/picl
USR_LIB_PLUGINDIR = $(USR_LIB_PICLDIR)/plugins
