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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# There should be a mapfile here
MAPFILES =

CPPFLAGS	+= -I$(SRC)/lib/libpicl -I$(SRC)/lib/libpicltree
CPPFLAGS	+= -I$(SRC)/cmd/picl/plugins/inc
CFLAGS		+= $(CCVERBOSE)
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-char-subscripts
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-variable

# Some picl plugins have dependencies to which they make no reference.  These
# dependencies are expected to be loaded so that their .init's fire and thus
# populate the picl database before the dependency itself adds to the database.
# Turn off lazy loading so that all plugin dependencies are loaded.  
DYNFLAGS	+= $(ZNOLAZYLOAD)

ROOTLIBDIR := DIRMODE=	0755

FILEMODE=	0755
DIRMODE=	0755

ROOT_PLATFORM := DIRMODE= 0755

ROOT_PLAT_LIBDIR = $(ROOT_PLATFORM)/lib
ROOT_PLAT_LIBDIR := DIRMODE= 0755

ROOT_PLAT_PICLDIR = $(ROOT_PLAT_LIBDIR)/picl
ROOT_PLAT_PICLDIR := DIRMODE= 0755

ROOT_PLAT_PLUGINDIR = $(ROOT_PLAT_PICLDIR)/plugins
ROOT_PLAT_PLUGINDIR := DIRMODE= 0755

USR_LIB_PICLDIR = $(ROOT)/usr/lib/picl
USR_LIB_PLUGINDIR = $(USR_LIB_PICLDIR)/plugins
