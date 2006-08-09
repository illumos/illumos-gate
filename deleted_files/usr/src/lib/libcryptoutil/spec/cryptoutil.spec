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
# lib/libcryptoutil/spec/cryptoutil.spec

function        cryptodebug
include         <cryptoutil.h>
declaration     void cryptodebug(const char *fmt, ...)
version         SUNWprivate_1.1
end

function        cryptoerror
include         <cryptoutil.h>
declaration     void cryptoerror(int priority, const char *fmt, ...)
version         SUNWprivate_1.1
end

function        cryptodebug_init
include         <cryptoutil.h>
declaration     void cryptodebug_init(const char *prefix)
version         SUNWprivate_1.1
end

function        pkcs11_mech2str
include         <cryptoutil.h>
declaration     char *pkcs11_mech2str(CK_MECHANISM_TYPE mech)
version         SUNWprivate_1.1
end

function        pkcs11_str2mech
include         <cryptoutil.h>
declaration     CK_RV pkcs11_str2mech(char *mech_str, CK_MECHANISM_TYPE_PTR mech)
version         SUNWprivate_1.1
end

function        pkcs11_mech2keytype
include         <cryptoutil.h>
declaration     CK_RV pkcs11_mech2keytype(CK_MECHANISM_TYPE mech_type, CK_KEY_TYPE *ktype)
version         SUNWprivate_1.1
end

function        pkcs11_strerror
include         <cryptoutil.h>
declaration     char *pkcs11_strerror(CK_RV rv)
version         SUNWprivate_1.1
end
function        get_pkcs11conf_info
include         <cryptoutil.h>
declaration     int get_pkcs11conf_info(uentrylist_t **)
version         SUNWprivate_1.1
end

function        tohexstr
include         <cryptoutil.h>
declaration     void tohexstr(uchar_t *bytes, size_t blen, char *hexstr, size_t hexlen)
version         SUNWprivate_1.1
end

function        create_umech
include         <cryptoutil.h>
declaration     umechlist_t *create_umech(char *)
version         SUNWprivate_1.1
end

function        free_umechlist
include         <cryptoutil.h>
declaration     void free_umechlist(umechlist_t *)
version         SUNWprivate_1.1
end

function        free_uentrylist
include         <cryptoutil.h>
declaration     void free_uentrylist(uentrylist_t *)
version         SUNWprivate_1.1
end

function        free_uentry
include         <cryptoutil.h>
declaration     void free_uentry(uentry_t *)
version         SUNWprivate_1.1
end
