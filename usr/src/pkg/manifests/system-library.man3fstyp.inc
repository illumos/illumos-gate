#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2012 Nexenta Systems, Inc. All rights reserved.
#

file path=usr/share/man/man3fstyp/fstyp_get_attr.3fstyp
file path=usr/share/man/man3fstyp/fstyp_ident.3fstyp
file path=usr/share/man/man3fstyp/fstyp_init.3fstyp
file path=usr/share/man/man3fstyp/fstyp_mod_init.3fstyp
file path=usr/share/man/man3fstyp/fstyp_strerror.3fstyp
link path=usr/share/man/man3fstyp/fstyp_fini.3fstyp target=fstyp_init.3fstyp
link path=usr/share/man/man3fstyp/fstyp_mod_dump.3fstyp \
    target=fstyp_mod_init.3fstyp
link path=usr/share/man/man3fstyp/fstyp_mod_fini.3fstyp \
    target=fstyp_mod_init.3fstyp
link path=usr/share/man/man3fstyp/fstyp_mod_get_attr.3fstyp \
    target=fstyp_mod_init.3fstyp
link path=usr/share/man/man3fstyp/fstyp_mod_ident.3fstyp \
    target=fstyp_mod_init.3fstyp
