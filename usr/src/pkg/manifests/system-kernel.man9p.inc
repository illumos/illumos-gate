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

file path=usr/share/man/man9p/ddi-forceattach.9p
file path=usr/share/man/man9p/inquiry-device-type.9p
file path=usr/share/man/man9p/no-involuntary-power-cycles.9p
file path=usr/share/man/man9p/pm-components.9p
file path=usr/share/man/man9p/pm.9p
file path=usr/share/man/man9p/removable-media.9p
file path=usr/share/man/man9p/size.9p
link path=usr/share/man/man9p/Nblock.9p target=size.9p
link path=usr/share/man/man9p/blksize.9p target=size.9p
link path=usr/share/man/man9p/ddi-no-autodetach.9p target=ddi-forceattach.9p
link path=usr/share/man/man9p/device-blksize.9p target=size.9p
link path=usr/share/man/man9p/device-nblocks.9p target=size.9p
link path=usr/share/man/man9p/inquiry-product-id.9p \
    target=inquiry-device-type.9p
link path=usr/share/man/man9p/inquiry-revision-id.9p \
    target=inquiry-device-type.9p
link path=usr/share/man/man9p/inquiry-serial-no.9p \
    target=inquiry-device-type.9p
link path=usr/share/man/man9p/inquiry-vendor-id.9p \
    target=inquiry-device-type.9p
