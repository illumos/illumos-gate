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
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2019 Joyent, Inc.
#

BASEPROG = aes_cbc_pad

# Currently, the cbc_pad mechanism is only present in PKCS#11 and
# not KCF, so we do not create _kcf test binaries.
CRYPTO = pkcs
CRYPTO_kcf = $(POUND_SIGN)

include $(SRC)/cmd/Makefile.cmd
include ../Makefile.subdirs
