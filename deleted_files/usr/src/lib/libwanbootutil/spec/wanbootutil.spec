#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libwanbootutil/spec/wanbootutil.spec

#
# Note that we do not define prototypes for these APIs as we
# are not generating the ABI libraries. Please do not add any
# prototypes.
#

function	wbku_errinit
version		SUNWprivate_1.1
end

function	wbku_printerr
version		SUNWprivate_1.1
end

function	wbku_retmsg
version		SUNWprivate_1.1
end

function	wbku_str_to_keyattr
version		SUNWprivate_1.1
end

function	wbku_find_key
version		SUNWprivate_1.1
end

function	wbku_write_key
version		SUNWprivate_1.1
end

function	wbku_delete_key
version		SUNWprivate_1.1
end

function	des3_decrypt
version		SUNWprivate_1.1
end

function	cbc_makehandle
version		SUNWprivate_1.1
end

function	des3_encrypt
version		SUNWprivate_1.1
end

function	aes_encrypt
version		SUNWprivate_1.1
end

function	aes_init
version		SUNWprivate_1.1
end

function	des3_fini
version		SUNWprivate_1.1
end

function	cbc_encrypt
version		SUNWprivate_1.1
end

function	cbc_decrypt
version		SUNWprivate_1.1
end

function	aes_decrypt
version		SUNWprivate_1.1
end

function	des3_init
version		SUNWprivate_1.1
end

function	aes_fini
version		SUNWprivate_1.1
end

function	des3_key
version		SUNWprivate_1.1
end

function	des3_keycheck
version		SUNWprivate_1.1
end

function	aes_key
version		SUNWprivate_1.1
end

function	aes_keycheck
version		SUNWprivate_1.1
end

function	HMACInit
version		SUNWprivate_1.1
end

function	HMACUpdate
version		SUNWprivate_1.1
end

function	HMACFinal
version		SUNWprivate_1.1
end

function	wbio_nwrite
version		SUNWprivate_1.1
end

function	wbio_nread
version		SUNWprivate_1.1
end

function	wbio_nread_rand
version		SUNWprivate_1.1
end
