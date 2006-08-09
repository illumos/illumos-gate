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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# ident	"%Z%%M%	%I%	%E% SMI"

function	MD5Init
include		<md5.h>
declaration	void MD5Init(MD5_CTX *context)
version		SUNW_1.1
end

function	MD5Update
include		<md5.h>
declaration	void MD5Update(MD5_CTX *context, \
				const void *input, \
				unsigned int inputLen)
version		SUNW_1.1
end

function	MD5Final
include		<md5.h>
declaration	void MD5Final(void *digest, MD5_CTX *context)
version		SUNW_1.1
end

function	md5_calc
declaration	void md5_calc(void *output, \
				const void *input, \
				unsigned int inlen)
version		SUNW_1.1
end

function	SHA1Init
include		<sha1.h>
declaration	void SHA1Init(SHA1_CTX *context)
version		SUNW_1.1
end

function	SHA1Update
include		<sha1.h>
declaration	void SHA1Update(SHA1_CTX *context, \
				const void *input, \
				unsigned int inputLen)
version		SUNW_1.1
end

function	SHA1Final
include		<sha1.h>
declaration	void SHA1Final(void *, SHA1_CTX *context)
version		SUNW_1.1
end

function	SHA1Init
include		<sha1.h>
declaration	void SHA1Init(SHA1_CTX *context)
version		SUNW_1.1
end

function	SHA1Update
include		<sha1.h>
declaration	void SHA1Update(SHA1_CTX *context, \
				const void *input, \
				unsigned int inputLen)
version		SUNW_1.1
end

function	SHA1Final
include		<sha1.h>
declaration	void SHA1Final(void *digest, SHA1_CTX *context)
version		SUNW_1.1
end

function	SHA2Init
include		<sha2.h>
declaration	void SHA2Init(uint64_t mech, SHA2_CTX *context)
version		SUNW_1.1
end

function	SHA2Update
include		<sha2.h>
declaration	void SHA2Update(SHA2_CTX *context, \
				const void *input, \
				size_t inputLen)
version		SUNW_1.1
end

function	SHA2Final
include		<sha2.h>
declaration	void SHA2Final(void *digest, SHA2_CTX *context)
version		SUNW_1.1
end

function	SHA256Init
include		<sha2.h>
declaration	void SHA2Init(uint64_t mech, SHA2_CTX *context)
version		SUNW_1.1
end

function	SHA256Update
include		<sha2.h>
declaration	void SHA2Update(SHA2_CTX *context, \
				const void *input, \
				size_t inputLen)
version		SUNW_1.1
end

function	SHA256Final
include		<sha2.h>
declaration	void SHA256Final(void *digest, SHA256_CTX *context)
version		SUNW_1.1
end

function	SHA384Init
include		<sha2.h>
declaration	void SHA384Init(uint64_t mech, SHA384_CTX *context)
version		SUNW_1.1
end

function	SHA384Update
include		<sha2.h>
declaration	void SHA384Update(SHA384_CTX *context, \
				const void *input, \
				size_t inputLen)
version		SUNW_1.1
end

function	SHA384Final
include		<sha2.h>
declaration	void SHA384Final(void *digest, SHA384_CTX *context)
version		SUNW_1.1
end

function	SHA512Init
include		<sha2.h>
declaration	void SHA512Init(uint64_t mech, SHA512_CTX *context)
version		SUNW_1.1
end

function	SHA512Update
include		<sha2.h>
declaration	void SHA512Update(SHA512_CTX *context, \
				const void *input, \
				size_t inputLen)
version		SUNW_1.1
end

function	SHA512Final
include		<sha2.h>
declaration	void SHA512Final(void *digest, SHA512_CTX *context)
version		SUNW_1.1
end

function	MD4Init
include		<md4.h>
declaration	void MD4Init(MD4_CTX *context)
version		SUNW_1.1
end

function	MD4Update
include		<md4.h>
declaration	void MD4Update(MD4_CTX *context, \
				const void *input, \
				unsigned int inputLen)
version		SUNW_1.1
end

function	MD4Final
include		<md4.h>
declaration	void MD4Final(void *digest, MD4_CTX *context)
version		SUNW_1.1
end
