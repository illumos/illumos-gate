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
# lib/libefi/spec/efi.spec

# EFI reading/writing
function	efi_alloc_and_init
include		<sys/types.h>, <sys/vtoc.h>, <sys/efi_partition.h>
declaration	int efi_alloc_and_init(int, uint32_t, struct dk_gpt **)
version		SUNW_1.1
exception	$return < 0
end		

# EFI reading/writing
function	efi_alloc_and_read
include		<sys/types.h>, <sys/vtoc.h>, <sys/efi_partition.h>
declaration	int efi_alloc_and_read(int, struct dk_gpt **)
version		SUNW_1.1
exception	$return < 0
end		

# EFI reading/writing
function	efi_write
include		<sys/types.h>, <sys/vtoc.h>, <sys/efi_partition.h>
declaration	int efi_write(int , struct dk_gpt *)
version		SUNW_1.1
exception	$return < 0
end		

# EFI reading/writing
function	efi_free
include		<stdlib.h>
declaration	void efi_free(struct dk_gpt *)
version		SUNW_1.1
end		

# EFI type
function	efi_type
include		<sys/vtoc.h>, <errno.h>
declaration	int efi_type(int fd)
version		SUNWprivate_1.1
end

# EFI error check
function	efi_err_check
include		<sys/vtoc.h>, <sys/efi_partition.h>
declaration	void efi_err_check(struct dk_gpt *vtoc)
version		SUNWprivate_1.1
end

# EFI auto sense
function	efi_auto_sense
include 	<sys/vtoc.h>, <sys/efi_partition.h>
declaration	int efi_auto_sense(int fd, struct dk_gpt **vtoc)
version		SUNWprivate_1.1
end
