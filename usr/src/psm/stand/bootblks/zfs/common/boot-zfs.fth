\
\ CDDL HEADER START
\
\ The contents of this file are subject to the terms of the
\ Common Development and Distribution License (the "License").
\ You may not use this file except in compliance with the License.
\
\ You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
\ or http://www.opensolaris.org/os/licensing.
\ See the License for the specific language governing permissions
\ and limitations under the License.
\
\ When distributing Covered Code, include this CDDL HEADER in each
\ file and include the License file at usr/src/OPENSOLARIS.LICENSE.
\ If applicable, add the following below this CDDL HEADER, with the
\ fields enclosed by brackets "[]" replaced with your own identifying
\ information: Portions Copyright [yyyy] [name of copyright owner]
\
\ CDDL HEADER END
\
\
\ Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
\ Use is subject to license terms.
\


purpose: ZFS bootblock
copyright: Copyright 2009 Sun Microsystems, Inc. All Rights Reserved

\ big bootblk
create bigbootblk
d# 16384  constant  /fs-fcode

\ Set the offset to the correct zfs boot block area. This area is at offset 512K
d# 512 d# 1024 * constant  fs-offset

\ for [ifdef] zfs
create zfs

: fs-pkg$   " zfs-file-system"  ;
: fs-type$  " zfs"  ;

\ load common words
fload ../../../common/util.fth

\ load booter
fload ../../../common/boot.fth
