/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AMD64CACHE_H
#define	_AMD64CACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _ASM	/* The remainder of this file is only for assembly files */

/*
 * Copyright (c) 2002 Advanced Micro Devices, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and  use in source and binary  forms, with or
 * without  modification,  are   permitted  provided  that  the
 * following conditions are met:
 *
 * + Redistributions  of source  code  must  retain  the  above
 *   copyright  notice,   this  list  of   conditions  and  the
 *   following disclaimer.
 *
 * + Redistributions  in binary  form must reproduce  the above
 *   copyright  notice,   this  list  of   conditions  and  the
 *   following  disclaimer in  the  documentation and/or  other
 *   materials provided with the distribution.
 *
 * + Neither the  name of Advanced Micro Devices,  Inc. nor the
 *   names  of  its contributors  may  be  used  to endorse  or
 *   promote  products  derived   from  this  software  without
 *   specific prior written permission.
 *
 * THIS  SOFTWARE  IS PROVIDED  BY  THE  COPYRIGHT HOLDERS  AND
 * CONTRIBUTORS AS IS AND  ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING,  BUT NOT  LIMITED TO,  THE IMPLIED  WARRANTIES OF
 * MERCHANTABILITY  AND FITNESS  FOR A  PARTICULAR  PURPOSE ARE
 * DISCLAIMED.  IN  NO  EVENT  SHALL  ADVANCED  MICRO  DEVICES,
 * INC.  OR CONTRIBUTORS  BE LIABLE  FOR ANY  DIRECT, INDIRECT,
 * INCIDENTAL,  SPECIAL,  EXEMPLARY,  OR CONSEQUENTIAL  DAMAGES
 * (INCLUDING,  BUT NOT LIMITED  TO, PROCUREMENT  OF SUBSTITUTE
 * GOODS  OR  SERVICES;  LOSS  OF  USE, DATA,  OR  PROFITS;  OR
 * BUSINESS INTERRUPTION)  HOWEVER CAUSED AND ON  ANY THEORY OF
 * LIABILITY,  WHETHER IN CONTRACT,  STRICT LIABILITY,  OR TORT
 * (INCLUDING NEGLIGENCE  OR OTHERWISE) ARISING IN  ANY WAY OUT
 * OF THE  USE  OF  THIS  SOFTWARE, EVEN  IF  ADVISED  OF  THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * It is  licensee's responsibility  to comply with  any export
 * regulations applicable in licensee's jurisdiction.
 *
 * $Header: /K8_Projects/Glibc/amd64cache.h 3     7/28/04 18:13 Emenezes $
 */

	.equiv CPUIDLARGESTFUNCTION,	0	   /* value in EAX */
	.equiv CPUIDVENDORID,		0	   /* string in EBX:EDX:ECX */
	.equiv CPUIDFEATURE,		1	   /* value in EDX */
	.equiv CPUIDSIGNATURE,		1	   /* value in EAX */
	.equiv CPUIDLARGESTFUNCTIONEX,	0x80000000 /* value in EAX */
	.equiv AMDIDSIGNATUREEX,	0x80000001 /* value in EAX */
	.equiv AMDIDFEATUREEX,		0x80000001 /* value in EDX */
	.equiv AMDIDNAME,		0x80000002
	/* string in EAX:EBX:ECX:EDX, also in CPUIDNAME + 1 and CPUIDNAME + 2 */
	.equiv AMDIDL1INFO,		0x80000005
	/* values in EAX, EBX, ECX and EDX */
	.equiv AMDIDL2INFO,		0x80000006
	/* values in EAX, EBX, ECX and EDX */

	.equiv AMDFAMILYK8, 0x0f
	.equiv AMDSTEPK8C0, 0x08

	.equiv AMD64PAGESIZE, 4096
	.equiv AMD64PAGEMASK, 4095

	.extern .amd64cache1, .amd64cache1half, .amd64cache2, .amd64cache2half

	.extern .largest_level_cache_size

	.extern __amd64id

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif /* _AMD64CACHE_H */
