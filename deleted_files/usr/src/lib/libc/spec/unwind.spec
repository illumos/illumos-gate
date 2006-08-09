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
# ident	"%Z%%M%	%I%	%E% SMI"
#

data		_UA_SEARCH_PHASE 
arch		amd64
version		SUNW_1.22
end		

data		_UA_CLEANUP_PHASE 
arch		amd64
version		SUNW_1.22
end		

data		_UA_HANDLER_FRAME 
arch		amd64
version		SUNW_1.22
end		

data		_UA_FORCE_UNWIND 
arch		amd64
version		SUNW_1.22
end		

function	_Unwind_DeleteException
include		<unwind.h>
declaration	void _Unwind_DeleteException( \
			struct _Unwind_Exception *exception_object)
arch		amd64
version		SUNW_1.22
end

function	_SUNW_Unwind_DeleteException
weak		_Unwind_DeleteException
arch		amd64
version		SUNW_1.22
end

function	_Unwind_ForcedUnwind
include		<unwind.h>
declaration	_Unwind_Reason_Code _Unwind_ForcedUnwind( \
			struct _Unwind_Exception *exception_object, \
			_Unwind_Stop_Fn stop, void *stop_parameter)
arch		amd64
version		SUNW_1.22
end

function	_SUNW_Unwind_ForcedUnwind
weak		_Unwind_ForcedUnwind
arch		amd64
version		SUNW_1.22
end

function	_Unwind_GetLanguageSpecificData
include		<unwind.h>
declaration	void *_Unwind_GetLanguageSpecificData( \
			struct _Unwind_Context *context)
arch		amd64
version		SUNW_1.22
end

function	_SUNW_Unwind_GetLanguageSpecificData
weak		_Unwind_GetLanguageSpecificData
arch		amd64
version		SUNW_1.22
end

function	_Unwind_GetRegionStart
include		<unwind.h>
declaration	uint64 _Unwind_GetRegionStart( \
			struct _Unwind_Context *context)
arch		amd64
version		SUNW_1.22
end

function	_SUNW_Unwind_GetRegionStart
weak		_Unwind_GetRegionStart
arch		amd64
version		SUNW_1.22
end

function	_Unwind_RaiseException
include		<unwind.h>
declaration	_Unwind_Reason_Code _Unwind_RaiseException( \
			struct _Unwind_Exception *exception_object)
arch		amd64
version		SUNW_1.22
end

function	_SUNW_Unwind_RaiseException
weak		_Unwind_RaiseException
arch		amd64
version		SUNW_1.22
end

function	_Unwind_Resume
include		<unwind.h>
declaration	void _Unwind_Resume( \
			struct _Unwind_Exception *exception_object)
arch		amd64
version		SUNW_1.22
end

function	_SUNW_Unwind_Resume
weak		_Unwind_Resume
arch		amd64
version		SUNW_1.22
end

function	_Unwind_GetCFA
include		<unwind.h>
declaration	uint64 _Unwind_GetCFA(struct _Unwind_Context *context)
arch		amd64
version		SUNW_1.22
end

function	_SUNW_Unwind_GetCFA
weak		_Unwind_GetCFA
arch		amd64
version		SUNW_1.22
end

function	_Unwind_GetGR
include		<unwind.h>
declaration	uint64 _Unwind_GetGR(struct _Unwind_Context *context, \
			int index)
arch		amd64
version		SUNW_1.22
end

function	_SUNW_Unwind_GetGR
weak		_Unwind_GetGR
arch		amd64
version		SUNW_1.22
end

function	_Unwind_GetIP
include		<unwind.h>
declaration	uint64 _Unwind_GetIP(struct _Unwind_Context *context)
arch		amd64
version		SUNW_1.22
end

function	_SUNW_Unwind_GetIP
weak		_Unwind_GetIP
arch		amd64
version		SUNW_1.22
end

function	_Unwind_SetGR
include		<unwind.h>
declaration	void _Unwind_SetGR(struct _Unwind_Context *context, \
			int index, uint64 new_value)
arch		amd64
version		SUNW_1.22
end

function	_SUNW_Unwind_SetGR
weak		_Unwind_SetGR
arch		amd64
version		SUNW_1.22
end

function	_Unwind_SetIP
include		<unwind.h>
declaration	void _Unwind_SetIP(struct _Unwind_Context *context, \
			uint64 new_value)
arch		amd64
version		SUNW_1.22
end

function	_SUNW_Unwind_SetIP
weak		_Unwind_SetIP
arch		amd64
version		SUNW_1.22
end
