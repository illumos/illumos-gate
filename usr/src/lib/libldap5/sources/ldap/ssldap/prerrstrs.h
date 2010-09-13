/*
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The contents of this file are subject to the Netscape Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/NPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is Mozilla Communicator client code, released
 * March 31, 1998.
 *
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation. Portions created by Netscape are
 * Copyright (C) 1998-1999 Netscape Communications Corporation. All
 * Rights Reserved.
 *
 * Contributor(s):
 */

/*
 * pserrstrs.h - map NSPR errors to strings (used by errormap.c)
 *
 */

/*
 ****************************************************************************
 * The code below this point was provided by Nelson Bolyard <nelsonb> of the
 *	Netscape Certificate Server team on 27-March-1998.
 *	Taken from the file ns/security/cmd/lib/NSPRerrs.h on NSS_1_BRANCH.
 *	Last updated from there: 24-July-1998 by Mark Smith <mcs>
 *
 * All of the Directory Server specific changes are enclosed inside
 *	#ifdef NS_DIRECTORY.
 ****************************************************************************
 */
/* General NSPR 2.0 errors */
/* Caller must #include "prerror.h" */

ER2( PR_OUT_OF_MEMORY_ERROR, 	dgettext(TEXT_DOMAIN,
					"Memory allocation attempt failed.") )
ER2( PR_BAD_DESCRIPTOR_ERROR, 	dgettext(TEXT_DOMAIN,
					"Invalid file descriptor.") )
ER2( PR_WOULD_BLOCK_ERROR, 	dgettext(TEXT_DOMAIN,
					"The operation would have blocked.") )
ER2( PR_ACCESS_FAULT_ERROR, 	dgettext(TEXT_DOMAIN,
					"Invalid memory address argument.") )
ER2( PR_INVALID_METHOD_ERROR, 	dgettext(TEXT_DOMAIN,
					"Invalid function for file type.") )
ER2( PR_ILLEGAL_ACCESS_ERROR, 	dgettext(TEXT_DOMAIN,
					"Invalid memory address argument.") )
ER2( PR_UNKNOWN_ERROR, 		dgettext(TEXT_DOMAIN,
					"Some unknown error has occurred.") )
ER2( PR_PENDING_INTERRUPT_ERROR,dgettext(TEXT_DOMAIN,
					"Operation interrupted by another thread.") )
ER2( PR_NOT_IMPLEMENTED_ERROR, 	dgettext(TEXT_DOMAIN,
					"function not implemented.") )
ER2( PR_IO_ERROR, 		dgettext(TEXT_DOMAIN,
					"I/O function error.") )
ER2( PR_IO_TIMEOUT_ERROR, 	dgettext(TEXT_DOMAIN,
					"I/O operation timed out.") )
ER2( PR_IO_PENDING_ERROR, 	dgettext(TEXT_DOMAIN,
					"I/O operation on busy file descriptor.") )
ER2( PR_DIRECTORY_OPEN_ERROR, 	dgettext(TEXT_DOMAIN,
					"The directory could not be opened.") )
ER2( PR_INVALID_ARGUMENT_ERROR, dgettext(TEXT_DOMAIN,
					"Invalid function argument.") )
ER2( PR_ADDRESS_NOT_AVAILABLE_ERROR, dgettext(TEXT_DOMAIN,
					"Network address not available (in use?).") )
ER2( PR_ADDRESS_NOT_SUPPORTED_ERROR, dgettext(TEXT_DOMAIN,
					"Network address type not supported.") )
ER2( PR_IS_CONNECTED_ERROR, 	dgettext(TEXT_DOMAIN,
					"Already connected.") )
ER2( PR_BAD_ADDRESS_ERROR, 	dgettext(TEXT_DOMAIN,
					"Network address is invalid.") )
ER2( PR_ADDRESS_IN_USE_ERROR, 	dgettext(TEXT_DOMAIN,
					"Local Network address is in use.") )
ER2( PR_CONNECT_REFUSED_ERROR, 	dgettext(TEXT_DOMAIN,
					"Connection refused by peer.") )
ER2( PR_NETWORK_UNREACHABLE_ERROR, dgettext(TEXT_DOMAIN,
					"Network address is presently unreachable.") )
ER2( PR_CONNECT_TIMEOUT_ERROR, 	dgettext(TEXT_DOMAIN,
					"Connection attempt timed out.") )
ER2( PR_NOT_CONNECTED_ERROR, 	dgettext(TEXT_DOMAIN,
					"Network file descriptor is not connected.") )
ER2( PR_LOAD_LIBRARY_ERROR, 	dgettext(TEXT_DOMAIN,
					"Failure to load dynamic library.") )
ER2( PR_UNLOAD_LIBRARY_ERROR, 	dgettext(TEXT_DOMAIN,
					"Failure to unload dynamic library.") )
ER2( PR_FIND_SYMBOL_ERROR, 	dgettext(TEXT_DOMAIN,
					"Symbol not found in any of the loaded dynamic libraries.") )
ER2( PR_INSUFFICIENT_RESOURCES_ERROR, dgettext(TEXT_DOMAIN,
					"Insufficient system resources.") )
ER2( PR_DIRECTORY_LOOKUP_ERROR, 	dgettext(TEXT_DOMAIN,
					"A directory lookup on a network address has failed.") )
ER2( PR_TPD_RANGE_ERROR, 		dgettext(TEXT_DOMAIN,
					"Attempt to access a TPD key that is out of range.") )
ER2( PR_PROC_DESC_TABLE_FULL_ERROR, dgettext(TEXT_DOMAIN,
					"Process open FD table is full.") )
ER2( PR_SYS_DESC_TABLE_FULL_ERROR, dgettext(TEXT_DOMAIN,
					"System open FD table is full.") )
ER2( PR_NOT_SOCKET_ERROR, 	dgettext(TEXT_DOMAIN,
					"Network operation attempted on non-network file descriptor.") )
ER2( PR_NOT_TCP_SOCKET_ERROR, 	dgettext(TEXT_DOMAIN,
					"TCP-specific function attempted on a non-TCP file descriptor.") )
ER2( PR_SOCKET_ADDRESS_IS_BOUND_ERROR, dgettext(TEXT_DOMAIN,
					"TCP file descriptor is already bound.") )
ER2( PR_NO_ACCESS_RIGHTS_ERROR, dgettext(TEXT_DOMAIN,
					"Access Denied.") )
ER2( PR_OPERATION_NOT_SUPPORTED_ERROR, dgettext(TEXT_DOMAIN,
					"The requested operation is not supported by the platform.") )
ER2( PR_PROTOCOL_NOT_SUPPORTED_ERROR, dgettext(TEXT_DOMAIN,
					"The host operating system does not support the protocol requested.") )
ER2( PR_REMOTE_FILE_ERROR, 	dgettext(TEXT_DOMAIN,
					"Access to the remote file has been severed.") )
ER2( PR_BUFFER_OVERFLOW_ERROR, 	dgettext(TEXT_DOMAIN,
					"The value requested is too large to be stored in the data buffer provided.") )
ER2( PR_CONNECT_RESET_ERROR, 	dgettext(TEXT_DOMAIN,
					"TCP connection reset by peer.") )
ER2( PR_RANGE_ERROR, 		dgettext(TEXT_DOMAIN,
					"Unused.") )
ER2( PR_DEADLOCK_ERROR, 	dgettext(TEXT_DOMAIN,
					"The operation would have deadlocked.") )
ER2( PR_FILE_IS_LOCKED_ERROR, 	dgettext(TEXT_DOMAIN,
					"The file is already locked.") )
ER2( PR_FILE_TOO_BIG_ERROR, 	dgettext(TEXT_DOMAIN,
					"Write would result in file larger than the system allows.") )
ER2( PR_NO_DEVICE_SPACE_ERROR, 	dgettext(TEXT_DOMAIN,
					"The device for storing the file is full.") )
ER2( PR_PIPE_ERROR, 		dgettext(TEXT_DOMAIN,
					"Unused.") )
ER2( PR_NO_SEEK_DEVICE_ERROR, 	dgettext(TEXT_DOMAIN,
					"Unused.") )
ER2( PR_IS_DIRECTORY_ERROR, 	dgettext(TEXT_DOMAIN,
					"Cannot perform a normal file operation on a directory.") )
ER2( PR_LOOP_ERROR, 		dgettext(TEXT_DOMAIN,
					"Symbolic link loop.") )
ER2( PR_NAME_TOO_LONG_ERROR, 	dgettext(TEXT_DOMAIN,
					"File name is too long.") )
ER2( PR_FILE_NOT_FOUND_ERROR, 	dgettext(TEXT_DOMAIN,
					"File not found.") )
ER2( PR_NOT_DIRECTORY_ERROR, 	dgettext(TEXT_DOMAIN,
					"Cannot perform directory operation on a normal file.") )
ER2( PR_READ_ONLY_FILESYSTEM_ERROR, dgettext(TEXT_DOMAIN,
					"Cannot write to a read-only file system.") )
ER2( PR_DIRECTORY_NOT_EMPTY_ERROR, dgettext(TEXT_DOMAIN,
					"Cannot delete a directory that is not empty.") )
ER2( PR_FILESYSTEM_MOUNTED_ERROR, dgettext(TEXT_DOMAIN,
					"Cannot delete or rename a file object while the file system is busy.") )
ER2( PR_NOT_SAME_DEVICE_ERROR, 	dgettext(TEXT_DOMAIN,
					"Cannot rename a file to a file system on another device.") )
ER2( PR_DIRECTORY_CORRUPTED_ERROR, dgettext(TEXT_DOMAIN,
					"The directory object in the file system is corrupted.") )
ER2( PR_FILE_EXISTS_ERROR, 	dgettext(TEXT_DOMAIN,
					"Cannot create or rename a filename that already exists.") )
ER2( PR_MAX_DIRECTORY_ENTRIES_ERROR, dgettext(TEXT_DOMAIN,
					"Directory is full.  No additional filenames may be added.") )
ER2( PR_INVALID_DEVICE_STATE_ERROR, dgettext(TEXT_DOMAIN,
					"The required device was in an invalid state.") )
ER2( PR_DEVICE_IS_LOCKED_ERROR, dgettext(TEXT_DOMAIN,
					"The device is locked.") )
ER2( PR_NO_MORE_FILES_ERROR, 	dgettext(TEXT_DOMAIN,
					"No more entries in the directory.") )
ER2( PR_END_OF_FILE_ERROR, 	dgettext(TEXT_DOMAIN,
					"Encountered end of file.") )
ER2( PR_FILE_SEEK_ERROR, 	dgettext(TEXT_DOMAIN,
					"Seek error.") )
ER2( PR_FILE_IS_BUSY_ERROR, 	dgettext(TEXT_DOMAIN,
					"The file is busy.") )
ER2( PR_IN_PROGRESS_ERROR, dgettext(TEXT_DOMAIN,
					"Operation is still in progress (probably a non-blocking connect).") )
ER2( PR_ALREADY_INITIATED_ERROR, dgettext(TEXT_DOMAIN,
					"Operation has already been initiated (probably a non-blocking connect).") )

#ifdef PR_GROUP_EMPTY_ERROR
ER2( PR_GROUP_EMPTY_ERROR, 	dgettext(TEXT_DOMAIN,
					"The wait group is empty.") )
#endif

#ifdef PR_INVALID_STATE_ERROR
ER2( PR_INVALID_STATE_ERROR, 	dgettext(TEXT_DOMAIN,
					"Object state improper for request.") )
#endif

ER2( PR_MAX_ERROR, 		"Placeholder for the end of the list" )
