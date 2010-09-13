/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



/*
 * Module:	vfpops.c
 * Synopsis:	Implements virtual file protocol operations
 * Description:
 *
 * This module implements the "Virtual File protocol" operations. These
 * operations are intended to provide very fast access to file data,
 * allowing a file to be accessed in very efficient ways with extremely
 * low-cpu intensive operations. If possible file data is mapped directly
 * into memory allowing the data to be accessed directly. If the data
 * cannot be mapped directly into memory, memory will be allocated and
 * the file data read directly into memory. If that fails currently the
 * file data is not accessible. Other methods of making the file could
 * be implemented in the future (e.g. stdio if all else fails).
 *
 * In general any code that uses stdio to access a file can be changed
 * to use the various "vfp" operations to access a file, with a resulting
 * increase in performance and decrease in cpu time required to access
 * the file contents.
 *
 * Public Methods:
 *
 *   vfpCheckpointFile - Create new VFP that checkpoints existing VFP
 *   vfpCheckpointOpen - open file, allocate storage, return pointer to VFP_T
 *   vfpClose - close file associated with vfp
 *   vfpDecCurrPtr - decrement current character pointer
 *   vfpGetBytesRemaining - get number of bytes remaining to read
 *   vfpGetCurrCharPtr - get pointer to current character
 *   vfpGetCurrPtrDelta - get number of bytes between current and specified char
 *   vfpGetFirstCharPtr - get pointer to first character
 *   vfpGetLastCharPtr - get pointer to last character
 *   vfpGetModifiedLen - get highest modified byte (length) contained in vfp
 *   vfpGetPath - get the path associated with the vfp
 *   vfpGetc - get current character and increment to next
 *   vfpGetcNoInc - get current character - do not increment
 *   vfpGets - get a string from the vfp into a fixed size buffer
 *   vfpIncCurrPtr - increment current character pointer
 *   vfpIncCurrPtrBy - increment current pointer by specified delta
 *   vfpOpen - open file on vfp
 *   vfpPutBytes - put fixed number of bytes to current character and increment
 *   vfpPutFormat - put format one arg to current character and increment
 *   vfpPutInteger - put integer to current character and increment
 *   vfpPutLong - put long to current character and increment
 *   vfpPutc - put current character and increment to next
 *   vfpPuts - put string to current character and increment
 *   vfpRewind - rewind file to first byte
 *   vfpSeekToEnd - seek to end of file
 *   vfpSetCurrCharPtr - set pointer to current character
 *   vfpSetFlags - set flags that affect file access
 *   vfpSetSize - set size of file (for writing)
 *   vfpTruncate - truncate file
 *   vfpWriteToFile - write data contained in vfp to specified file
 */

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <libintl.h>
#include "pkglib.h"
#include "pkgstrct.h"
#include "pkglocale.h"

/*
 * These are internal flags that occupy the high order byte of the VFPFLAGS_T
 * flags element of the vfp. These flags may only occupy the high order order
 * 16 bits of the 32-bit unsigned vfp "flags" object.
 */

#define	_VFP_MMAP	0x00010000	/* mmap used */
#define	_VFP_MALLOC	0x00020000	/* malloc used */
#define	_VFP_WRITE	0x00040000	/* file opened for write */
#define	_VFP_READ	0x00080000	/* file opened for reading */
#define	_VFP_MODIFIED	0x00100000	/* contents are marked modified */

/* path name given to "anonymous" (string) vfp */

#define	VFP_ANONYMOUS_PATH	"<<string>>"

/* minimum size file to mmap (64mb) */

#define	MIN_MMAP_SIZE	(64*1024)

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	vfpOpen
 * Description:	Open file on vfp, allocate storage, return pointer to VFP_T
 *		that can be used to access/modify file contents.
 * Arguments:	VFP_T **r_vfp - pointer to pointer to VFP_T
 *		char *a_path - path of file to open and associate with this VFP.
 *			- if the path is (char *)NULL then no file is associated
 *			  with this VFP - this is a way to create a fixed length
 *			  string that can be manipulated with the VFP operators.
 *			  Before the VFP can be used "vfpSetSize" must be called
 *			  to set the size of the string buffer.
 *		char *a_mode - fopen mode to open the file with
 *		VFPFLAGS_T a_flags - one or more flags to control the operation:
 *			- VFP_NONE - no special flags
 *			- VFP_NEEDNOW - file data needed in memory now
 *			- VFP_SEQUENTIAL - memory will be sequentially accessed
 *			- VFP_RANDOM - memory will be randomly accessed
 *			- VFP_NOMMAP - do not use mmap to access file
 *			- VFP_NOMALLOC - do not use malloc to buffer file
 * Returns:	int	== 0 - operation was successful
 *			!= 0 - operation failed, errno contains reason
 * Side Effects: r_vfp -- filled in with a pointer to a newly allocated vfp
 *			which can be used with the various vfp functions.
 *		errno -- contains system error number if return is != 0
 */

int
vfpOpen(VFP_T **r_vfp, char *a_path, char *a_mode, VFPFLAGS_T a_flags)
{
	FILE		*fp = (FILE *)NULL;
	VFP_T		*vfp;
	int		lerrno;
	struct stat	statbuf;
	int		pagesize = getpagesize();

	/* reset return VFP/FILE pointers */

	(*r_vfp) = (VFP_T *)NULL;

	/* allocate pre-zeroed vfp object */

	vfp = (VFP_T *)calloc(sizeof (VFP_T), 1);
	if (vfp == (VFP_T *)NULL) {
		return (-1);
	}

	/* create "string" vfp if no path specified */

	if (a_path == (char *)NULL) {
		/*
		 * no path specified - no open file associated with vfp
		 * The vfp is initialized to all zeros - initialize just those
		 * values that need to be non-zero.
		 */

		vfp->_vfpFlags = _VFP_MALLOC;
		vfp->_vfpPath = strdup(VFP_ANONYMOUS_PATH);
		(*r_vfp) = vfp;
		return (0);
	}

	/*
	 * path specified - associate open file with vfp;
	 * return an error if no path or mode specified
	 */

	if (a_mode == (char *)NULL) {
		errno = EFAULT;		/* Bad address */
		(void) free(vfp);
		return (-1);
	}

	/* return an error if an empty path or mode specified */

	if ((*a_path == '\0') || (*a_mode == '\0')) {
		errno = EINVAL;		/* Invalid argument */
		(void) free(vfp);
		return (-1);
	}

	/* open the file */

	fp = fopen(a_path, a_mode);
	if (fp == (FILE *)NULL) {
		lerrno = errno;
		(void) free(vfp);
		errno = lerrno;
		return (-1);
	}

	/* Get the file size */

	if (fstat(fileno(fp), &statbuf) != 0) {
		lerrno = errno;
		(void) fclose(fp);
		(void) free(vfp);
		errno = lerrno;
		return (-1);
	}

	/*
	 * Obtain access to existing file contents:
	 *  -> plan a: map contents file into memory
	 *  -> plan b: on failure just read into large buffer
	 */

	/* attempt to mmap file if mmap is allowed */

	vfp->_vfpStart = MAP_FAILED;	/* assume map failed if not allowed */

	/*
	 * if file is a regular file, and if mmap allowed,
	 * and (malloc not forbidden or size is > minumum size to mmap)
	 */

	if ((S_ISREG(statbuf.st_mode)) && (!(a_flags & VFP_NOMMAP)) &&
		((a_flags & VFP_NOMALLOC) || statbuf.st_size > MIN_MMAP_SIZE)) {
		char *p;
		/* set size to current size of file */

		vfp->_vfpMapSize = statbuf.st_size;

		/*
		 * compute proper size for mapping for the file contents;
		 * add in one extra page so falling off end when file size is
		 * exactly modulo page size does not cause a page fault to
		 * guarantee that the end of the file contents will always
		 * contain a '\0' null character.
		 */

		vfp->_vfpSize = (statbuf.st_size + pagesize +
				(pagesize-(statbuf.st_size % pagesize)));

		/*
		 * mmap allowed: mmap file into memory
		 * first allocate space on top of which the mapping can be done;
		 * this way we can guarantee that if the mapping happens to be
		 * an exact multiple of a page size, that there will be at least
		 * one byte past the end of the mapping that can be accessed and
		 * that is guaranteed to be zero.
		 */

		/* allocate backing space */

		p = (char *)memalign(pagesize, vfp->_vfpSize);
		if (p == (char *)NULL) {
			vfp->_vfpStart = MAP_FAILED;
		} else {
			/* guarantee first byte after end of data is zero */

			p[vfp->_vfpMapSize] = '\0';

			/* map file on top of the backing space */

			vfp->_vfpStart = mmap(p, vfp->_vfpMapSize, PROT_READ,
				MAP_PRIVATE|MAP_FIXED, fileno(fp), (off_t)0);

			/* if mmap succeeded set mmap used flag in vfp */

			if (vfp->_vfpStart != MAP_FAILED) {
				vfp->_vfpFlags |= _VFP_MMAP;
			}
		}
	}

	/* if map failed (or not allowed) attempt malloc (if allowed) */

	if ((vfp->_vfpStart == MAP_FAILED) && (!(a_flags & VFP_NOMALLOC))) {
		/* mmap failed - plan b: read directly into memory */
		ssize_t	rlen;

		/*
		 * compute proper size for allocating storage for file contents;
		 * add in one extra page so falling off end when file size is
		 * exactly modulo page size does not cause a page fault to
		 * guarantee that the end of the file contents will always
		 * contain a '\0' null character.
		 */

		vfp->_vfpSize = statbuf.st_size+pagesize;

		/* allocate buffer to hold file data */

		vfp->_vfpStart = memalign((size_t)pagesize, vfp->_vfpSize);
		if (vfp->_vfpStart == (char *)NULL) {
			lerrno = errno;
			(void) fclose(fp);
			(void) free(vfp);
			errno = lerrno;
			return (-1);
		}

		/* read the file into the buffer */

		if (statbuf.st_size != 0) {
			rlen = read(fileno(fp), vfp->_vfpStart,
							statbuf.st_size);
			if (rlen != statbuf.st_size) {
				lerrno = errno;
				if (lerrno == 0) {
					lerrno = EIO;
				}
				(void) free(vfp->_vfpStart);
				(void) fclose(fp);
				(void) free(vfp);
				errno = lerrno;
				return (-1);
			}

			/* assure last byte+1 is null character */

			((char *)vfp->_vfpStart)[statbuf.st_size] = '\0';
		}

		/* set malloc used flag in vfp */

		vfp->_vfpFlags |= _VFP_MALLOC;
	}

	/* if no starting address all read methods failed */

	if (vfp->_vfpStart == MAP_FAILED) {
		/* no mmap() - no read() - cannot allocate memory */
		(void) fclose(fp);
		(void) free(vfp);
		errno = ENOMEM;
		return (-1);
	}

	/*
	 * initialize vfp contents
	 */

	/* _vfpCurr -> next byte to read */
	vfp->_vfpCurr = (char *)vfp->_vfpStart;

	/* _vfpEnd -> last data byte */
	vfp->_vfpEnd = (((char *)vfp->_vfpStart) + statbuf.st_size)-1;

	/* _vfpHighWater -> last byte written */
	vfp->_vfpHighWater = (char *)vfp->_vfpEnd;

	/* _vfpFile -> associated FILE* object */
	vfp->_vfpFile = fp;

	/* set flags as appropriate */

	(void) vfpSetFlags(vfp, a_flags);

	/* retain path name */

	vfp->_vfpPath = strdup(a_path ? a_path : "");

	/* set read/write flags */

	if (*a_mode == 'w') {
		vfp->_vfpFlags |= _VFP_WRITE;
	}

	if (*a_mode == 'r') {
		vfp->_vfpFlags |= _VFP_READ;
	}

	/* set return vfp pointer */

	(*r_vfp) = vfp;

	/* All OK */

	return (0);
}

/*
 * Name:	vfpClose
 * Description:	Close an open vfp, causing any modified data to be written out
 *		to the file associated with the vfp.
 * Arguments:	VFP_T **r_vfp - pointer to pointer to VFP_T returned by vfpOpen
 * Returns:	int	== 0 - operation was successful
 *			!= 0 - operation failed, errno contains reason
 * Side Effects: r_vfp is set to (VFP_T)NULL
 */

int
vfpClose(VFP_T **r_vfp)
{
	int	ret;
	int	lerrno;
	VFP_T	*vfp;

	/* return error if NULL VFP_T** provided */

	if (r_vfp == (VFP_T **)NULL) {
		errno = EFAULT;
		return (-1);
	}

	/* localize access to VFP_T */

	vfp = *r_vfp;

	/* return successful if NULL VFP_T* provided */

	if (vfp == (VFP_T *)NULL) {
		return (0);
	}

	/* reset return VFP_T* handle */

	*r_vfp = (VFP_T *)NULL;

	/*
	 * if closing a file that is open for writing, commit all data if the
	 * backing memory is volatile and if there is a file open to write
	 * the data to.
	 */

	if (vfp->_vfpFlags & _VFP_WRITE) {
		if ((vfp->_vfpFlags & _VFP_MALLOC) &&
				(vfp->_vfpFile != (FILE *)NULL)) {
			size_t	len;

			/* determine number of bytes to write */
			len = vfpGetModifiedLen(vfp);

			/* if modified bytes present commit data to the file */
			if (len > 0) {
				(void) vfpSafePwrite(fileno(vfp->_vfpFile),
						vfp->_vfpStart, len, (off_t)0);
			}
		}
	}

	/* deallocate any allocated storage/mappings/etc */

	if (vfp->_vfpFlags & _VFP_MALLOC) {
		(void) free(vfp->_vfpStart);
	} else if (vfp->_vfpFlags & _VFP_MMAP) {
		/* unmap the file mapping */

		(void) munmap(vfp->_vfpStart, vfp->_vfpMapSize);

		/* free the backing allocation */

		(void) free(vfp->_vfpStart);
	}

	/* free up path */

	(void) free(vfp->_vfpPath);

	/* close the file */

	ret = 0;
	if (vfp->_vfpFile != (FILE *)NULL) {
		ret = fclose(vfp->_vfpFile);
		lerrno = errno;
	}

	/* deallocate the vfp itself */

	(void) free(vfp);

	/* if the fclose() failed, return error and errno */

	if (ret != 0) {
		errno = lerrno;
		return (-1);
	}

	return (0);
}

/*
 * Name:	vfpSetFlags
 * Description:	Modify operation of VFP according to flags specified
 * Arguments:	VFP_T *a_vfp - VFP_T pointer associated with file to set flags
 *		VFPFLAGS_T a_flags - one or more flags to control the operation:
 *			- VFP_NEEDNOW - file data needed in memory now
 *			- VFP_SEQUENTIAL - file data sequentially accessed
 *			- VFP_RANDOM - file data randomly accessed
 *			Any other flags specified are silently ignored.
 * Returns:	int	== 0 - operation was successful
 *			!= 0 - operation failed, errno contains reason
 */

int
vfpSetFlags(VFP_T *a_vfp, VFPFLAGS_T a_flags)
{
	/* return if no vfp specified */

	if (a_vfp == (VFP_T *)NULL) {
		return (0);
	}

	/* if file data mapped into memory, apply vm flags */

	if ((a_vfp->_vfpSize != 0) && (a_vfp->_vfpFlags & _VFP_MMAP)) {
		/* mmap succeeded: properly advise vm system */

		if (a_flags & VFP_NEEDNOW) {
			/* advise vm system data is needed now */
			(void) madvise(a_vfp->_vfpStart, a_vfp->_vfpMapSize,
							MADV_WILLNEED);
		}
		if (a_flags & VFP_SEQUENTIAL) {
			/* advise vm system data access is sequential */
			(void) madvise(a_vfp->_vfpStart, a_vfp->_vfpSize,
							MADV_SEQUENTIAL);
		}
		if (a_flags & VFP_RANDOM) {
			/* advise vm system data access is random */
			(void) madvise(a_vfp->_vfpStart, a_vfp->_vfpSize,
							MADV_RANDOM);
		}
	}

	return (0);
}

/*
 * Name:	vfpRewind
 * Description:	Reset default pointer for next read/write to start of file data
 * Arguments:	VFP_T *a_vfp - VFP_T pointer associated with file to rewind
 * Returns:	void
 *			Operation is always successful
 */

void
vfpRewind(VFP_T *a_vfp)
{
	/* return if no vfp specified */

	if (a_vfp == (VFP_T *)NULL) {
		return;
	}

	/* set high water mark of last modified data */

	if (a_vfp->_vfpCurr > a_vfp->_vfpHighWater) {
		a_vfp->_vfpHighWater = a_vfp->_vfpCurr;
	}

	/* reset next character pointer to start of file data */

	a_vfp->_vfpCurr = a_vfp->_vfpStart;
}

/*
 * Name:	vfpSetSize
 * Description:	Set size of in-memory image associated with VFP
 * Arguments:	VFP_T *a_vfp - VFP_T pointer associated with file to set
 *		size_t a_size - number of bytes to associatge with VFP
 * Returns:	int	== 0 - operation was successful
 *			!= 0 - operation failed, errno contains reason
 * Side Effects:
 *		Currently only a file that is in malloc()ed memory can
 *		have its in-memory size changed.
 *		An error is returned If the file is mapped into memory.
 *		A file cannot be decreased in size - if the specified
 *		size is less than the current size, the operation is
 *		successful but no change in file size occurs.
 *		If no file is associated with the VFP (no "name" was
 *		given to vfpOpen) the first call to vfpSetSize allocates
 *		the initial size of the file data - effectively calling
 *		"malloc" to allocate the initial memory for the file data.
 *		Once an initial allocation has been made, subsequent calls
 *		to vfpSetSize are effectively a "realloc" of the existing
 *		file data.
 *		All existing file data is preserved.
 */

int
vfpSetSize(VFP_T *a_vfp, size_t a_size)
{
	char	*np;
	size_t	curSize;

	/* return if no vfp specified */

	if (a_vfp == (VFP_T *)NULL) {
		return (0);
	}

	/* if malloc not used don't know how to set size right now */

	if (!(a_vfp->_vfpFlags & _VFP_MALLOC)) {
		return (-1);
	}

	/* adjust size to reflect extra page of data maintained */

	a_size += getpagesize();

	/* if size is not larger than current nothing to do */

	if (a_size <= a_vfp->_vfpSize) {
		return (0);
	}

	/* remember new size */

	curSize = a_vfp->_vfpSize;
	a_vfp->_vfpSize = a_size;

	/* allocate/reallocate memory as appropriate */

	if (a_vfp->_vfpStart != (char *)NULL) {
		np = (char *)realloc(a_vfp->_vfpStart, a_vfp->_vfpSize+1);
		if (np == (char *)NULL) {
			return (-1);
		}
		np[curSize-1] = '\0';
	} else {
		np = (char *)malloc(a_vfp->_vfpSize+1);
		if (np == (char *)NULL) {
			return (-1);
		}
		np[0] = '\0';
	}

	/* make sure last allocated byte is a null */

	np[a_vfp->_vfpSize] = '\0';

	/*
	 * adjust all pointers to account for buffer address change
	 */

	/* _vfpCurr -> next byte to read */
	a_vfp->_vfpCurr = (char *)(((ptrdiff_t)a_vfp->_vfpCurr -
					(ptrdiff_t)a_vfp->_vfpStart) + np);

	/* _vfpHighWater -> last byte written */
	a_vfp->_vfpHighWater = (char *)(((ptrdiff_t)a_vfp->_vfpHighWater -
					(ptrdiff_t)a_vfp->_vfpStart) + np);

	/* _vfpEnd -> last data byte */
	a_vfp->_vfpEnd = (np + a_vfp->_vfpSize)-1;

	/* _vfpStart -> first data byte */
	a_vfp->_vfpStart = np;

	return (0);
}

/*
 * Name:	vfpTruncate
 * Description:	Truncate data associated with VFP
 * Arguments:	VFP_T *a_vfp - VFP_T pointer associated with file to truncate
 * Returns:	void
 *			Operation is always successful.
 * Side Effects:
 *		In memory data associated with file is believed to be empty.
 *		Actual memory associated with file is not affected.
 *		If a file is associated with the VFP, it is truncated.
 */

void
vfpTruncate(VFP_T *a_vfp)
{
	/* return if no vfp specified */

	if (a_vfp == (VFP_T *)NULL) {
		return;
	}

	/*
	 * reset all pointers so that no data is associated with file
	 */

	/* current byte is start of data area */

	a_vfp->_vfpCurr = a_vfp->_vfpStart;

	/* last byte written is start of data area */

	a_vfp->_vfpHighWater = a_vfp->_vfpStart;

	/* current character is NULL */

	*a_vfp->_vfpCurr = '\0';

	/* if file associated with VFP, truncate actual file */

	if (a_vfp->_vfpFile != (FILE *)NULL) {
		(void) ftruncate(fileno(a_vfp->_vfpFile), 0);
	}
}

/*
 * Name:	vfpWriteToFile
 * Description:	Write data associated with VFP to specified file
 * Arguments:	VFP_T *a_vfp - VFP_T pointer associated with file to write
 *		char *a_path - path of file to write file data to
 * Returns:	int	== 0 - operation was successful
 *			!= 0 - operation failed, errno contains reason
 */

int
vfpWriteToFile(VFP_T *a_vfp, char *a_path)
{
	int	fd;
	int	lerrno = 0;
	size_t	len;
	ssize_t	result = 0;

	/* return if no vfp specified */

	if (a_vfp == (VFP_T *)NULL) {
		errno = EFAULT;
		return (-1);
	}

	/* on buffer overflow generate error */

	if ((a_vfp->_vfpOverflow != 0) || (vfpGetBytesAvailable(a_vfp) < 1)) {
		errno = EFBIG;
		return (-1);
	}

	/* open file to write data to */

	fd = open(a_path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd < 0) {
		return (-1);
	}

	/* determine number of bytes to write */

	len = vfpGetModifiedLen(a_vfp);

	/*
	 * if there is data associated with the file, write it out;
	 * if an error occurs, close the file and return failure.
	 */

	if (len > 0) {
		result = vfpSafeWrite(fd, a_vfp->_vfpStart, len);
		if (result != len) {
			/* error comitting data - return failure */
			lerrno = errno;
			(void) close(fd);
			errno = lerrno;
			return (-1);
		}
	}

	/* close the file */

	(void) close(fd);

	/* data committed to backing store - clear the modified flag */

	(void) vfpClearModified(a_vfp);

	/* return success */

	return (0);
}

/*
 * Name:	vfpCheckpointFile
 * Description:	Create new VFP that checkpoints existing VFP, can be used by
 *		subsequent call to vfpCheckpointOpen to open a file using the
 *		existing in-memory cache of the contents of the file
 * Arguments:	VFP_T **r_cpVfp - pointer to pointer to VFP_T to be filled in
 *			with "checkpointed file" VFP (backing store)
 *		VFP_T **a_vfp - pointer to pointer to VFP_T returned by vfpOpen
 *			representing the VFP to checkpoint
 *		char *a_path - path to file that is the backing store for the
 *			in-memory data represented by a_vfp - used to verify
 *			that the data in memory is not out of date with respect
 *			to the backing store when vfpCheckpointOpen is called
 *			== (char *)NULL - use path associated with a_vfp
 *				that is, the backing store file in use
 * Returns:	int	== 0 - operation was successful
 *				- r_destVfp contains a pointer to a new VFP that
 *					may be used in a subsequent call to
 *					vfpCheckpointOpen
 *				- the VFP referenced by *a_vfp is free()ed and
 *					must no longer be referenced
 *			!= 0 - operation failed, errno contains reason
 *				- the VFP referenced by *a_vfp is not affected;
 *					the caller may continue to use it
 * Notes:	If the data of a VFP to checkpoint is mmap()ed then this method
 *			returns failure - only malloc()ed data VFPs can be
 *			checkpointed.
 */

int
vfpCheckpointFile(VFP_T **r_cpVfp, VFP_T **a_vfp, char *a_path)
{
	VFP_T		*vfp;		/* newly allocated checkpointed VFP */
	VFP_T		*avfp;		/* local -> to a_vfp */
	struct stat	statbuf;	/* stat(2) info for backing store */

	/* return error if NULL VFP_T** to checkpoint provided */

	if (r_cpVfp == (VFP_T **)NULL) {
		errno = EFAULT;
		return (-1);
	}

	/* reset return checkpoint VFP pointer */

	(*r_cpVfp) = (VFP_T *)NULL;

	/* return error if no VFP to checkpoint specified */

	if (a_vfp == (VFP_T **)NULL) {
		errno = EFAULT;
		return (-1);
	}

	/* localize reference to a_vfp */

	avfp = *a_vfp;

	/* return error if no VFP to checkpoint specified */

	if (avfp == (VFP_T *)NULL) {
		errno = EFAULT;
		return (-1);
	}

	/* on buffer overflow generate error */

	if ((avfp->_vfpOverflow != 0) || (vfpGetBytesAvailable(avfp) < 1)) {
		errno = EFBIG;
		return (-1);
	}

	/* no checkpointing is possible if the existing VFP is mmap()ed */

	if (avfp->_vfpFlags & _VFP_MMAP) {
		errno = EIO;
		return (-1);
	}

	/* if no path specified, grab it from the VFP to checkpoint */

	if ((a_path == (char *)NULL) || (*a_path == '\0')) {
		a_path = avfp->_vfpPath;
	}

	/* backing store required: if VFP is "string" then this is an error */

	if ((a_path == (char *)NULL) ||
				strcmp(a_path, VFP_ANONYMOUS_PATH) == 0) {
		errno = EINVAL;
		return (-1);
	}

	/* Get the VFP to checkpoint (backing store) file size */

	if (stat(a_path, &statbuf) != 0) {
		return (-1);
	}

	/* allocate storage for checkpointed VFP (to return) */

	vfp = (VFP_T *)malloc(sizeof (VFP_T));
	if (vfp == (VFP_T *)NULL) {
		return (-1);
	}

	/*
	 * close any file that is on the VFP to checkpoint (backing store);
	 * subsequent processes can modify the backing store data, and
	 * then when vfpCheckpointOpen is called, either the in-memory
	 * cached data will be used (if backing store unmodified) or else
	 * the in-memory data is released and the backing store is used.
	 */

	if (avfp->_vfpFile != (FILE *)NULL) {
		(void) fclose(avfp->_vfpFile);
		avfp->_vfpFile = (FILE *)NULL;
	}

	/* free any path associated with VFP to checkpoint (backing store) */

	if (avfp->_vfpPath != (char *)NULL) {
		(void) free(avfp->_vfpPath);
		avfp->_vfpPath = (char *)NULL;
	}

	/* copy contents of VFP to checkpoint to checkpointed VFP */

	memcpy(vfp, avfp, sizeof (VFP_T));

	/* free contents of VFP to checkpoint */

	(void) free(avfp);

	/* reset pointer to VFP that has been free'd */

	*a_vfp = (VFP_T *)NULL;

	/* remember path associated with the checkpointed VFP (backing store) */

	vfp->_vfpPath = strdup(a_path);

	/* save tokens that identify the backing store for the in-memory data */

	vfp->_vfpCkDev = statbuf.st_dev;	/* devid holding st_ino inode */
	vfp->_vfpCkIno = statbuf.st_ino;	/* backing store inode */
	vfp->_vfpCkMtime = statbuf.st_mtime;	/* last data modification */
	vfp->_vfpCkSize = statbuf.st_size;	/* backing store size (bytes) */
	vfp->_vfpCkStBlocks = statbuf.st_blocks; /* blocks allocated to file */

	/* pass checkpointed VFP to caller */

	(*r_cpVfp) = vfp;

	/* success! */

	return (0);
}

/*
 * Name:	vfpCheckpointOpen
 * Description:	Open file on vfp, allocate storage, return pointer to VFP_T
 *		that can be used to access/modify file contents. If a VFP_T to
 *		a checkpointed VFP is passed in, and the in memory contents of
 *		the VFP are not out of date with respect to the backing store
 *		file, use the existing in-memory contents - otherwise, discard
 *		the in-memory contents and reopen and reread the file.
 * Arguments:	VFP_T **a_cpVfp - pointer to pointer to VFP_T that represents
 *			checkpointed VFP to use to open the file IF the contents
 *			of the backing store are identical to the in-memory data
 *		VFP_T **r_vfp - pointer to pointer to VFP_T to open file on
 *		char *a_path - path of file to open and associate with this VFP.
 *			- if the path is (char *)NULL then no file is associated
 *			  with this VFP - this is a way to create a fixed length
 *			  string that can be manipulated with the VFP operators.
 *			  Before the VFP can be used "vfpSetSize" must be called
 *			  to set the size of the string buffer.
 *		char *a_mode - fopen mode to open the file with
 *		VFPFLAGS_T a_flags - one or more flags to control the operation:
 *			- VFP_NONE - no special flags
 *			- VFP_NEEDNOW - file data needed in memory now
 *			- VFP_SEQUENTIAL - memory will be sequentially accessed
 *			- VFP_RANDOM - memory will be randomly accessed
 *			- VFP_NOMMAP - do not use mmap to access file
 *			- VFP_NOMALLOC - do not use malloc to buffer file
 * Returns:	int	== 0 - operation was successful
 *			!= 0 - operation failed, errno contains reason
 * Side Effects: r_vfp -- filled in with a pointer to a newly allocated vfp
 *			which can be used with the various VFP functions.
 *		a_cpVfp -- contents reset to zero if used to open the file
 *		errno -- contains system error number if return is != 0
 */

int
vfpCheckpointOpen(VFP_T **a_cpVfp, VFP_T **r_vfp, char *a_path,
	char *a_mode, VFPFLAGS_T a_flags)
{
	FILE		*fp;	/* backing store */
	VFP_T		*cpVfp;	/* local -> to a_cpVfp checkpointed VFP */
	VFP_T		*vfp;	/* new VFP open on checkpointed backing store */
	struct stat	statbuf; /* stat(2) info on backing store */

	/*
	 * if no source VFP, or source VFP empty,
	 * or no backing store, just open file
	 */

	if ((a_cpVfp == (VFP_T **)NULL) || (*a_cpVfp == (VFP_T *)NULL) ||
		((*a_cpVfp)->_vfpStart == (char *)NULL)) {
		(void) vfpClose(a_cpVfp);
		return (vfpOpen(r_vfp, a_path, a_mode, a_flags));
	}

	/* localize access to checkpointed VFP_T (*a_cpVfp) */

	cpVfp = *a_cpVfp;

	/* if no path specified, grab it from the checkpointed VFP */

	if ((a_path == (char *)NULL) || (*a_path == '\0')) {
		a_path = cpVfp->_vfpPath;
	}

	/* return error if no path specified and no path in checkpointed VFP */

	if ((a_path == (char *)NULL) && (*a_path == '\0')) {
		errno = EINVAL;
		return (-1);
	}

	/* if no backing store path, then just open file */

	if (stat(a_path, &statbuf) != 0) {
		(void) vfpClose(a_cpVfp);
		return (vfpOpen(r_vfp, a_path, a_mode, a_flags));
	}

	/*
	 * if backing store tokens do not match checkpointed VFP,
	 * the backing store has been updated since the VFP was checkpointed;
	 * release the in-memory data, and open and read the backing store
	 */

	if ((statbuf.st_size != cpVfp->_vfpCkSize) ||
		(statbuf.st_mtime != cpVfp->_vfpCkMtime) ||
		(statbuf.st_blocks != cpVfp->_vfpCkStBlocks) ||
		(statbuf.st_ino != cpVfp->_vfpCkIno) ||
		(statbuf.st_dev != cpVfp->_vfpCkDev)) {
		(void) vfpClose(a_cpVfp);
		return (vfpOpen(r_vfp, a_path, a_mode, a_flags));
	}

	/*
	 * backing store has not been updated since the VFP was checkpointed;
	 * use the in-memory data without re-reading the backing store; open the
	 * backing store file (if no file already open on the checkpointed VFP)
	 * so there is an open file associated with the in-memory data
	 */

	fp = cpVfp->_vfpFile;
	if (fp == (FILE *)NULL) {
		fp = fopen(a_path, a_mode);
		if (fp == (FILE *)NULL) {
			int	lerrno;

			lerrno = errno;
			(void) vfpClose(a_cpVfp);
			errno = lerrno;
			return (-1);
		}
	}

	/* allocate new VFP object to return as open VFP */

	vfp = (VFP_T *)malloc(sizeof (VFP_T));
	if (vfp == (VFP_T *)NULL) {
		(void) vfpClose(a_cpVfp);
		return (vfpOpen(r_vfp, a_path, a_mode, a_flags));
	}

	/* copy cached checkpointed VFP to new VFP to return */

	(void) memcpy(vfp, cpVfp, sizeof (VFP_T));

	/*
	 * initialize VFP to return contents
	 */

	/* FILE -> file opened on the VFPs backing store */

	vfp->_vfpFile = fp;

	/* release any existing path associated with the VFP */

	if (vfp->_vfpPath != (char *)NULL) {
		(void) free(vfp->_vfpPath);
	}

	/* path associated with the backing store for this VFP */

	vfp->_vfpPath = strdup(a_path);

	/*
	 * data pointers associated with in memory copy of backing store
	 * (such as _vfpHighWater, _vfpEnd, _vfpStart, etc.)
	 * do not need to be modified because we are using the same backing
	 * store as was checkpointed in cpVfp that is pointed to by vfp.
	 */

	/* _vfpCurr -> next byte to read */
	vfp->_vfpCurr = (char *)vfp->_vfpStart;

	/* free checkpointed VFP as it is now open on "vfp" */

	(void) free(cpVfp);

	/* reset callers -> checkpointed VFP */

	(*a_cpVfp) = (VFP_T *)NULL;

	/* set return VFP pointer */

	(*r_vfp) = vfp;

	/* success! */

	return (0);
}

/*
 * Name:	vfpClearModified
 * Description:	Clear the "data is modified" indication from the VFP
 * Arguments:	VFP_T *a_vfp - VFP_T pointer associated with file to clear
 *			the "data is modified" indication
 * Returns:	int	- previous setting of "data is modified" indication
 *			== 0 - "data is modified" was NOT previously set
 *			!= 0 - "data is modified" WAS previously set
 */

int
vfpClearModified(VFP_T *a_vfp)
{
	VFPFLAGS_T	flags;

	/* save current flags settings */

	flags = a_vfp->_vfpFlags;

	/* clear "data is modified" flag */

	a_vfp->_vfpFlags &= (~_VFP_MODIFIED);

	/* return previous "data is modified" flag setting */

	return ((flags & _VFP_MODIFIED) != 0);
}

/*
 * Name:	vfpSetModified
 * Description:	Set the "data is modified" indication from the VFP
 * Arguments:	VFP_T *a_vfp - VFP_T pointer associated with file to set
 *			the "data is modified" indication
 * Returns:	int	- previous setting of "data is modified" indication
 *			== 0 - "data is modified" was NOT previously set
 *			!= 0 - "data is modified" WAS previously set
 */

int
vfpSetModified(VFP_T *a_vfp)
{
	VFPFLAGS_T	flags;

	/* save current flags settings */

	flags = a_vfp->_vfpFlags;

	/* set "data is modified" flag */

	a_vfp->_vfpFlags |= _VFP_MODIFIED;

	/* return previous "data is modified" flag setting */

	return ((flags & _VFP_MODIFIED) != 0);
}

/*
 * Name:	vfpGetModified
 * Description:	Get the "data is modified" indication from the VFP
 * Arguments:	VFP_T *a_vfp - VFP_T pointer associated with file to get
 *			the "data is modified" indication
 * Returns:	int	- current setting of "data is modified" indication
 *			== 0 - "data is modified" is NOT set
 *			!= 0 - "data is modified" IS set
 */

int
vfpGetModified(VFP_T *a_vfp)
{
	/* return current "data is modified" flag setting */

	return ((a_vfp->_vfpFlags & _VFP_MODIFIED) != 0);
}

/*
 * Name:	vfpSafeWrite
 * Description:	write data to open file safely
 * Arguments:	a_fildes - file descriptor to write data to
 *		a_buf - pointer to buffer containing data to write
 *		a_nbyte - number of bytes to write to open file
 * Returns:	int
 *		< 0 - error, errno set
 *		>= 0 - success
 * NOTE: unlike write(2), vfpSafeWrite() handles partial writes, and will
 * ----- restart the write() until all bytes are written, or an error occurs.
 */

ssize_t
vfpSafeWrite(int a_fildes, void *a_buf, size_t a_nbyte)
{
	ssize_t	r;
	size_t	bytes = a_nbyte;

	for (;;) {
		/* write bytes to file */
		r = write(a_fildes, a_buf, a_nbyte);

		/* return error on failure of write() */
		if (r < 0) {
			/* EAGAIN: try again */
			if (errno == EAGAIN) {
				continue;
			}
			/* EINTR: interrupted - try again */
			if (errno == EINTR) {
				continue;
			}
			return (r);
		}

		/* return total bytes written on success */
		if (r >= a_nbyte) {
			return (bytes);
		}

		/* partial write, adjust pointers, call write again */
		a_buf = (void *)((ptrdiff_t)a_buf + (ptrdiff_t)r);
		a_nbyte -= (size_t)r;
	}
}

/*
 * Name:	vfpSafePwrite
 * Description:	write data to open file safely
 * Arguments:	a_fildes - file descriptor to write data to
 *		a_buf - pointer to buffer containing data to write
 *		a_nbyte - number of bytes to write to open file
 *		a_offset - offset into open file to write the first byte to
 * Returns:	int
 *		< 0 - error, errno set
 *		>= 0 - success
 * NOTE: unlike pwrite(2), vfpSafePwrite() handles partial writes, and will
 * ----- restart the pwrite() until all bytes are written, or an error occurs.
 */

ssize_t
vfpSafePwrite(int a_fildes, void *a_buf, size_t a_nbyte, off_t a_offset)
{
	ssize_t	r;
	size_t	bytes = a_nbyte;

	for (;;) {
		/* write bytes to file */
		r = pwrite(a_fildes, a_buf, a_nbyte, a_offset);

		/* return error on failure of write() */
		if (r < 0) {
			/* EAGAIN: try again */
			if (errno == EAGAIN) {
				continue;
			}
			/* EINTR: interrupted - try again */
			if (errno == EINTR) {
				continue;
			}
			return (r);
		}

		/* return total bytes written on success */
		if (r >= a_nbyte) {
			return (bytes);
		}

		/* partial write, adjust pointers, call write again */
		a_buf = (void *)((ptrdiff_t)a_buf + (ptrdiff_t)r);
		a_nbyte -= (size_t)r;
		a_offset += (off_t)r;
	}
}
