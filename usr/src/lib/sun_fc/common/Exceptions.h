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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_EXCEPTIONS_H
#define	_EXCEPTIONS_H



#include <hbaapi.h>
#include "Handle.h"
#include "HBAPort.h"
#include "Trace.h"
#include <string>

/**
 * @memo	    Superclass for all Exception we'll throw.
 *
 * @doc		    To ensure
 * no uncaught exceptions squeeze through, all exceptions
 * will map to some HBA_STATUS error code so we can easily
 * handle them in catch blocks in our external API.
 */
class HBAException {
public:
    HBAException(HBA_STATUS err) : errorCode(err) {
	Trace log("HBAException");
	log.debug("Error code: %d", err);
	log.stackTrace();
    }
    HBA_STATUS getErrorCode() { return errorCode; }
private:
    HBA_STATUS errorCode;
};


/**
 * @memo	    Represents HBA API "Not Supported" error
 */
class NotSupportedException : public HBAException {
public:
    NotSupportedException() : HBAException(HBA_STATUS_ERROR_NOT_SUPPORTED) { }
};

/**
 * @memo	    Represents HBA API "Invalid Handle" error
 */
class InvalidHandleException : public HBAException {
public:
    InvalidHandleException() : HBAException(HBA_STATUS_ERROR_INVALID_HANDLE) { }
};

/**
 * @memo	    Represents HBA API "Bad Argument" error

 */
class BadArgumentException : public HBAException {
public:
    BadArgumentException() : HBAException(HBA_STATUS_ERROR_ARG) { }
};

/**
 * @memo	    Represents HBA API "Illegal WWN" error
 */
class IllegalWWNException : public HBAException {
public:
    IllegalWWNException() : HBAException(HBA_STATUS_ERROR_ILLEGAL_WWN) { }
};

/**
 * @memo	    Represents HBA API "Illegal Index" error
 */
class IllegalIndexException : public HBAException {
public:
    IllegalIndexException() : HBAException(HBA_STATUS_ERROR_ILLEGAL_INDEX) { }
};

/**
 * @memo	    Represents HBA API "More Data" error
 */
class MoreDataException : public HBAException {
public:
    MoreDataException() : HBAException(HBA_STATUS_ERROR_MORE_DATA) { }
};

/**
 * @memo	    Represents HBA API "Stale Data" error
 */
class StaleDataException : public HBAException {
public:
    StaleDataException() : HBAException(HBA_STATUS_ERROR_STALE_DATA) { }
};

/**
 * @memo	    Represents HBA API "SCSI Check Condition" error
 */
class CheckConditionException : public HBAException {
public:
    CheckConditionException() : HBAException(HBA_STATUS_SCSI_CHECK_CONDITION) { }
};

/**
 * @memo	    Represents HBA API "Busy" error
 */
class BusyException : public HBAException {
public:
    BusyException() : HBAException(HBA_STATUS_ERROR_BUSY) { }
};

/**
 * @memo	    Represents HBA API "Try Again" error
 */
class TryAgainException : public HBAException {
public:
    TryAgainException() : HBAException(HBA_STATUS_ERROR_TRY_AGAIN) { }
};

/**
 * @memo	    Represents HBA API "Unavailable" error
 */
class UnavailableException : public HBAException {
public:
    UnavailableException() : HBAException(HBA_STATUS_ERROR_UNAVAILABLE) { }
};

/**
 * @memo	    Represents HBA API "ELS Rejection" error
 */
class ELSRejectException : public HBAException {
public:
    ELSRejectException() : HBAException(HBA_STATUS_ERROR_ELS_REJECT) { }
};

/**
 * @memo	    Represents HBA API "Invalid Logical Unit Number" error
 */
class InvalidLUNException : public HBAException {
public:
    InvalidLUNException() : HBAException(HBA_STATUS_ERROR_INVALID_LUN) { }
};

/**
 * @memo	    Represents HBA API "Incompatible" error
 */
class IncompatibleException : public HBAException {
public:
    IncompatibleException() : HBAException(HBA_STATUS_ERROR_INCOMPATIBLE) { }
};

/**
 * @memo	    Represents HBA API "Ambiguous WWN" error
 */
class AmbiguousWWNException : public HBAException {
public:
    AmbiguousWWNException() : HBAException(HBA_STATUS_ERROR_AMBIGUOUS_WWN) { }
};

/**
 * @memo	    Represents HBA API "Not a Target" error
 */
class NotATargetException : public HBAException {
public:
    NotATargetException() : HBAException(HBA_STATUS_ERROR_NOT_A_TARGET) { }
};

/**
 * @memo	    Represents HBA API "Unsupported FC4 type" error
 */
class UnsupportedFC4Exception : public HBAException {
public:
    UnsupportedFC4Exception() : HBAException(HBA_STATUS_ERROR_UNSUPPORTED_FC4) { }
};

/**
 * @memo	    Represents HBA API "Incapable" error
 */
class IncapableException : public HBAException {
public:
    IncapableException() : HBAException(HBA_STATUS_ERROR_INCAPABLE) { }
};

/**
 * @memo	    Encapsulate I/O error scenarios.
 *
 * @doc		    If logging is enabled, this will
 * automatically log the failure with as much detail as possible.
 */
class IOError : public HBAException {
public:
    IOError(std::string message);
    IOError(Handle *handle);
    IOError(HBAPort *port);
    IOError(HBAPort *port, uint64_t target);
    IOError(HBAPort *port, uint64_t target, uint64_t lun);
};

/**
 * @memo	    Generic error of unknown type
 *
 * @doc
 * Grab bag for something catastrophic occuring in the internal
 * logic of the VSL.  Hopefully, this should never ever happen.
 */
class InternalError : public HBAException {
public:
    InternalError();
    InternalError(std::string message);
};

#endif /* _EXCEPTIONS_H */
