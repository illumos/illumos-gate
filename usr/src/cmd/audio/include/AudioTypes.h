/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1992-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MULTIMEDIA_AUDIOTYPES_H
#define	_MULTIMEDIA_AUDIOTYPES_H

#ifdef NO_EXTERN_C

#ifdef __cplusplus
extern "C" {
#endif

#endif /* NO_EXTERN_C */

#include <math.h>
#include <stdlib.h>
#include <float.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>

#include <audio_hdr.h>

// Types used in the audio API

// Values used for indeterminate size (e.g., data passed through a pipe)
const double		AUDIO_UNKNOWN_TIME = DBL_MAX;

// Error severity
enum AudioSeverity {
	InitMessage,			// debugging message from constructor
	InitFatal,			// fatal error from constructor
	Message,			// debugging message
	Warning,			// non-fatal error
	Error,				// potentially severe error
	Consistency,			// internal consistency warning
	Fatal				// fatal internal error
};

// Used in SetPosition methods
enum Whence { Absolute = 0, Relative = 1, Relative_eof = 2};

// XXX - classes that ought to be defined elsewhere

// A Boolean 'primitive type' with values TRUE and FALSE
// undefine these in case they're defined elsewhere
#undef TRUE
#undef FALSE

// use bool_t 'cause boolean_t is already used under 5.0
// Since 4/93 can't use bool_t cause rpc/types.h typedefs it
// so use aud_bool_t
enum aud_bool_t {FALSE = 0, TRUE = 1};

class Boolean {
private:
	aud_bool_t	value;		// value is TRUE or FALSE
public:
	inline Boolean(aud_bool_t x = FALSE): value(x)	// Constructor
	    { }
	inline Boolean(int x)				// Constructor from int
	    { value = (x == 0) ? FALSE : TRUE; }
	inline Boolean operator=(int x)			// Assignment from int
	    { return (value = (x == 0) ? FALSE : TRUE); }
	inline operator int()				// Cast to integer
	    { return ((value == TRUE) ? 1 : 0); }
	inline Boolean operator!()			// Logical not
	    { return ((value == TRUE) ? FALSE : TRUE); }
};

// A 'primitive type' for file access modes
enum fileaccess_t {
    NoAccess = 0, ReadOnly = 1, WriteOnly = 2, ReadWrite = 3,
    AppendOnly = 6, ReadAppend = 7
};

class FileAccess {
private:
	fileaccess_t	mode;		// combined mode
public:
	FileAccess(fileaccess_t x = NoAccess): mode(x) { }	// Constructor
	inline operator fileaccess_t()			// Cast to enum
	    { return (mode); }
	inline operator int() {				// Cast to integer
	    switch (mode) {
	    case ReadOnly: return (O_RDONLY);
	    case WriteOnly: return (O_WRONLY);
	    case ReadWrite: return (O_RDWR);
	    case AppendOnly: return (O_WRONLY | O_APPEND);
	    case ReadAppend: return (O_RDWR | O_APPEND);
	    case NoAccess:
	    default:
		return (-1);
	    }
	}
	// These tests depend on the actual enum values
	inline Boolean Readable() const			// TRUE if readable
	    { return ((int)mode & 1); }
	inline Boolean Writeable() const		// TRUE if writeable
	    { return ((int)mode & 2); }
	inline Boolean Append() const			// TRUE if append only
	    { return ((int)mode & 4); }
};


// Define a small number corresponding to minor floating-point bit errors
const double		AUDIO_MINFLOAT = .00000001;

// Define a 'double' class that allows some leeway in magnitude checking
// to try to correct for small errors due to floating-point imprecision
class Double {
private:
	double	val;
public:
	Double(double x = 0.): val(x) { }
	Double(const Double &x): val(x.val) { }
	inline int Undefined() const
	    { return (val == AUDIO_UNKNOWN_TIME); }
	inline operator double() const
	    { return (val); }
	inline Double& operator += (double y)
	    { val += y; return (*this); }
	inline Double& operator -= (double y)
	    { val -= y; return (*this); }
};

// inline double fabs(double x)
//    { return ((x >= 0.) ? x : -x); }

inline double min(const Double& x, const Double& y) {
	return (((double)x <  (double)y) ? (double)x : (double)y);
}

inline double min(const Double& x, double y) {
	return (((double)x <  (double)y) ? (double)x : (double)y);
}
inline double min(double x, const Double& y) {
	return (((double)x <  (double)y) ? (double)x : (double)y);
}

inline double max(const Double& x, const Double& y) {
	return (((double)x >  (double)y) ? (double)x : (double)y);
}
inline double max(const Double& x, double y) {
	return (((double)x >  (double)y) ? (double)x : (double)y);
}
inline double max(double x, const Double& y) {
	return (((double)x >  (double)y) ? (double)x : (double)y);
}

inline int operator == (const Double &x, const Double &y) {
	return (fabs((double)x - (double)y) <= AUDIO_MINFLOAT);
}
inline int operator == (const Double &x, double y) {
	return (fabs((double)x - (double)y) <= AUDIO_MINFLOAT);
}
inline int operator == (double x, const Double &y) {
	return (fabs((double)x - (double)y) <= AUDIO_MINFLOAT);
}

inline int operator != (const Double &x, const Double &y) {
	return (!(x == y));
}
inline int operator != (const Double &x, double y) {
	return (!(x == y));
}
inline int operator != (double x, const Double &y) {
	return (!(x == y));
}

inline int operator <= (const Double &x, const Double &y) {
	return (((double)x < (double)y) || (x == y));
}
inline int operator <= (const Double &x, double y) {
	return (((double)x < (double)y) || (x == y));
}
inline int operator <= (double x, const Double &y)
	{ return (((double)x < (double)y) || (x == y)); }

inline int operator >= (const Double &x, const Double &y)
	{ return (((double)x > (double)y) || (x == y)); }
inline int operator >= (const Double &x, double y) {
	return (((double)x > (double)y) || (x == y));
}
inline int operator >= (double x, const Double &y) {
	return (((double)x > (double)y) || (x == y));
}

inline int operator < (const Double &x, const Double &y) {
	return (!(x >= y));
}
inline int operator < (const Double &x, double y) {
	return (!(x >= y));
}
inline int operator < (double x, const Double &y) {
	return (!(x >= y));
}

inline int operator > (const Double &x, const Double &y) {
	return (!(x <= y));
}
inline int operator > (const Double &x, double y) {
	return (!(x <= y));
}
inline int operator > (double x, const Double &y) {
	return (!(x <= y));
}

inline Double& operator += (Double &x, const Double &y) {
	return (x += (double)y);
}
inline double operator += (double &x, const Double &y) {
	return (x += (double)y);
}
inline Double& operator -= (Double &x, const Double &y) {
	return (x -= (double)y);
}
inline double operator -= (double &x, const Double &y) {
	return (x -= (double)y);
}

inline int Undefined(const Double &x) {
	return (x.Undefined());
}
inline int Undefined(double x) {
	return (x == AUDIO_UNKNOWN_TIME);
}

#ifdef NO_EXTERN_C

#ifdef __cplusplus
}
#endif

#endif /* NO_EXTERN_C */

#endif /* !_MULTIMEDIA_AUDIOTYPES_H */
