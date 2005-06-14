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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_STR_H
#define	_STR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

struct Str
{
	Str();
	Str(const char *str);
	Str(const char *str, int len);
	Str(const Str& rhs);
	virtual ~Str();

	void operator=(const Str& rhs);
	void operator=(const char *str);

	int operator != (const Str& rhs) const;
	int operator == (const Str& rhs) const;

	char& operator[](int index) const;
	Str& operator<<(Str rhs);
	Str& operator<<(long long i);
	Str& operator<<(long i);
	Str& operator<<(int i);
	Str& operator<<(char c);

	// normal "C" strcmp
	int compare(const Str& rhs) const;

	int length(void) const;

	// returns character found or 0x00 if nothing found.
	char tokenize(Str& token, const Str& separators, Str& remainder);
	void resetToken(void);

	const char *peak(void) const;

	void replaceAll(char c, char newc);

private:
	char *str_;
	char *nextTok_;
};

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _STR_H */
