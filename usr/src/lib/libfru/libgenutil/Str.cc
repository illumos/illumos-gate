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

#include <string.h>
#include <stdio.h>

#include "Str.h"

Str::Str()
	: str_(strcpy(new char[strlen("")+1], "")),
    nextTok_(str_)
{}

Str::Str(const char *str)
	: str_(strcpy(new char[strlen(str)+1], str)),
    nextTok_(str_)
{}

Str::Str(const char *str, int len)
	: str_(new char[len+1]),
    nextTok_(str_)
{
	strlcpy(str_, str, len+1);
}

Str::Str(const Str& rhs)
	: str_(strcpy(new char[strlen(rhs.str_)+1], rhs.str_)),
    nextTok_(str_)
{}

Str::~Str()
{
	delete[] str_;
}

void
Str::operator = (const Str& rhs)
{
	delete[] str_;
	str_ = strcpy(new char[strlen(rhs.str_)+1], rhs.str_);
	// pointer arithmetic very BAD I know...
	nextTok_ = str_ + (rhs.nextTok_ - rhs.str_);
}

void
Str::operator = (const char *str)
{
	delete[] str_;
	str_ = strcpy(new char[strlen(str)+1], str);
	nextTok_ = str_;
}

int
Str::operator == (const Str& rhs) const
{
	return (strcmp(str_, rhs.str_) == 0);
}

int
Str::operator != (const Str& rhs) const
{
	return (strcmp(str_, rhs.str_) != 0);
}

char&
Str::operator[](int index) const
{
	return (str_[index]);
}

Str&
Str::operator<<(Str rhs)
{
	char *tmp = new char[strlen(str_)+strlen(rhs.peak())+1];
	strcpy(tmp, str_);
	delete[] str_;
	str_ = tmp;
	strcat(str_, rhs.peak());
	return (*this);
}

Str&
Str::operator<<(long long i)
{
	char msg[256];
	sprintf(msg, "%lld", i);
	return (*this << msg);
}

Str&
Str::operator<<(long i)
{
	char msg[256];
	sprintf(msg, "%ld", i);
	return (*this << msg);
}

Str&
Str::operator<<(int i)
{
	char msg[256];
	sprintf(msg, "%d", i);
	return (*this << msg);
}

Str&
Str::operator<<(char c)
{
	char msg[256];
	sprintf(msg, "%c", c);
	return (*this << msg);
}

// normal "C" strcmp
int
Str::compare(const Str& rhs) const
{
	return (strcmp(str_, rhs.str_));
}

int
Str::length(void) const
{
	return (strlen(str_));
}

char
Str::tokenize(Str& token, const Str& separators, Str& remainder)
{
	int i = 0;
	int j = 0;
	for (i = 0; nextTok_[i] != '\0'; i++) {
		for (j = 0; j < separators.length(); j++) {
			if (nextTok_[i] == separators[j]) {
				Str rc(nextTok_, i);
				token = rc;
				nextTok_ = &(nextTok_[i+1]);
				// Str remain(nextTok_);
				remainder = nextTok_;
				return (separators[j]);
			}
		}
	}

	token = "";
	remainder = nextTok_;
	// remainder = *this;
	// did not find it!
	return ('\0');
}

void
Str::resetToken(void)
{
	nextTok_ = str_;
}

const char *
Str::peak(void) const
{
	return (str_);
}

void
Str::replaceAll(char c, char newc)
{
	for (int i = 0; i < strlen(str_); i++) {
		if (str_[i] == c) {
			str_[i] = newc;
		}
	}
}
// oh look an extra line!!!
