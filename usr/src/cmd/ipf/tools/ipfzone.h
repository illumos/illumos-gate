/*
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * See the IPFILTER.LICENCE file for details on licensing.
 */

#ifndef	__IPFZONE_H__
#define	__IPFZONE_H__

void getzonearg(int, char *[], const char *);
void getzoneopt(int, char *[], const char *);
int setzone(int);
void setzonename(const char *);
void setzonename_global(const char *);

#endif /* __IPFZONE_H__ */
