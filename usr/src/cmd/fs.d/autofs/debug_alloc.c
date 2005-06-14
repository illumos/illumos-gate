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
 * Copyright (c) 1998,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	MALLOC_DEBUG
#include <stdlib.h>
#include <stdio.h>
#include <thread.h>
#include <synch.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <netdb.h>
#include <netdir.h>
#include <rpc/nettype.h>

/*
 * To use debugging facility, compile with * -DMALLOC_DEBUG.
 * You can do this by setting the environment variable
 * MALLOC_DEBUG to "-DMALLOC_DEBUG"
 *
 * To make automountd dump trace records (i.e. make it call check_leaks),
 * run:
 * 	make malloc_dump
 */

struct alloc_list
{
	char type[20];
	void *addr;
	int size;
	char file[80];
	int line;
	struct alloc_list *next;
};

static struct alloc_list *halist = NULL;
static mutex_t alloc_list_lock = DEFAULTMUTEX;

int
add_alloc(char *type, void *addr, size_t size, const char *file, int line)
{
	struct alloc_list *alist = NULL;

	/* allocate the list item */
	alist = (struct alloc_list *)malloc(sizeof (*alist));
	if (alist == NULL) {
		syslog(LOG_ERR, "add_alloc: out of memory\n");
		return (-1);
	}
	strcpy(alist->type, type);
	alist->addr = addr;
	alist->size = size;
	strcpy(alist->file, file);
	alist->line = line;

	/* add it to the head of the list */
	if (halist == NULL)
		alist->next = NULL;
	else
		alist->next = halist;
	halist = alist;
	return (0);
}

int
drop_alloc(const char *type, void *addr, const char *file, int line)
{
	struct alloc_list *alist, *alist_prev;

	alist = halist;
	while (alist != NULL) {
		if (addr == alist->addr) {
			if (alist == halist)
				halist = halist->next;
			else
				alist_prev->next = alist->next;
			free(alist);
			break;
		}
		alist_prev = alist;
		alist = alist->next;
	}

	if (alist == NULL) {
		syslog(LOG_ERR, "*** POSSIBLE CORRUPTION ****\n");
		syslog(LOG_ERR, "\tduplicate free, type %s, at %p in %s/%d\n",
		    type, addr, file, line);
		return (-1);
	}
	return (0);
}

void *
my_malloc(size_t size, const char *file, int line)
{
	void *addr;

	addr = (void *)malloc(size);
	if (addr == NULL)
		return (NULL);
	mutex_lock(&alloc_list_lock);
	add_alloc("MALLOC", addr, size, file, line);
	mutex_unlock(&alloc_list_lock);
	return (addr);
}

void *
my_realloc(void *addr, size_t size, const char *file, int line)
{
	void *ptr;

	ptr = (void *)realloc(addr, size);
	if (ptr == NULL)
		return (NULL);
	mutex_lock(&alloc_list_lock);
	drop_alloc("MALLOC", addr, file, line);
	add_alloc("MALLOC", ptr, size, file, line);
	mutex_unlock(&alloc_list_lock);

	return (ptr);
}

void
my_free(void *addr, const char *file, int line)
{
	mutex_lock(&alloc_list_lock);
	drop_alloc("MALLOC", addr, file, line);
	mutex_unlock(&alloc_list_lock);
	free(addr);
}

char *
my_strdup(const char *straddr, const char *file, int line)
{
	void *addr;
	size_t size;

	addr = strdup(straddr);
	if (addr == NULL)
		return (NULL);
	size = strlen(straddr);
	mutex_lock(&alloc_list_lock);
	add_alloc("STRDUP", addr, size, file, line);
	mutex_unlock(&alloc_list_lock);

	return ((char *)addr);
}

int
my_sethostent(int stay, const char *file, int line)
{
	(void) sethostent(stay);
	mutex_lock(&alloc_list_lock);
	add_alloc("SETHOSTENT", NULL, 0, file, line);
	mutex_unlock(&alloc_list_lock);
	return (0);
}

int
my_endhostent(const char *file, int line)
{
	int ret;

	ret = endhostent();
	if (ret != 0)
		return (ret);
	mutex_lock(&alloc_list_lock);
	drop_alloc("SETHOSTENT", NULL, file, line);
	mutex_unlock(&alloc_list_lock);
	return (ret);
}

void *
my_setnetconfig(const char *file, int line)
{
	void *nconf;

	nconf = setnetconfig();
	if (nconf == NULL)
		return (NULL);
	mutex_lock(&alloc_list_lock);
	add_alloc("SETNETCONFIG", nconf, 0, file, line);
	mutex_unlock(&alloc_list_lock);
	return (nconf);
}

int
my_endnetconfig(void *nconf, const char *file, int line)
{
	int res;

	res = endnetconfig(nconf);
	if (res != 0)
		return (res);
	mutex_lock(&alloc_list_lock);
	drop_alloc("SETNETCONFIG", nconf, file, line);
	mutex_unlock(&alloc_list_lock);
	return (0);
}

void *
my_setnetpath(const char *file, int line)
{
	void *npath;

	npath = setnetpath();
	if (npath == NULL)
		return (NULL);
	mutex_lock(&alloc_list_lock);
	add_alloc("SETNETPATH", npath, 0, file, line);
	mutex_unlock(&alloc_list_lock);
	return (npath);
}

int
my_endnetpath(void *npath, const char *file, int line)
{
	int res;

	res = endnetpath(npath);
	if (res != 0)
		return (res);
	mutex_lock(&alloc_list_lock);
	drop_alloc("SETNETPATH", npath, file, line);
	mutex_unlock(&alloc_list_lock);
	return (0);
}

int
my_netdir_getbyname(
	struct netconfig *tp,
	struct nd_hostserv *serv,
	struct nd_addrlist **addrs,
	const char *file,
	int line)
{
	int res;

	res = netdir_getbyname(tp, serv, addrs);
	if (res != 0)
		return (res);
	mutex_lock(&alloc_list_lock);
	add_alloc("NETDIR_GETBYNAME", *addrs, 0, file, line);
	mutex_unlock(&alloc_list_lock);
	return (0);
}

void
my_netdir_free(void *ptr, int type, const char *file, int line)
{
	netdir_free(ptr, type);
	mutex_lock(&alloc_list_lock);
	drop_alloc("NETDIR_GETBYNAME", ptr, file, line);
	mutex_unlock(&alloc_list_lock);
}

struct hostent *
my_getipnodebyname(
	const char *name,
	int af,
	int flags,
	int *error_num,
	char *file,
	int line)
{
	struct hostent *res;

	res = getipnodebyname(name, af, flags, error_num);
	if (res == NULL)
		return (NULL);
	mutex_lock(&alloc_list_lock);
	add_alloc("GETIPNODEBYNAME", res, 0, file, line);
	mutex_unlock(&alloc_list_lock);
	return (res);
}

void
my_freehostent(struct hostent *hent, char *file, int line)
{
	freehostent(hent);
	mutex_lock(&alloc_list_lock);
	drop_alloc("GETIPNODEBYNAME", hent, file, line);
	mutex_unlock(&alloc_list_lock);
}

struct netconfig *
my_getnetconfigent(char *netid, char *file, int line)
{
	struct netconfig *res;

	res = getnetconfigent(netid);
	if (res == NULL)
		return (NULL);
	mutex_lock(&alloc_list_lock);
	add_alloc("GETNETCONFIGENT", res, 0, file, line);
	mutex_unlock(&alloc_list_lock);
	return (res);
}

void
my_freenetconfigent(struct netconfig *netp, char *file, int line)
{
	freenetconfigent(netp);
	mutex_lock(&alloc_list_lock);
	drop_alloc("GETNETCONFIGENT", netp, file, line);
	mutex_unlock(&alloc_list_lock);
}

void *
my__rpc_setconf(char *nettype, char *file, int line)
{
	void *res;

	res = __rpc_setconf(nettype);
	if (res == NULL)
		return (NULL);
	mutex_lock(&alloc_list_lock);
	add_alloc("RPC_SETCONF", res, 0, file, line);
	mutex_unlock(&alloc_list_lock);
	return (res);
}

void
my__rpc_endconf(void *vhandle, char *file, int line)
{
	__rpc_endconf(vhandle);
	mutex_lock(&alloc_list_lock);
	drop_alloc("RPC_SETCONF", vhandle, file, line);
	mutex_unlock(&alloc_list_lock);
}

extern void flush_caches();
void
_flush_caches()
{
}
#pragma weak    flush_caches = _flush_caches

void
check_leaks(char *filename)
{
	struct alloc_list *alist;

	FILE *fp;
	fp = fopen(filename, "a");
	if (fp == NULL) {
		syslog(LOG_ERR, "check_leaks, could not open file: %s",
			filename);
		return;
	}

	flush_caches();
	fprintf(fp, "*** POSSIBLE LEAKS ****\n");
	mutex_lock(&alloc_list_lock);
	alist = halist;
	while (alist != NULL) {
		fprintf(fp, "\t%s: %d bytes at %p in %s/%d\n",
			alist->type, alist->size, alist->addr,
			alist->file, alist->line);
		alist = alist->next;
	}
	mutex_unlock(&alloc_list_lock);

	(void) fclose(fp);
}
#else
/*
 * To prevent a compiler warning.
 */
static char filler;
#endif
