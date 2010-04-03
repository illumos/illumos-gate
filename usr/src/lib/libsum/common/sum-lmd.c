/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1996-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                                                                      *
***********************************************************************/
#pragma prototyped

/*
 * sum(3) wrapper for solaris -lmd message digest library
 */

typedef void (*Lmd_init_f)(void*);
typedef void (*Lmd_update_f)(void*, const void*, size_t);
typedef void (*Lmd_final_f)(unsigned char*, void*);

#define	_SUM_LMD_	\
	_SUM_PUBLIC_	\
	_SUM_PRIVATE_	\
	Lmd_init_f	initf; \
	Lmd_update_f	updatef; \
	Lmd_final_f	finalf; \
	unsigned int	datasize; \
	unsigned char	total[64]; \
	unsigned char	data[64];

typedef struct Lmd_s
{
	_SUM_LMD_
	struct
	{
	uintmax_t	context;
	}		context;
} Lmd_t;

static int
lmd_init(Sum_t* p)
{
	Lmd_t*	lmd = (Lmd_t*)p;

	(*lmd->initf)(&lmd->context);
	return 0;
}

static int
lmd_block(Sum_t* p, const void* s, size_t n)
{
	Lmd_t*	lmd = (Lmd_t*)p;

	(*lmd->updatef)(&lmd->context, s, n);
	return 0;
}

static int
lmd_done(Sum_t* p)
{
	register Lmd_t*	lmd = (Lmd_t*)p;
	register int	i;

	(*lmd->finalf)(lmd->data, &lmd->context);
	for (i = 0; i < lmd->datasize; i++)
		lmd->total[i] ^= lmd->data[i];
	return 0;
}

static int
lmd_print(Sum_t* p, Sfio_t* sp, register int flags, size_t scale)
{
	register Lmd_t*		lmd = (Lmd_t*)p;
	register unsigned char*	d;
	register int		i;

	d = (flags & SUM_TOTAL) ? lmd->total : lmd->data;
	for (i = 0; i < lmd->datasize; i++)
		sfprintf(sp, "%02x", d[i]);
	return 0;
}

static int
lmd_data(Sum_t* p, Sumdata_t* data)
{
	Lmd_t*		lmd = (Lmd_t*)p;

	data->size = lmd->datasize;
	data->num = 0;
	data->buf = lmd->data;
	return 0;
}

#if _lib_MD4Init && _hdr_md4

#include <md4.h>

#define md4_description "RFC1320 MD4 message digest. Cryptographically weak. The block count is not printed."
#define md4_options	"[+(version)?md4 (solaris -lmd) 2005-07-26]"
#define md4_match	"md4|MD4"
#define md4_scale	0
#define md4_init	lmd_init
#define md4_block	lmd_block
#define md4_done	lmd_done
#define md4_print	lmd_print
#define md4_data	lmd_data

typedef struct Md4_s
{
	_SUM_LMD_
	MD4_CTX		context;
} Md4_t;

static Sum_t*
md4_open(const Method_t* method, const char* name)
{
	Md4_t*	lmd;

	if (lmd = newof(0, Md4_t, 1, 0))
	{
		lmd->method = (Method_t*)method;
		lmd->name = name;
		lmd->datasize = 16;
		lmd->initf = (Lmd_init_f)MD4Init;
		lmd->updatef = (Lmd_update_f)MD4Update;
		lmd->finalf = (Lmd_final_f)MD4Final;
		md4_init((Sum_t*)lmd);
	}
	return (Sum_t*)lmd;
}

#endif

#if _lib_MD5Init && _hdr_md5

#include <md5.h>

#define md5_description	"RFC1321 MD5 message digest. Cryptographically weak. The block count is not printed."
#define md5_options	"[+(version)?md5 (solaris -lmd) 2005-07-26]"
#define md5_match	"md5|MD5"
#define md5_scale	0
#define md5_init	lmd_init
#define md5_block	lmd_block
#define md5_done	lmd_done
#define md5_print	lmd_print
#define md5_data	lmd_data

typedef struct Md5_s
{
	_SUM_LMD_
	MD5_CTX		context;
} Md5_t;

static Sum_t*
md5_open(const Method_t* method, const char* name)
{
	Md5_t*	lmd;

	if (lmd = newof(0, Md5_t, 1, 0))
	{
		lmd->method = (Method_t*)method;
		lmd->name = name;
		lmd->datasize = 16;
		lmd->initf = (Lmd_init_f)MD5Init;
		lmd->updatef = (Lmd_update_f)MD5Update;
		lmd->finalf = (Lmd_final_f)MD5Final;
		md5_init((Sum_t*)lmd);
	}
	return (Sum_t*)lmd;
}

#endif

#if _lib_SHA1Init && _hdr_sha1

#include <sha1.h>

#define sha1_description "RFC3174 / FIPS 180-1 SHA-1 secure hash algorithm 1. Cryptographically weak. The block count is not printed."
#define sha1_options	"[+(version)?sha1 (solaris -lmd) 2005-07-26]"
#define sha1_match	"sha1|SHA1|sha-1|SHA-1"
#define sha1_scale	0
#define sha1_init	lmd_init
#define sha1_block	lmd_block
#define sha1_done	lmd_done
#define sha1_print	lmd_print
#define sha1_data	lmd_data

typedef struct Sha1_s
{
	_SUM_LMD_
	SHA1_CTX	context;
	unsigned char	pad[1024];	/* XXX: who's bug is it? */
} Sha1_t;

static Sum_t*
sha1_open(const Method_t* method, const char* name)
{
	Sha1_t*	lmd;

	if (lmd = newof(0, Sha1_t, 1, 0))
	{
		lmd->method = (Method_t*)method;
		lmd->name = name;
		lmd->datasize = 20;
		lmd->initf = (Lmd_init_f)SHA1Init;
		lmd->updatef = (Lmd_update_f)SHA1Update;
		lmd->finalf = (Lmd_final_f)SHA1Final;
		sha1_init((Sum_t*)lmd);
	}
	return (Sum_t*)lmd;
}

#endif

#if _lib_SHA2Init && _hdr_sha2

#include <sha2.h>

#define sha256_description "FIPS 180-2 SHA256 secure hash algorithm.  The block count is not printed."
#define sha256_options	"[+(version)?sha256 (solaris -lmd) 2005-07-26]"
#define sha256_match	"sha256|sha-256|SHA256|SHA-256"
#define sha256_scale	0
#define sha256_init	lmd_init
#define sha256_block	lmd_block
#define sha256_done	lmd_done
#define sha256_print	lmd_print
#define sha256_data	lmd_data

typedef struct Sha256_s
{
	_SUM_LMD_
	SHA256_CTX	context;
} Sha256_t;

static Sum_t*
sha256_open(const Method_t* method, const char* name)
{
	Sha256_t*	lmd;

	if (lmd = newof(0, Sha256_t, 1, 0))
	{
		lmd->method = (Method_t*)method;
		lmd->name = name;
		lmd->datasize = 32;
		lmd->initf = (Lmd_init_f)SHA256Init;
		lmd->updatef = (Lmd_update_f)SHA256Update;
		lmd->finalf = (Lmd_final_f)SHA256Final;
		sha256_init((Sum_t*)lmd);
	}
	return (Sum_t*)lmd;
}

#define sha384_description "FIPS 180-2 SHA384 secure hash algorithm.  The block count is not printed."
#define sha384_options	"[+(version)?sha384 (solaris -lmd) 2005-07-26]"
#define sha384_match	"sha384|sha-384|SHA384|SHA-384"
#define sha384_scale	0
#define sha384_init	lmd_init
#define sha384_block	lmd_block
#define sha384_done	lmd_done
#define sha384_print	lmd_print
#define sha384_data	lmd_data

typedef struct Sha384_s
{
	_SUM_LMD_
	SHA384_CTX	context;
} Sha384_t;

static Sum_t*
sha384_open(const Method_t* method, const char* name)
{
	Sha384_t*	lmd;

	if (lmd = newof(0, Sha384_t, 1, 0))
	{
		lmd->method = (Method_t*)method;
		lmd->name = name;
		lmd->datasize = 48;
		lmd->initf = (Lmd_init_f)SHA384Init;
		lmd->updatef = (Lmd_update_f)SHA384Update;
		lmd->finalf = (Lmd_final_f)SHA384Final;
		sha384_init((Sum_t*)lmd);
	}
	return (Sum_t*)lmd;
}

#define sha512_description "FIPS 180-2 SHA512 secure hash algorithm.  The block count is not printed."
#define sha512_options	"[+(version)?sha512 (solaris -lmd) 2005-07-26]"
#define sha512_match	"sha512|sha-512|SHA512|SHA-512"
#define sha512_scale	0
#define sha512_init	lmd_init
#define sha512_block	lmd_block
#define sha512_done	lmd_done
#define sha512_print	lmd_print
#define sha512_data	lmd_data

typedef struct Sha512_s
{
	_SUM_LMD_
	SHA512_CTX	context;
} Sha512_t;

static Sum_t*
sha512_open(const Method_t* method, const char* name)
{
	Sha512_t*	lmd;

	if (lmd = newof(0, Sha512_t, 1, 0))
	{
		lmd->method = (Method_t*)method;
		lmd->name = name;
		lmd->datasize = 64;
		lmd->initf = (Lmd_init_f)SHA512Init;
		lmd->updatef = (Lmd_update_f)SHA512Update;
		lmd->finalf = (Lmd_final_f)SHA512Final;
		sha512_init((Sum_t*)lmd);
	}
	return (Sum_t*)lmd;
}

#endif
