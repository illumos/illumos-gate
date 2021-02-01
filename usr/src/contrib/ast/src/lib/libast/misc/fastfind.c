#pragma prototyped
/*
 * original code
 *
 *  	James A. Woods, Informatics General Corporation,
 *	NASA Ames Research Center, 6/81.
 *	Usenix ;login:, February/March, 1983, p. 8.
 *
 * discipline/method interface
 *
 *	Glenn Fowler
 *	AT&T Research
 *	modified from the original BSD source
 *
 * 'fastfind' scans a file list for the full pathname of a file
 * given only a piece of the name.  The list is processed with
 * with "front-compression" and bigram coding.  Front compression reduces
 * space by a factor of 4-5, bigram coding by a further 20-25%.
 *
 * there are 4 methods:
 *
 *	FF_old	original with 7 bit bigram encoding (no magic)
 *	FF_gnu	8 bit clean front compression (FF_gnu_magic)
 *	FF_dir	FF_gnu with sfgetl/sfputl and trailing / on dirs (FF_dir_magic)
 *	FF_typ	FF_dir with (mime) types (FF_typ_magic)
 *
 * the bigram encoding steals the eighth bit (that's why its FF_old)
 * maybe one day we'll limit it to readonly:
 *
 * 0-2*FF_OFF	 likeliest differential counts + offset to make nonnegative 
 * FF_ESC	 4 byte big-endian out-of-range count+FF_OFF follows
 * FF_MIN-FF_MAX ascii residue
 * >=FF_MAX	 bigram codes
 *
 * a two-tiered string search technique is employed
 *
 * a metacharacter-free subpattern and partial pathname is matched
 * backwards to avoid full expansion of the pathname list
 *
 * then the actual shell glob-style regular expression (if in this form)
 * is matched against the candidate pathnames using the slower regexec()
 *
 * The original BSD code is covered by the BSD license:
 *
 * Copyright (c) 1985, 1993, 1999
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

static const char id[] = "\n@(#)$Id: fastfind (AT&T Research) 2002-10-02 $\0\n";

static const char lib[] = "libast:fastfind";

#include "findlib.h"

#define FIND_MATCH	"*/(find|locate)/*"

/*
 * this db could be anywhere
 * findcodes[] directories are checked for findnames[i]
 */

static char*		findcodes[] =
{
	0,
	0,
	FIND_CODES,
	"/usr/local/share/lib",
	"/usr/local/lib",
	"/usr/share/lib",
	"/usr/lib",
	"/var/spool",
	"/usr/local/var",
	"/var/lib",
	"/var/lib/slocate",
	"/var/db",
};

static char*		findnames[] =
{
	"find/codes",
	"find/find.codes",
	"locate/locatedb",
	"locatedb",
	"locate.database",
	"slocate.db",
};

/*
 * convert t to lower case and drop leading x- and x- after /
 * converted value copied to b of size n
 */

char*
typefix(char* buf, size_t n, register const char* t)
{
	register int	c;
	register char*	b = buf;

	if ((*t == 'x' || *t == 'X') && *(t + 1) == '-')
		t += 2;
	while (c = *t++)
	{
		if (isupper(c))
			c = tolower(c);
		if ((*b++ = c) == '/' && (*t == 'x' || *t == 'X') && *(t + 1) == '-')
			t += 2;
	}
	*b = 0;
	return buf;
}

/*
 * return a fastfind stream handle for pattern
 */

Find_t*
findopen(const char* file, const char* pattern, const char* type, Finddisc_t* disc)
{
	register Find_t*	fp;
	register char*		p;
	register char*		s;
	register char*		b;
	register int		i; 
	register int		j;
	char*			path;
	int			brace = 0;
	int			paren = 0;
	int			k;
	int			q;
	int			fd;
	int			uid;
	Vmalloc_t*		vm;
	Type_t*			tp;
	struct stat		st;


	if (!(vm = vmopen(Vmdcheap, Vmbest, 0)))
		goto nospace;

	/*
	 * NOTE: searching for FIND_CODES would be much simpler if we
	 *       just stuck with our own, but we also support GNU
	 *	 locate codes and have to search for the one of a
	 *	 bazillion possible names for that file
	 */

	if (!findcodes[1])
		findcodes[1] = getenv(FIND_CODES_ENV);
	if (disc->flags & FIND_GENERATE)
	{
		if (!(fp = (Find_t*)vmnewof(vm, 0, Find_t, 1, sizeof(Encode_t) - sizeof(Code_t))))
			goto nospace;
		fp->vm = vm;
		fp->id = lib;
		fp->disc = disc;
		fp->generate = 1;
		if (file && (!*file || streq(file, "-")))
			file = 0;
		uid = geteuid();
		j = (findcodes[0] = (char*)file) && *file == '/' ? 1 : elementsof(findcodes);

		/*
		 * look for the codes file, but since it may not exist yet,
		 * also look for the containing directory if i<2 or if
		 * it is sufficiently qualified (FIND_MATCH)
		 */

		for (i = 0; i < j; i++)
			if (path = findcodes[i])
			{
				if (*path == '/')
				{
					if (!stat(path, &st))
					{
						if (S_ISDIR(st.st_mode))
						{
							for (k = 0; k < elementsof(findnames); k++)
							{
								sfsprintf(fp->encode.file, sizeof(fp->encode.file), "%s/%s", path, findnames[k]);
								if (!eaccess(fp->encode.file, R_OK|W_OK))
								{
									path = fp->encode.file;
									break;
								}
								if (strchr(findnames[k], '/') && (b = strrchr(fp->encode.file, '/')))
								{
									*b = 0;
									if (!stat(fp->encode.file, &st) && st.st_uid == uid && (st.st_mode & S_IWUSR))
									{
										*b = '/';
										path = fp->encode.file;
										break;
									}
								}
							}
							if (k < elementsof(findnames))
								break;
						}
						else if (st.st_uid == uid && (st.st_mode & S_IWUSR))
						{
							sfsprintf(fp->encode.file, sizeof(fp->encode.file), "%s", path);
							path = fp->encode.file;
							break;
						}
					}
					else if (i < 2 || strmatch(path, FIND_MATCH))
					{
						sfsprintf(fp->encode.file, sizeof(fp->encode.file), "%s", path);
						if (b = strrchr(fp->encode.file, '/'))
						{
							*b = 0;
							if (!stat(fp->encode.file, &st) && st.st_uid == uid && (st.st_mode & S_IWUSR))
							{
								*b = '/';
								path = fp->encode.file;
								break;
							}
						}
					}
				}
				else if (pathpath(path, "", PATH_REGULAR|PATH_READ|PATH_WRITE, fp->encode.file, sizeof(fp->encode.file)))
				{
					path = fp->encode.file;
					break;
				}
				else if (b = strrchr(path, '/'))
				{
					sfsprintf(fp->encode.file, sizeof(fp->encode.file), "%-.*s", b - path, path);
					if (pathpath(fp->encode.file, "", PATH_EXECUTE|PATH_READ|PATH_WRITE, fp->encode.temp, sizeof(fp->encode.temp)) &&
					    !stat(fp->encode.temp, &st) && st.st_uid == uid && (st.st_mode & S_IWUSR))
					{
						sfsprintf(fp->encode.file, sizeof(fp->encode.file), "%s%s", fp->encode.temp, b);
						path = fp->encode.file;
						break;
					}
				}
			}
		if (i >= j)
		{
			if (fp->disc->errorf)
				(*fp->disc->errorf)(fp, fp->disc, 2, "%s: cannot locate codes", file ? file : findcodes[2]);
			goto drop;
		}
		if (fp->disc->flags & FIND_OLD)
		{
			/*
			 * FF_old generates temp data that is read
			 * in a second pass to generate the real codes
			 */

			fp->method = FF_old;
			if (!(fp->fp = sftmp(32 * PATH_MAX)))
			{
				if (fp->disc->errorf)
					(*fp->disc->errorf)(fp, fp->disc, ERROR_SYSTEM|2, "cannot create tmp file");
				goto drop;
			}
		}
		else
		{
			/*
			 * the rest generate into a temp file that
			 * is simply renamed on completion
			 */

			if (s = strrchr(path, '/'))
			{
				*s = 0;
				p = path;
			}
			else
				p = ".";
			if (!pathtemp(fp->encode.temp, sizeof(fp->encode.temp), p, "ff", &fd))
			{
				if (fp->disc->errorf)
					(*fp->disc->errorf)(fp, fp->disc, ERROR_SYSTEM|2, "%s: cannot create tmp file in this directory", p ? p : ".");
				goto drop;
			}
			if (s)
				*s = '/';
			if (!(fp->fp = sfnew(NiL, NiL, (size_t)SF_UNBOUND, fd, SF_WRITE)))
			{
				if (fp->disc->errorf)
					(*fp->disc->errorf)(fp, fp->disc, ERROR_SYSTEM|2, "%s: cannot open tmp file", fp->encode.temp);
				close(fd);
				goto drop;
			}
			if (fp->disc->flags & FIND_TYPE)
			{
				fp->method = FF_typ;
				fp->encode.namedisc.key = offsetof(Type_t, name);
				fp->encode.namedisc.link = offsetof(Type_t, byname);
				fp->encode.indexdisc.key = offsetof(Type_t, index);
				fp->encode.indexdisc.size = sizeof(unsigned long);
				fp->encode.indexdisc.link = offsetof(Type_t, byindex);
				s = "system/dir";
				if (!(fp->encode.namedict = dtopen(&fp->encode.namedisc, Dtoset)) || !(fp->encode.indexdict = dtopen(&fp->encode.indexdisc, Dtoset)) || !(tp = newof(0, Type_t, 1, strlen(s) + 1)))
				{
					if (fp->encode.namedict)
						dtclose(fp->encode.namedict);
					if (fp->disc->errorf)
						(*fp->disc->errorf)(fp, fp->disc, 2, "cannot allocate type table");
					goto drop;
				}

				/*
				 * type index 1 is always system/dir
				 */

				tp->index = ++fp->types;
				strcpy(tp->name, s);
				dtinsert(fp->encode.namedict, tp);
				dtinsert(fp->encode.indexdict, tp);
			}
			else if (fp->disc->flags & FIND_GNU)
			{
				fp->method = FF_gnu;
				sfputc(fp->fp, 0);
				sfputr(fp->fp, FF_gnu_magic, 0);
			}
			else
			{
				fp->method = FF_dir;
				sfputc(fp->fp, 0);
				sfputr(fp->fp, FF_dir_magic, 0);
			}
		}
	}
	else
	{
		i = sizeof(Decode_t) + sizeof(Code_t);
		if (!pattern || !*pattern)
			pattern = "*";
		i += (j = 2 * (strlen(pattern) + 1));
		if (!(fp = (Find_t*)vmnewof(vm, 0, Find_t, 1, i)))
		{
			vmclose(vm);
			return 0;
		}
		fp->vm = vm;
		fp->id = lib;
		fp->disc = disc;
		if (disc->flags & FIND_ICASE)
			fp->decode.ignorecase = 1;
		j = (findcodes[0] = (char*)file) && *file == '/' ? 1 : elementsof(findcodes);
		for (i = 0; i < j; i++)
			if (path = findcodes[i])
			{
				if (*path == '/')
				{
					if (!stat(path, &st))
					{
						if (S_ISDIR(st.st_mode))
						{
							for (k = 0; k < elementsof(findnames); k++)
							{
								sfsprintf(fp->decode.path, sizeof(fp->decode.path), "%s/%s", path, findnames[k]);
								if (fp->fp = sfopen(NiL, fp->decode.path, "r"))
								{
									path = fp->decode.path;
									break;
								}
							}
							if (fp->fp)
								break;
						}
						else if (fp->fp = sfopen(NiL, path, "r"))
							break;
					}
				}
				else if ((path = pathpath(path, "", PATH_REGULAR|PATH_READ, fp->decode.path, sizeof(fp->decode.path))) && (fp->fp = sfopen(NiL, path, "r")))
					break;
			}
		if (!fp->fp)
		{
			if (fp->disc->errorf)
				(*fp->disc->errorf)(fp, fp->disc, 2, "%s: cannot locate codes", file ? file : findcodes[2]);
			goto drop;
		}
		if (fstat(sffileno(fp->fp), &st))
		{
			if (fp->disc->errorf)
				(*fp->disc->errorf)(fp, fp->disc, 2, "%s: cannot stat codes", path);
			goto drop;
		}
		if (fp->secure = ((st.st_mode & (S_IRGRP|S_IROTH)) == S_IRGRP) && st.st_gid == getegid() && getegid() != getgid())
			setgid(getgid());
		fp->stamp = st.st_mtime;
		b = (s = fp->decode.temp) + 1;
		for (i = 0; i < elementsof(fp->decode.bigram1); i++) 
		{
			if ((j = sfgetc(fp->fp)) == EOF)
				goto invalid;
			if (!(*s++ = fp->decode.bigram1[i] = j) && i)
			{
				i = -i;
				break;
			}
			if ((j = sfgetc(fp->fp)) == EOF)
				goto invalid;
			if (!(*s++ = fp->decode.bigram2[i] = j) && (i || fp->decode.bigram1[0] >= '0' && fp->decode.bigram1[0] <= '1'))
				break;
		}
		if (streq(b, FF_typ_magic))
		{
			if (type)
			{
				type = (const char*)typefix(fp->decode.bigram2, sizeof(fp->decode.bigram2), type);
				memset(fp->decode.bigram1, 0, sizeof(fp->decode.bigram1));
			}
			fp->method = FF_typ;
			for (j = 0, i = 1;; i++)
			{
				if (!(s = sfgetr(fp->fp, 0, 0)))
					goto invalid;
				if (!*s)
					break;
				if (type && strmatch(s, type))
				{
					FF_SET_TYPE(fp, i);
					j++;
				}
			}
			if (type && !j)
				goto drop;
			fp->types = j;
		}
		else if (streq(b, FF_dir_magic))
			fp->method = FF_dir;
		else if (streq(b, FF_gnu_magic))
			fp->method = FF_gnu;
		else if (!*b && *--b >= '0' && *b <= '1')
		{
			fp->method = FF_gnu;
			while (j = sfgetc(fp->fp))
			{
				if (j == EOF || fp->decode.count >= sizeof(fp->decode.path))
					goto invalid;
				fp->decode.path[fp->decode.count++] = j;
			}
		}
		else
		{
			fp->method = FF_old;
			if (i < 0)
			{
				if ((j = sfgetc(fp->fp)) == EOF)
					goto invalid;
				fp->decode.bigram2[i = -i] = j;
			}
			while (++i < elementsof(fp->decode.bigram1))
			{
				if ((j = sfgetc(fp->fp)) == EOF)
					goto invalid;
				fp->decode.bigram1[i] = j;
				if ((j = sfgetc(fp->fp)) == EOF)
					goto invalid;
				fp->decode.bigram2[i] = j;
			}
			if ((fp->decode.peek = sfgetc(fp->fp)) != FF_OFF)
				goto invalid;
		}

		/*
		 * set up the physical dir table
		 */

		if (disc->version >= 19980301L)
		{
			fp->verifyf = disc->verifyf;
			if (disc->dirs && *disc->dirs)
			{
				for (k = 0; disc->dirs[k]; k++);
				if (k == 1 && streq(disc->dirs[0], "/"))
					k = 0;
				if (k)
				{
					if (!(fp->dirs = vmnewof(fp->vm, 0, char*, 2 * k + 1, 0)))
						goto drop;
					if (!(fp->lens = vmnewof(fp->vm, 0, int, 2 * k, 0)))
						goto drop;
					p = 0;
					b = fp->decode.temp;
					j = fp->method == FF_old || fp->method == FF_gnu;

					/*
					 * fill the dir list with logical and
					 * physical names since we don't know
					 * which way the db was encoded (it
					 * could be *both* ways)
					 */

					for (i = q = 0; i < k; i++)
					{
						if (*(s = disc->dirs[i]) == '/')
							sfsprintf(b, sizeof(fp->decode.temp) - 1, "%s", s);
						else if (!p && !(p = getcwd(fp->decode.path, sizeof(fp->decode.path))))
							goto nospace;
						else
							sfsprintf(b, sizeof(fp->decode.temp) - 1, "%s/%s", p, s);
						s = pathcanon(b, sizeof(fp->decode.temp), 0);
						*s = '/';
						*(s + 1) = 0;
						if (!(fp->dirs[q] = vmstrdup(fp->vm, b)))
							goto nospace;
						if (j)
							(fp->dirs[q])[s - b] = 0;
						q++;
						*s = 0;
						s = pathcanon(b, sizeof(fp->decode.temp), PATH_PHYSICAL);
						*s = '/';
						*(s + 1) = 0;
						if (!strneq(b, fp->dirs[q - 1], s - b))
						{
							if (!(fp->dirs[q] = vmstrdup(fp->vm, b)))
								goto nospace;
							if (j)
								(fp->dirs[q])[s - b] = 0;
							q++;
						}
					}
					strsort(fp->dirs, q, strcasecmp);
					for (i = 0; i < q; i++)
						fp->lens[i] = strlen(fp->dirs[i]);
				}
			}
		}
		if (fp->verifyf || (disc->flags & FIND_VERIFY))
		{
			if (fp->method != FF_dir && fp->method != FF_typ)
			{
				if (fp->disc->errorf)
					(*fp->disc->errorf)(fp, fp->disc, 2, "%s: %s code format does not support directory verification", path, fp->method == FF_gnu ? FF_gnu_magic : "OLD-BIGRAM");
				goto drop;
			}
			fp->verify = 1;
		}

		/*
		 * extract last glob-free subpattern in name for fast pre-match
		 * prepend 0 for backwards match
		 */

		if (p = s = (char*)pattern)
		{
			b = fp->decode.pattern;
			for (;;)
			{
				switch (*b++ = *p++)
				{
				case 0:
					break;
				case '\\':
					s = p;
					if (!*p++)
						break;
					continue;
				case '[':
					if (!brace)
					{
						brace++;
						if (*p == ']')
							p++;
					}
					continue;
				case ']':
					if (brace)
					{
						brace--;
						s = p;
					}
					continue;
				case '(':
					if (!brace)
						paren++;
					continue;
				case ')':
					if (!brace && paren > 0 && !--paren)
						s = p;
					continue;
				case '|':
				case '&':
					if (!brace && !paren)
					{
						s = "";
						break;
					}
					continue;
				case '*':
				case '?':
					s = p;
					continue;
				default:
					continue;
				}
				break;
			}
			if (s != pattern && !streq(pattern, "*"))
			{
				fp->decode.match = 1;
				if (i = regcomp(&fp->decode.re, pattern, REG_SHELL|REG_AUGMENTED|(fp->decode.ignorecase?REG_ICASE:0)))
				{
					if (disc->errorf)
					{
						regerror(i, &fp->decode.re, fp->decode.temp, sizeof(fp->decode.temp));
						(*fp->disc->errorf)(fp, fp->disc, 2, "%s: %s", pattern, fp->decode.temp);
					}
					goto drop;
				}
			}
			if (*s)
			{
				*b++ = 0;
				while (i = *s++)
					*b++ = i;
				*b-- = 0;
				fp->decode.end = b;
				if (fp->decode.ignorecase)
					for (s = fp->decode.pattern; s <= b; s++)
						if (isupper(*s))
							*s = tolower(*s);
			}
		}
	}
	return fp;
 nospace:
	if (disc->errorf)
		(*fp->disc->errorf)(fp, fp->disc, 2, "out of space");
	if (!vm)
		return 0;
	if (!fp)
	{
		vmclose(vm);
		return 0;
	}
	goto drop;
 invalid:
	if (fp->disc->errorf)
		(*fp->disc->errorf)(fp, fp->disc, 2, "%s: invalid codes", path);
 drop:
	if (!fp->generate && fp->decode.match)
		regfree(&fp->decode.re);
	if (fp->fp)
		sfclose(fp->fp);
	vmclose(fp->vm);
	return 0;
}

/*
 * return the next fastfind path
 * 0 returned when list exhausted
 */

char*
findread(register Find_t* fp)
{
	register char*		p;
	register char*		q;
	register char*		s;
	register char*		b;
	register char*		e;
	register int		c;
	register int		n;
	register int		m;
	int			ignorecase;
	int			t;
	unsigned char		w[4];
	struct stat		st;

	if (fp->generate)
		return 0;
	if (fp->decode.restore)
	{
		*fp->decode.restore = '/';
		fp->decode.restore = 0;
	}
	ignorecase = fp->decode.ignorecase ? STR_ICASE : 0;
	c = fp->decode.peek;
 next:
	for (;;)
	{
		switch (fp->method)
		{
		case FF_dir:
			t = 0;
			n = sfgetl(fp->fp);
			goto grab;
		case FF_gnu:
			if ((c = sfgetc(fp->fp)) == EOF)
				return 0;
			if (c == 0x80)
			{
				if ((c = sfgetc(fp->fp)) == EOF)
					return 0;
				n = c << 8;
				if ((c = sfgetc(fp->fp)) == EOF)
					return 0;
				n |= c;
				if (n & 0x8000)
					n = (n - 0xffff) - 1;
			}
			else if ((n = c) & 0x80)
				n = (n - 0xff) - 1;
			t = 0;
			goto grab;
		case FF_typ:
			t = sfgetu(fp->fp);
			n = sfgetl(fp->fp);
		grab:
			p = fp->decode.path + (fp->decode.count += n);
			do
			{
				if ((c = sfgetc(fp->fp)) == EOF)
					return 0;
			} while (*p++ = c);
			p -= 2;
			break;
		case FF_old:
			if (c == EOF)
			{
				fp->decode.peek = c;
				return 0;
			}
			if (c == FF_ESC)
			{
				if (sfread(fp->fp, w, sizeof(w)) != sizeof(w))
					return 0;
				if (fp->decode.swap >= 0)
				{
					c = (int32_t)((w[0] << 24) | (w[1] << 16) | (w[2] << 8) | w[3]);
					if (!fp->decode.swap)
					{
						/*
						 * the old format uses machine
						 * byte order; this test uses
						 * the smallest magnitude of
						 * both byte orders on the
						 * first encoded path motion
						 * to determine the original
						 * byte order
						 */

						m = c;
						if (m < 0)
							m = -m;
						n = (int32_t)((w[3] << 24) | (w[2] << 16) | (w[1] << 8) | w[0]);
						if (n < 0)
							n = -n;
						if (m < n)
							fp->decode.swap = 1;
						else
						{
							fp->decode.swap = -1;
							c = (int32_t)((w[3] << 24) | (w[2] << 16) | (w[1] << 8) | w[0]);
						}
					}
				}
				else
					c = (int32_t)((w[3] << 24) | (w[2] << 16) | (w[1] << 8) | w[0]);
			}
			fp->decode.count += c - FF_OFF;
			for (p = fp->decode.path + fp->decode.count; (c = sfgetc(fp->fp)) > FF_ESC;)
				if (c & (1<<(CHAR_BIT-1)))
				{
					*p++ = fp->decode.bigram1[c & ((1<<(CHAR_BIT-1))-1)];
					*p++ = fp->decode.bigram2[c & ((1<<(CHAR_BIT-1))-1)];
				}
				else
					*p++ = c;
			*p-- = 0;
			t = 0;
			break;
		}
		b = fp->decode.path;
		if (fp->decode.found)
			fp->decode.found = 0;
		else
			b += fp->decode.count;
		if (fp->dirs)
			for (;;)
			{
				if (!*fp->dirs)
					return 0;

				/*
				 * use the ordering and lengths to prune
				 * comparison function calls
				 * (*fp->dirs)[*fp->lens]=='/' if its
				 * already been matched
				 */

				if ((n = p - fp->decode.path + 1) > (m = *fp->lens))
				{
					if (!(*fp->dirs)[m])
						goto next;
					if (!strncasecmp(*fp->dirs, fp->decode.path, m))
						break;
				}
				else if (n == m)
				{
					if (!(*fp->dirs)[m])
					{
						if (!(n = strcasecmp(*fp->dirs, fp->decode.path)) && (ignorecase || !strcmp(*fp->dirs, fp->decode.path)))
						{
							if (m > 0)
							{
								(*fp->dirs)[m] = '/';
								if ((*fp->dirs)[m - 1] != '/')
									(*fp->dirs)[++(*fp->lens)] = '/';
							}
							break;
						}
						if (n >= 0)
							goto next;
					}
				}
				else if (!(*fp->dirs)[m])
					goto next;
				fp->dirs++;
				fp->lens++;
			}
		if (fp->verify && (*p == '/' || t == 1))
		{
			if ((n = p - fp->decode.path))
				*p = 0;
			else
				n = 1;
			if (fp->verifyf)
				n = (*fp->verifyf)(fp, fp->decode.path, n, fp->disc);
			else if (stat(fp->decode.path, &st))
				n = -1;
			else if ((unsigned long)st.st_mtime > fp->stamp)
				n = 1;
			else
				n = 0;
			*p = '/';

			/*
			 * n<0	skip this subtree
			 * n==0 keep as is
			 * n>0	read this dir now
			 */

			/* NOT IMPLEMENTED YET */
		}
		if (FF_OK_TYPE(fp, t))
		{
			if (fp->decode.end)
			{
				if (*(s = p) == '/')
					s--;
				if (*fp->decode.pattern == '/' && b > fp->decode.path)
					b--;
				for (; s >= b; s--) 
					if (*s == *fp->decode.end || ignorecase && tolower(*s) == *fp->decode.end)
					{
						if (ignorecase)
							for (e = fp->decode.end - 1, q = s - 1; *e && (*q == *e || tolower(*q) == *e); e--, q--);
						else
							for (e = fp->decode.end - 1, q = s - 1; *e && *q == *e; e--, q--);
						if (!*e)
						{
							fp->decode.found = 1;
							if (!fp->decode.match || strgrpmatch(fp->decode.path, fp->decode.pattern, NiL, 0, STR_MAXIMAL|STR_LEFT|STR_RIGHT|ignorecase))
							{
								fp->decode.peek = c;
								if (*p == '/')
									*(fp->decode.restore = p) = 0;
								if (!fp->secure || !access(fp->decode.path, F_OK))
									return fp->decode.path;
							}
							break;
						}
					}
			}
			else if (!fp->decode.match || !(n = regexec(&fp->decode.re, fp->decode.path, 0, NiL, 0)))
			{
				fp->decode.peek = c;
				if (*p == '/' && p > fp->decode.path)
					*(fp->decode.restore = p) = 0;
				if (!fp->secure || !access(fp->decode.path, F_OK))
					return fp->decode.path;
			}
			else if (n != REG_NOMATCH)
			{
				if (fp->disc->errorf)
				{
					regerror(n, &fp->decode.re, fp->decode.temp, sizeof(fp->decode.temp));
					(*fp->disc->errorf)(fp, fp->disc, 2, "%s: %s", fp->decode.pattern, fp->decode.temp);
				}
				return 0;
			}
		}
	}
}

/*
 * add path to the code table
 * paths are assumed to be in sort order
 */

int
findwrite(register Find_t* fp, const char* path, size_t len, const char* type)
{
	register unsigned char*	s;
	register unsigned char*	e;
	register unsigned char*	p;
	register int		n;
	register int		d;
	register Type_t*	x;
	register unsigned long	u;

	if (!fp->generate)
		return -1;
	if (type && fp->method == FF_dir)
	{
		len = sfsprintf(fp->encode.mark, sizeof(fp->encode.mark), "%-.*s/", len, path);
		path = fp->encode.mark;
	}
	s = (unsigned char*)path;
	if (len <= 0)
		len = strlen(path);
	if (len < sizeof(fp->encode.path))
		e = s + len++;
	else
	{
		len = sizeof(fp->encode.path) - 1;
		e = s + len;
	}
	p = (unsigned char*)fp->encode.path;
	while (s < e)
	{
		if (*s != *p++)
			break;
		s++;
	}
	n = s - (unsigned char*)path;
	switch (fp->method)
	{
	case FF_gnu:
		d = n - fp->encode.prefix;
		if (d >= -127 && d <= 127)
			sfputc(fp->fp, d & 0xff);
		else
		{
			sfputc(fp->fp, 0x80);
			sfputc(fp->fp, (d >> 8) & 0xff);
			sfputc(fp->fp, d & 0xff);
		}
		fp->encode.prefix = n;
		sfputr(fp->fp, (char*)s, 0);
		break;
	case FF_old:
		sfprintf(fp->fp, "%ld", n - fp->encode.prefix + FF_OFF);
		fp->encode.prefix = n;
		sfputc(fp->fp, ' ');
		p = s;
		while (s < e)
		{
			n = *s++;
			if (s >= e)
				break;
			fp->encode.code[n][*s++]++;
		}
		while (p < e)
		{
			if ((n = *p++) < FF_MIN || n >= FF_MAX)
				n = '?';
			sfputc(fp->fp, n);
		}
		sfputc(fp->fp, 0);
		break;
	case FF_typ:
		if (type)
		{
			type = (const char*)typefix((char*)fp->encode.bigram, sizeof(fp->encode.bigram), type);
			if (x = (Type_t*)dtmatch(fp->encode.namedict, type))
				u = x->index;
			else if (!(x = newof(0, Type_t, 1, strlen(type) + 1)))
				u = 0;
			else
			{
				u = x->index = ++fp->types;
				strcpy(x->name, type);
				dtinsert(fp->encode.namedict, x);
				dtinsert(fp->encode.indexdict, x);
			}
		}
		else
			u = 0;
		sfputu(fp->fp, u);
		/*FALLTHROUGH...*/
	case FF_dir:
		d = n - fp->encode.prefix;
		sfputl(fp->fp, d);
		fp->encode.prefix = n;
		sfputr(fp->fp, (char*)s, 0);
		break;
	}
	memcpy(fp->encode.path, path, len);
	return 0;
}

/*
 * findsync() helper
 */

static int
finddone(register Find_t* fp)
{
	int	r;

	if (sfsync(fp->fp))
	{
		if (fp->disc->errorf)
			(*fp->disc->errorf)(fp, fp->disc, 2, "%s: write error [sfsync]", fp->encode.file);
		return -1;
	}
	if (sferror(fp->fp))
	{
		if (fp->disc->errorf)
			(*fp->disc->errorf)(fp, fp->disc, 2, "%s: write error [sferror]", fp->encode.file);
		return -1;
	}
	r = sfclose(fp->fp);
	fp->fp = 0;
	if (r)
	{
		if (fp->disc->errorf)
			(*fp->disc->errorf)(fp, fp->disc, 2, "%s: write error [sfclose]", fp->encode.file);
		return -1;
	}
	return 0;
}

/*
 * finish the code table
 */

static int
findsync(register Find_t* fp)
{
	register char*		s;
	register int		n;
	register int		m;
	register int		d;
	register Type_t*	x;
	char*			t;
	int			b;
	long			z;
	Sfio_t*			sp;

	switch (fp->method)
	{
	case FF_dir:
	case FF_gnu:
		/*
		 * replace the real file with the temp file
		 */

		if (finddone(fp))
			goto bad;
		remove(fp->encode.file);
		if (rename(fp->encode.temp, fp->encode.file))
		{
			if (fp->disc->errorf)
				(*fp->disc->errorf)(fp, fp->disc, ERROR_SYSTEM|2, "%s: cannot rename from tmp file %s", fp->encode.file, fp->encode.temp);
			remove(fp->encode.temp);
			return -1;
		}
		break;
	case FF_old:
		/*
		 * determine the top FF_MAX bigrams
		 */

		for (n = 0; n < FF_MAX; n++)
			for (m = 0; m < FF_MAX; m++)
				fp->encode.hits[fp->encode.code[n][m]]++;
		fp->encode.hits[0] = 0;
		m = 1;
		for (n = USHRT_MAX; n >= 0; n--)
			if (d = fp->encode.hits[n])
			{
				fp->encode.hits[n] = m;
				if ((m += d) > FF_MAX)
					break;
			}
		while (--n >= 0)
			fp->encode.hits[n] = 0;
		for (n = FF_MAX - 1; n >= 0; n--)
			for (m = FF_MAX - 1; m >= 0; m--)
				if (fp->encode.hits[fp->encode.code[n][m]])
				{
					d = fp->encode.code[n][m];
					b = fp->encode.hits[d] - 1;
					fp->encode.code[n][m] = b + FF_MAX;
					if (fp->encode.hits[d]++ >= FF_MAX)
						fp->encode.hits[d] = 0;
					fp->encode.bigram[b *= 2] = n;
					fp->encode.bigram[b + 1] = m;
				}
				else
					fp->encode.code[n][m] = 0;

		/*
		 * commit the real file 
		 */

		if (sfseek(fp->fp, (Sfoff_t)0, SEEK_SET))
		{
			if (fp->disc->errorf)
				(*fp->disc->errorf)(fp, fp->disc, ERROR_SYSTEM|2, "cannot rewind tmp file");
			return -1;
		}
		if (!(sp = sfopen(NiL, fp->encode.file, "w")))
			goto badcreate;

		/*
		 * dump the bigrams
		 */

		sfwrite(sp, fp->encode.bigram, sizeof(fp->encode.bigram));

		/*
		 * encode the massaged paths
		 */

		while (s = sfgetr(fp->fp, 0, 0))
		{
			z = strtol(s, &t, 0);
			s = t;
			if (z < 0 || z > 2 * FF_OFF)
			{
				sfputc(sp, FF_ESC);
				sfputc(sp, (z >> 24));
				sfputc(sp, (z >> 16));
				sfputc(sp, (z >> 8));
				sfputc(sp, z);
			}
			else
				sfputc(sp, z);
			while (n = *s++)
			{
				if (!(m = *s++))
				{
					sfputc(sp, n);
					break;
				}
				if (d = fp->encode.code[n][m])
					sfputc(sp, d);
				else
				{
					sfputc(sp, n);
					sfputc(sp, m);
				}
			}
		}
		sfclose(fp->fp);
		fp->fp = sp;
		if (finddone(fp))
			goto bad;
		break;
	case FF_typ:
		if (finddone(fp))
			goto bad;
		if (!(fp->fp = sfopen(NiL, fp->encode.temp, "r")))
		{
			if (fp->disc->errorf)
				(*fp->disc->errorf)(fp, fp->disc, ERROR_SYSTEM|2, "%s: cannot read tmp file", fp->encode.temp);
			remove(fp->encode.temp);
			return -1;
		}

		/*
		 * commit the output file
		 */

		if (!(sp = sfopen(NiL, fp->encode.file, "w")))
			goto badcreate;

		/*
		 * write the header magic
		 */

		sfputc(sp, 0);
		sfputr(sp, FF_typ_magic, 0);

		/*
		 * write the type table in index order starting with 1
		 */

		for (x = (Type_t*)dtfirst(fp->encode.indexdict); x; x = (Type_t*)dtnext(fp->encode.indexdict, x))
			sfputr(sp, x->name, 0);
		sfputc(sp, 0);

		/*
		 * append the front compressed strings
		 */

		if (sfmove(fp->fp, sp, SF_UNBOUND, -1) < 0 || !sfeof(fp->fp))
		{
			sfclose(sp);
			if (fp->disc->errorf)
				(*fp->disc->errorf)(fp, fp->disc, 2, "%s: cannot append codes", fp->encode.file);
			goto bad;
		}
		sfclose(fp->fp);
		fp->fp = sp;
		if (finddone(fp))
			goto bad;
		remove(fp->encode.temp);
		break;
	}
	return 0;
 badcreate:
	if (fp->disc->errorf)
		(*fp->disc->errorf)(fp, fp->disc, 2, "%s: cannot write codes", fp->encode.file);
 bad:
	if (fp->fp)
	{
		sfclose(fp->fp);
		fp->fp = 0;
	}
	remove(fp->encode.temp);
	return -1;
}

/*
 * close an open fastfind stream
 */

int
findclose(register Find_t* fp)
{
	int	n = 0;

	if (!fp)
		return -1;
	if (fp->generate)
	{
		n = findsync(fp);
		if (fp->encode.indexdict)
			dtclose(fp->encode.indexdict);
		if (fp->encode.namedict)
			dtclose(fp->encode.namedict);
	}
	else
	{
		if (fp->decode.match)
			regfree(&fp->decode.re);
		n = 0;
	}
	if (fp->fp)
		sfclose(fp->fp);
	vmclose(fp->vm);
	return n;
}
