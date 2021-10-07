/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Minimal libsbuf wrapper around libcustr for illumos.
 */

#ifndef LIB9P_SBUF_H
#define LIB9P_SBUF_H

#include <stdarg.h>
#include <libcustr.h>

struct sbuf
{
	custr_t *s_custr;
};

struct sbuf *sbuf_new_auto(void);
char *sbuf_data(struct sbuf *s);
int sbuf_printf(struct sbuf *s, const char *fmt, ...);
void sbuf_delete(struct sbuf *s);

#define	sbuf_cat(s, str) custr_append((s)->s_custr, (str))
#define	sbuf_vprintf(s, fmt, args) \
    custr_append_vprintf((s)->s_custr, (fmt), (args))
#define	sbuf_data(s) custr_cstr((s)->s_custr)
#define	sbuf_finish(s)

#endif /* LIB9P_SBUF_H */
