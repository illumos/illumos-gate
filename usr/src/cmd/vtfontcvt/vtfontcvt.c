/*
 * Copyright (c) 2009, 2014 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Ed Schouten under sponsorship from the
 * FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <endian.h>
#include <sys/param.h>
#include <sys/queue.h>

#include <assert.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include "fnv_hash.h"

#define	VFNT_MAPS 4
#define	VFNT_MAP_NORMAL 0
#define	VFNT_MAP_NORMAL_RH 1
#define	VFNT_MAP_BOLD 2
#define	VFNT_MAP_BOLD_RH 3

extern size_t lz4_compress(void *, void *, size_t, size_t, int);

static unsigned int width = 8, wbytes, height = 16;

struct bbox {
	unsigned int width;	/* pixels */
	unsigned int height;
	int x;			/* lower left corner x */
	int y;			/* lower left corner y */
};

static struct bbox bbox;	/* font bounding box */
static int font_ascent;		/* pixels above baseline */
static int font_descent;	/* pixels below baseline */
static unsigned int default_char = 0xFFFD;

struct glyph {
	TAILQ_ENTRY(glyph)	 g_list;
	SLIST_ENTRY(glyph)	 g_hash;
	uint8_t			*g_data;
	unsigned int		 g_index;
};

#define	FONTCVT_NHASH 4096
TAILQ_HEAD(glyph_list, glyph);
static SLIST_HEAD(, glyph) glyph_hash[FONTCVT_NHASH];
static struct glyph_list glyphs[VFNT_MAPS] = {
    TAILQ_HEAD_INITIALIZER(glyphs[0]),
    TAILQ_HEAD_INITIALIZER(glyphs[1]),
    TAILQ_HEAD_INITIALIZER(glyphs[2]),
    TAILQ_HEAD_INITIALIZER(glyphs[3]),
};
static unsigned int glyph_total, glyph_count[4], glyph_unique, glyph_dupe;

struct mapping {
	TAILQ_ENTRY(mapping)	 m_list;
	unsigned int		 m_char;
	unsigned int		 m_length;
	struct glyph		*m_glyph;
};

TAILQ_HEAD(mapping_list, mapping);
static struct mapping_list maps[VFNT_MAPS] = {
    TAILQ_HEAD_INITIALIZER(maps[0]),
    TAILQ_HEAD_INITIALIZER(maps[1]),
    TAILQ_HEAD_INITIALIZER(maps[2]),
    TAILQ_HEAD_INITIALIZER(maps[3]),
};
static unsigned int mapping_total, map_count[4], map_folded_count[4],
    mapping_unique, mapping_dupe;

enum output_format {
	VT_FONT,		/* default */
	VT_C_SOURCE,		/* C source for built in fonts */
	VT_C_COMPRESSED		/* C source with compressed font data */
};

struct whitelist {
	uint32_t c;
	uint32_t len;
};

/*
 * Compressed font glyph list. To be used with boot loader, we need to have
 * ascii set and box drawing chars.
 */
static struct whitelist c_list[] = {
	{ .c = 0, .len = 0 },		/* deault char */
	{ .c = 0x20, .len = 0x5f },
	{ .c = 0x2500, .len = 0 },	/* single frame */
	{ .c = 0x2502, .len = 0 },
	{ .c = 0x250c, .len = 0 },
	{ .c = 0x2510, .len = 0 },
	{ .c = 0x2514, .len = 0 },
	{ .c = 0x2518, .len = 0 },
	{ .c = 0x2550, .len = 1 },	/* double frame */
	{ .c = 0x2554, .len = 0 },
	{ .c = 0x2557, .len = 0 },
	{ .c = 0x255a, .len = 0 },
	{ .c = 0x255d, .len = 0 },
};

/*
 * Uncompressed source. For x86 we need cp437 so the vga text mode
 * can program font into the vga card.
 */
static struct whitelist s_list[] = {
	{ .c = 0, .len = 0 },		/* deault char */
	{ .c = 0x20, .len = 0x5f },	/* ascii set */
	{ .c = 0xA0, .len = 0x5f },	/* latin 1 */
	{ .c = 0x0192, .len = 0 },
	{ .c = 0x0332, .len = 0 },	/* composing lower line */
	{ .c = 0x0393, .len = 0 },
	{ .c = 0x0398, .len = 0 },
	{ .c = 0x03A3, .len = 0 },
	{ .c = 0x03A6, .len = 0 },
	{ .c = 0x03A9, .len = 0 },
	{ .c = 0x03B1, .len = 1 },
	{ .c = 0x03B4, .len = 0 },
	{ .c = 0x03C0, .len = 0 },
	{ .c = 0x03C3, .len = 0 },
	{ .c = 0x03C4, .len = 0 },
	{ .c = 0x207F, .len = 0 },
	{ .c = 0x20A7, .len = 0 },
	{ .c = 0x2205, .len = 0 },
	{ .c = 0x220A, .len = 0 },
	{ .c = 0x2219, .len = 1 },
	{ .c = 0x221E, .len = 0 },
	{ .c = 0x2229, .len = 0 },
	{ .c = 0x2248, .len = 0 },
	{ .c = 0x2261, .len = 0 },
	{ .c = 0x2264, .len = 1 },
	{ .c = 0x2310, .len = 0 },
	{ .c = 0x2320, .len = 1 },
	{ .c = 0x2500, .len = 0 },
	{ .c = 0x2502, .len = 0 },
	{ .c = 0x250C, .len = 0 },
	{ .c = 0x2510, .len = 0 },
	{ .c = 0x2514, .len = 0 },
	{ .c = 0x2518, .len = 0 },
	{ .c = 0x251C, .len = 0 },
	{ .c = 0x2524, .len = 0 },
	{ .c = 0x252C, .len = 0 },
	{ .c = 0x2534, .len = 0 },
	{ .c = 0x253C, .len = 0 },
	{ .c = 0x2550, .len = 0x1c },
	{ .c = 0x2580, .len = 0 },
	{ .c = 0x2584, .len = 0 },
	{ .c = 0x2588, .len = 0 },
	{ .c = 0x258C, .len = 0 },
	{ .c = 0x2590, .len = 3 },
	{ .c = 0x25A0, .len = 0 },
};

bool filter = true;
enum output_format format = VT_FONT;
/* Type for write callback. */
typedef size_t (*vt_write)(const void *, size_t, size_t, FILE *);
uint8_t *uncompressed;

static void
usage(void)
{

	(void) fprintf(stderr, "usage:\tvtfontcvt "
	    "[-n] [-f font|source|compressed-source] [-w width] "
	    "[-h height]\n\t[-v] -o outfile normal.bdf [bold.bdf]\n");
	exit(1);
}

static void *
xmalloc(size_t size)
{
	void *m;

	if ((m = malloc(size)) == NULL)
		errx(1, "memory allocation failure");
	return (m);
}

static int
add_mapping(struct glyph *gl, unsigned int c, unsigned int map_idx)
{
	struct mapping *mp, *v;
	struct mapping_list *ml;

	mapping_total++;

	mp = xmalloc(sizeof (*mp));
	mp->m_char = c;
	mp->m_glyph = gl;
	mp->m_length = 0;

	ml = &maps[map_idx];
	if (TAILQ_LAST(ml, mapping_list) != NULL &&
	    TAILQ_LAST(ml, mapping_list)->m_char >= c) {
		TAILQ_FOREACH_REVERSE(v, ml, mapping_list, m_list) {
			if (v->m_char < c) {
				TAILQ_INSERT_AFTER(ml, v, mp, m_list);
				break;
			} else if (v->m_char == c)
				errx(1, "Bad ordering at character %u", c);
		}
	} else
		TAILQ_INSERT_TAIL(ml, mp, m_list);

	map_count[map_idx]++;
	mapping_unique++;

	return (0);
}

static int
dedup_mapping(unsigned int map_idx)
{
	struct mapping *mp_bold, *mp_normal;
	unsigned normal_map_idx = map_idx - VFNT_MAP_BOLD;

	assert(map_idx == VFNT_MAP_BOLD || map_idx == VFNT_MAP_BOLD_RH);
	mp_normal = TAILQ_FIRST(&maps[normal_map_idx]);
	TAILQ_FOREACH(mp_bold, &maps[map_idx], m_list) {
		while (mp_normal->m_char < mp_bold->m_char)
			mp_normal = TAILQ_NEXT(mp_normal, m_list);
		if (mp_bold->m_char != mp_normal->m_char)
			errx(1, "Character %u not in normal font!",
			    mp_bold->m_char);
		if (mp_bold->m_glyph != mp_normal->m_glyph)
			continue;

		/* No mapping is needed if it's equal to the normal mapping. */
		TAILQ_REMOVE(&maps[map_idx], mp_bold, m_list);
		free(mp_bold);
		mapping_dupe++;
	}
	return (0);
}

static struct glyph *
add_glyph(const uint8_t *bytes, unsigned int map_idx, int fallback)
{
	struct glyph *gl;
	int hash;

	glyph_total++;
	glyph_count[map_idx]++;

	hash = fnv_32_buf(bytes, wbytes * height, FNV1_32_INIT) % FONTCVT_NHASH;
	SLIST_FOREACH(gl, &glyph_hash[hash], g_hash) {
		if (memcmp(gl->g_data, bytes, wbytes * height) == 0) {
			glyph_dupe++;
			return (gl);
		}
	}

	gl = xmalloc(sizeof (*gl));
	gl->g_data = xmalloc(wbytes * height);
	memcpy(gl->g_data, bytes, wbytes * height);
	if (fallback)
		TAILQ_INSERT_HEAD(&glyphs[map_idx], gl, g_list);
	else
		TAILQ_INSERT_TAIL(&glyphs[map_idx], gl, g_list);
	SLIST_INSERT_HEAD(&glyph_hash[hash], gl, g_hash);

	glyph_unique++;
	return (gl);
}

static bool
check_whitelist(unsigned c)
{
	struct whitelist *w = NULL;
	int i, n = 0;

	if (filter == false)
		return (true);

	if (format == VT_C_SOURCE) {
		w = s_list;
		n = sizeof (s_list) / sizeof (s_list[0]);
	}
	if (format == VT_C_COMPRESSED) {
		w = c_list;
		n = sizeof (c_list) / sizeof (c_list[0]);
	}
	if (w == NULL)
		return (true);
	for (i = 0; i < n; i++) {
		if (c >= w[i].c && c <= w[i].c + w[i].len)
			return (true);
	}
	return (false);
}

static int
add_char(unsigned curchar, unsigned map_idx, uint8_t *bytes, uint8_t *bytes_r)
{
	struct glyph *gl;

	/* Prevent adding two glyphs for default_char */
	if (curchar == default_char) {
		if (map_idx < VFNT_MAP_BOLD)
			gl = add_glyph(bytes, 0, 1);
	} else if (filter == false || curchar >= 0x20) {
		gl = add_glyph(bytes, map_idx, 0);
		if (add_mapping(gl, curchar, map_idx) != 0)
			return (1);
		if (bytes_r != NULL) {
			gl = add_glyph(bytes_r, map_idx + 1, 0);
			if (add_mapping(gl, curchar,
			    map_idx + 1) != 0)
				return (1);
		}
	}
	return (0);
}


static int
parse_bitmap_line(uint8_t *left, uint8_t *right, unsigned int line,
    unsigned int dwidth)
{
	uint8_t *p;
	unsigned int i, subline;

	if (dwidth != width && dwidth != width * 2)
		errx(1, "Bitmap with unsupported width %u!", dwidth);

	/* Move pixel data right to simplify splitting double characters. */
	line >>= (howmany(dwidth, 8) * 8) - dwidth;

	for (i = dwidth / width; i > 0; i--) {
		p = (i == 2) ? right : left;

		subline = line & ((1 << width) - 1);
		subline <<= (howmany(width, 8) * 8) - width;

		if (wbytes == 1) {
			*p = subline;
		} else if (wbytes == 2) {
			*p++ = subline >> 8;
			*p = subline;
		} else {
			errx(1, "Unsupported wbytes %u!", wbytes);
		}

		line >>= width;
	}

	return (0);
}

static int
parse_bdf(FILE *fp, unsigned int map_idx)
{
	char ln[BUFSIZ];
	uint8_t bytes[wbytes * height], bytes_r[wbytes * height];
	unsigned int curchar = 0, dwidth = 0, i, line;

	memset(bytes, 0, sizeof (bytes));
	memset(bytes_r, 0, sizeof (bytes_r));

	while (fgets(ln, sizeof (ln), fp) != NULL) {
		if (sscanf(ln, "ENCODING %u", &curchar) == 1)
			continue;

		if (sscanf(ln, "DWIDTH %u", &dwidth) == 1)
			continue;

		if (strncmp(ln, "BITMAP", 6) == 0) {
			for (i = 0; i < height; i++) {
				if (fgets(ln, sizeof (ln), fp) == NULL)
					errx(1, "Unexpected EOF!");
				sscanf(ln, "%x", &line);
				if (parse_bitmap_line(bytes + i * wbytes,
				    bytes_r + i * wbytes, line, dwidth) != 0)
					return (1);
			}

			if (check_whitelist(curchar) == true) {
				if (add_char(curchar, map_idx, bytes,
				    dwidth == width * 2 ? bytes_r : NULL) != 0)
					return (1);
			}
		}
	}

	return (0);
}

static void
set_width(int w)
{

	if (w <= 0 || w > 128)
		errx(1, "invalid width %d", w);
	width = w;
	wbytes = howmany(width, 8);
}

static int
parse_hex(FILE *fp, unsigned int map_idx)
{
	char ln[BUFSIZ], *p;
	char fmt_str[8];
	uint8_t *bytes = NULL, *bytes_r = NULL;
	unsigned curchar = 0, i, line, chars_per_row, dwidth;
	int rv = 0;

	while (fgets(ln, sizeof (ln), fp) != NULL) {
		if (strncmp(ln, "# Height: ", 10) == 0) {
			if (bytes != NULL) {
				errx(1, "malformed input: Height tag after "
				    "font data");
			}
			height = atoi(ln + 10);
		} else if (strncmp(ln, "# Width: ", 9) == 0) {
			if (bytes != NULL) {
				errx(1, "malformed input: Width tag after "
				    "font data");
			}
			set_width(atoi(ln + 9));
		} else if (sscanf(ln, "%6x:", &curchar)) {
			if (bytes == NULL) {
				bytes = xmalloc(wbytes * height);
				bytes_r = xmalloc(wbytes * height);
			}
			/* ln is guaranteed to have a colon here. */
			p = strchr(ln, ':') + 1;
			chars_per_row = strlen(p) / height;
			dwidth = width;
			if (chars_per_row / 2 > (width + 7) / 8)
				dwidth *= 2; /* Double-width character. */
			snprintf(fmt_str, sizeof (fmt_str), "%%%ux",
			    chars_per_row);

			for (i = 0; i < height; i++) {
				sscanf(p, fmt_str, &line);
				p += chars_per_row;
				if (parse_bitmap_line(bytes + i * wbytes,
				    bytes_r + i * wbytes, line, dwidth) != 0) {
					rv = 1;
					goto out;
				}
			}

			if (add_char(curchar, map_idx, bytes,
			    dwidth == width * 2 ? bytes_r : NULL) != 0) {
				rv = 1;
				goto out;
			}
		}
	}
out:
	free(bytes);
	free(bytes_r);
	return (rv);
}

/* Read BDF header and set the font data. */
static int
parse_bdf_header(FILE *fp)
{
	char ln[BUFSIZ];
	char spacing = '\0';	/* Should we assume C if not specified? */
	int ret;

	while (fgets(ln, sizeof (ln), fp) != NULL) {
		ret = sscanf(ln, "FONTBOUNDINGBOX %u %u %d %d",
		    &bbox.width, &bbox.height, &bbox.x, &bbox.y);
		if (ret == 4)
			continue;
		ret = sscanf(ln, "FONT_ASCENT %u", &font_ascent);
		if (ret == 1)
			continue;
		ret = sscanf(ln, "FONT_DESCENT %u", &font_descent);
		if (ret == 1)
			continue;
		ret = sscanf(ln, "DEFAULT_CHAR %u", &default_char);
		if (ret == 1) {
			c_list[0].c = default_char;
			s_list[0].c = default_char;
			continue;
		}
		ret = sscanf(ln, "SPACING \"%c\"", &spacing);
		if (ret == 1)
			continue;
		if (strncmp("ENDPROPERTIES", ln, 13) == 0)
			break;
	}
	if (spacing != 'C') {
		printf("Spacing '%c' is not supported\n", spacing);
		return (1);
	}
	if (bbox.width == 0)
		bbox.width = width;
	set_width(bbox.width);

	if (bbox.height == 0)
		bbox.height = height;
	height = bbox.height;
	return (0);
}

static int
parse_file(const char *filename, unsigned int map_idx)
{
	FILE *fp;
	size_t len;
	int rv;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		perror(filename);
		return (1);
	}
	len = strlen(filename);
	if (len > 4 && strcasecmp(filename + len - 4, ".hex") == 0) {
		rv = parse_hex(fp, map_idx);
	} else {
		if ((rv = parse_bdf_header(fp)) == 0)
			rv = parse_bdf(fp, map_idx);
	}
	fclose(fp);
	return (rv);
}

static void
number_glyphs(void)
{
	struct glyph *gl;
	unsigned int i, idx = 0;

	for (i = 0; i < VFNT_MAPS; i++)
		TAILQ_FOREACH(gl, &glyphs[i], g_list)
			gl->g_index = idx++;
}

/* Note we only deal with byte stream here. */
static size_t
write_glyph_source(const void *ptr, size_t size, size_t nitems, FILE *stream)
{
	const uint8_t *data = ptr;
	size_t i;

	size *= nitems;
	for (i = 0; i < size; i++) {
		if ((i % wbytes) == 0) {
			if (fprintf(stream, "\n") < 0)
				return (0);
		}
		if (fprintf(stream, "0x%02x, ", data[i]) < 0)
			return (0);
	}
	if (fprintf(stream, "\n") < 0)
		nitems = 0;

	return (nitems);
}

/* Write to buffer */
static size_t
write_glyph_buf(const void *ptr, size_t size, size_t nitems, FILE *stream)
{
	static size_t index = 0;

	size *= nitems;
	(void) memmove(uncompressed + index, ptr, size);
	index += size;

	return (nitems);
}

static int
write_glyphs(FILE *fp, vt_write cb)
{
	struct glyph *gl;
	unsigned int i;

	for (i = 0; i < VFNT_MAPS; i++) {
		TAILQ_FOREACH(gl, &glyphs[i], g_list)
			if (cb(gl->g_data, wbytes * height, 1, fp) != 1)
				return (1);
	}
	return (0);
}

static void
fold_mappings(unsigned int map_idx)
{
	struct mapping_list *ml = &maps[map_idx];
	struct mapping *mn, *mp, *mbase;

	mp = mbase = TAILQ_FIRST(ml);
	for (mp = mbase = TAILQ_FIRST(ml); mp != NULL; mp = mn) {
		mn = TAILQ_NEXT(mp, m_list);
		if (mn != NULL && mn->m_char == mp->m_char + 1 &&
		    mn->m_glyph->g_index == mp->m_glyph->g_index + 1)
			continue;
		mbase->m_length = mp->m_char - mbase->m_char + 1;
		mbase = mp = mn;
		map_folded_count[map_idx]++;
	}
}

struct file_mapping {
	uint32_t	source;
	uint16_t	destination;
	uint16_t	length;
} __attribute__((packed));

static int
write_mappings(FILE *fp, unsigned int map_idx)
{
	struct mapping_list *ml = &maps[map_idx];
	struct mapping *mp;
	struct file_mapping fm;
	unsigned int i = 0, j = 0;

	TAILQ_FOREACH(mp, ml, m_list) {
		j++;
		if (mp->m_length > 0) {
			i += mp->m_length;
			fm.source = htobe32(mp->m_char);
			fm.destination = htobe16(mp->m_glyph->g_index);
			fm.length = htobe16(mp->m_length - 1);
			if (fwrite(&fm, sizeof (fm), 1, fp) != 1)
				return (1);
		}
	}
	assert(i == j);
	return (0);
}

static int
write_source_mappings(FILE *fp, unsigned int map_idx)
{
	struct mapping_list *ml = &maps[map_idx];
	struct mapping *mp;
	unsigned int i = 0, j = 0;

	TAILQ_FOREACH(mp, ml, m_list) {
		j++;
		if (mp->m_length > 0) {
			i += mp->m_length;
			if (fprintf(fp, "\t{ 0x%08x, 0x%04x, 0x%04x },\n",
			    mp->m_char, mp->m_glyph->g_index,
			    mp->m_length - 1) < 0)
				return (1);
		}
	}
	assert(i == j);
	return (0);
}

struct file_header {
	uint8_t		magic[8];
	uint8_t		width;
	uint8_t		height;
	uint16_t	pad;
	uint32_t	glyph_count;
	uint32_t	map_count[4];
} __attribute__((packed));

static int
write_fnt(const char *filename)
{
	FILE *fp;
	struct file_header fh = {
		.magic = "VFNT0002",
	};

	fp = fopen(filename, "wb");
	if (fp == NULL) {
		perror(filename);
		return (1);
	}

	fh.width = width;
	fh.height = height;
	fh.glyph_count = htobe32(glyph_unique);
	fh.map_count[0] = htobe32(map_folded_count[0]);
	fh.map_count[1] = htobe32(map_folded_count[1]);
	fh.map_count[2] = htobe32(map_folded_count[2]);
	fh.map_count[3] = htobe32(map_folded_count[3]);
	if (fwrite(&fh, sizeof (fh), 1, fp) != 1) {
		perror(filename);
		fclose(fp);
		return (1);
	}

	if (write_glyphs(fp, &fwrite) != 0 ||
	    write_mappings(fp, VFNT_MAP_NORMAL) != 0 ||
	    write_mappings(fp, 1) != 0 ||
	    write_mappings(fp, VFNT_MAP_BOLD) != 0 ||
	    write_mappings(fp, 3) != 0) {
		perror(filename);
		fclose(fp);
		return (1);
	}

	fclose(fp);
	return (0);
}

static int
write_fnt_source(bool lz4, const char *filename)
{
	FILE *fp;
	int rv = 1;
	size_t uncompressed_size = wbytes * height * glyph_unique;
	size_t compressed_size = uncompressed_size;
	uint8_t *compressed = NULL;

	fp = fopen(filename, "w");
	if (fp == NULL) {
		perror(filename);
		return (1);
	}

	if (lz4 == true) {
		uncompressed = xmalloc(uncompressed_size);
		compressed = xmalloc(uncompressed_size);
	}
	if (fprintf(fp, "/* Generated %ux%u console font source. */\n\n",
	    width, height) < 0)
		goto done;
	if (fprintf(fp, "#include <sys/types.h>\n") < 0)
		goto done;
	if (fprintf(fp, "#include <sys/param.h>\n") < 0)
		goto done;
	if (fprintf(fp, "#include <sys/font.h>\n\n") < 0)
		goto done;

	/* Write font bytes. */
	if (fprintf(fp, "static uint8_t FONTDATA_%ux%u[] = {\n",
	    width, height) < 0)
		goto done;
	if (lz4 == true) {
		if (write_glyphs(fp, &write_glyph_buf) != 0)
			goto done;
		compressed_size = lz4_compress(uncompressed, compressed,
		    uncompressed_size, compressed_size, 0);
		if (write_glyph_source(compressed, compressed_size, 1, fp) != 1)
			goto done;
		free(uncompressed);
		free(compressed);
	} else {
		if (write_glyphs(fp, &write_glyph_source) != 0)
			goto done;
	}
	if (fprintf(fp, "};\n\n") < 0)
		goto done;

	/* Write font maps. */
	if (!TAILQ_EMPTY(&maps[VFNT_MAP_NORMAL])) {
		if (fprintf(fp, "static struct font_map "
		    "FONTMAP_NORMAL_%ux%u[] = {\n", width, height) < 0)
			goto done;
		if (write_source_mappings(fp, VFNT_MAP_NORMAL) != 0)
			goto done;
		if (fprintf(fp, "};\n\n") < 0)
			goto done;
	}
	if (!TAILQ_EMPTY(&maps[VFNT_MAP_NORMAL_RH])) {
		if (fprintf(fp, "static struct font_map "
		    "FONTMAP_NORMAL_RH_%ux%u[] = {\n", width, height) < 0)
			goto done;
		if (write_source_mappings(fp, VFNT_MAP_NORMAL_RH) != 0)
			goto done;
		if (fprintf(fp, "};\n\n") < 0)
			goto done;
	}
	if (!TAILQ_EMPTY(&maps[VFNT_MAP_BOLD])) {
		if (fprintf(fp, "static struct font_map "
		    "FONTMAP_BOLD_%ux%u[] = {\n", width, height) < 0)
			goto done;
		if (write_source_mappings(fp, VFNT_MAP_BOLD) != 0)
			goto done;
		if (fprintf(fp, "};\n\n") < 0)
			goto done;
	}
	if (!TAILQ_EMPTY(&maps[VFNT_MAP_BOLD_RH])) {
		if (fprintf(fp, "static struct font_map "
		    "FONTMAP_BOLD_RH_%ux%u[] = {\n", width, height) < 0)
			goto done;
		if (write_source_mappings(fp, VFNT_MAP_BOLD_RH) != 0)
			goto done;
		if (fprintf(fp, "};\n\n") < 0)
			goto done;
	}

	/* Write struct font. */
	if (fprintf(fp, "struct font font_%ux%u = {\n",
	    width, height) < 0)
		goto done;
	if (fprintf(fp, "\t.vf_map\t= {\n") < 0)
		goto done;
	if (TAILQ_EMPTY(&maps[VFNT_MAP_NORMAL])) {
		if (fprintf(fp, "\t\t\tNULL,\n") < 0)
			goto done;
	} else {
		if (fprintf(fp, "\t\t\tFONTMAP_NORMAL_%ux%u,\n",
		    width, height) < 0)
			goto done;
	}
	if (TAILQ_EMPTY(&maps[VFNT_MAP_NORMAL_RH])) {
		if (fprintf(fp, "\t\t\tNULL,\n") < 0)
			goto done;
	} else {
		if (fprintf(fp, "\t\t\tFONTMAP_NORMAL_RH_%ux%u,\n",
		    width, height) < 0)
			goto done;
	}
	if (TAILQ_EMPTY(&maps[VFNT_MAP_BOLD])) {
		if (fprintf(fp, "\t\t\tNULL,\n") < 0)
			goto done;
	} else {
		if (fprintf(fp, "\t\t\tFONTMAP_BOLD_%ux%u,\n",
		    width, height) < 0)
			goto done;
	}
	if (TAILQ_EMPTY(&maps[VFNT_MAP_BOLD_RH])) {
		if (fprintf(fp, "\t\t\tNULL\n") < 0)
			goto done;
	} else {
		if (fprintf(fp, "\t\t\tFONTMAP_BOLD_RH_%ux%u\n",
		    width, height) < 0)
			goto done;
	}
	if (fprintf(fp, "\t\t},\n") < 0)
		goto done;
	if (lz4 == true) {
		if (fprintf(fp, "\t.vf_bytes\t= NULL,\n") < 0)
			goto done;
	} else {
		if (fprintf(fp, "\t.vf_bytes\t= FONTDATA_%ux%u,\n",
		    width, height) < 0) {
			goto done;
		}
	}
	if (fprintf(fp, "\t.vf_width\t= %u,\n", width) < 0)
		goto done;
	if (fprintf(fp, "\t.vf_height\t= %u,\n", height) < 0)
		goto done;
	if (fprintf(fp, "\t.vf_map_count\t= { %u, %u, %u, %u }\n",
	    map_folded_count[0], map_folded_count[1], map_folded_count[2],
	    map_folded_count[3]) < 0) {
		goto done;
	}
	if (fprintf(fp, "};\n\n") < 0)
		goto done;

	/* Write bitmap data. */
	if (fprintf(fp, "bitmap_data_t font_data_%ux%u = {\n",
	    width, height) < 0)
		goto done;
	if (fprintf(fp, "\t.width\t= %u,\n", width) < 0)
		goto done;
	if (fprintf(fp, "\t.height\t= %u,\n", height) < 0)
		goto done;
	if (lz4 == true) {
		if (fprintf(fp, "\t.compressed_size\t= %u,\n",
		    compressed_size) < 0) {
			goto done;
		}
		if (fprintf(fp, "\t.uncompressed_size\t= %u,\n",
		    uncompressed_size) < 0) {
			goto done;
		}
		if (fprintf(fp, "\t.compressed_data\t= FONTDATA_%ux%u,\n",
		    width, height) < 0) {
			goto done;
		}
	} else {
		if (fprintf(fp, "\t.compressed_size\t= 0,\n") < 0)
			goto done;
		if (fprintf(fp, "\t.uncompressed_size\t= %u,\n",
		    uncompressed_size) < 0) {
			goto done;
		}
		if (fprintf(fp, "\t.compressed_data\t= NULL,\n") < 0)
			goto done;
	}
	if (fprintf(fp, "\t.font = &font_%ux%u\n", width, height) < 0)
		goto done;
	if (fprintf(fp, "};\n") < 0)
		goto done;

	rv = 0;
done:
	if (rv != 0)
		perror(filename);
	fclose(fp);
	return (0);
}

static void
print_font_info(void)
{
	printf(
"Statistics:\n"
"- glyph_total:                 %6u\n"
"- glyph_normal:                %6u\n"
"- glyph_normal_right:          %6u\n"
"- glyph_bold:                  %6u\n"
"- glyph_bold_right:            %6u\n"
"- glyph_unique:                %6u\n"
"- glyph_dupe:                  %6u\n"
"- mapping_total:               %6u\n"
"- mapping_normal:              %6u\n"
"- mapping_normal_folded:       %6u\n"
"- mapping_normal_right:        %6u\n"
"- mapping_normal_right_folded: %6u\n"
"- mapping_bold:                %6u\n"
"- mapping_bold_folded:         %6u\n"
"- mapping_bold_right:          %6u\n"
"- mapping_bold_right_folded:   %6u\n"
"- mapping_unique:              %6u\n"
"- mapping_dupe:                %6u\n",
	    glyph_total,
	    glyph_count[0],
	    glyph_count[1],
	    glyph_count[2],
	    glyph_count[3],
	    glyph_unique, glyph_dupe,
	    mapping_total,
	    map_count[0], map_folded_count[0],
	    map_count[1], map_folded_count[1],
	    map_count[2], map_folded_count[2],
	    map_count[3], map_folded_count[3],
	    mapping_unique, mapping_dupe);
}

int
main(int argc, char *argv[])
{
	int ch, val, verbose = 0, rv = 0;
	char *outfile = NULL;

	assert(sizeof (struct file_header) == 32);
	assert(sizeof (struct file_mapping) == 8);

	while ((ch = getopt(argc, argv, "nf:h:vw:o:")) != -1) {
		switch (ch) {
		case 'f':
			if (strcmp(optarg, "font") == 0)
				format = VT_FONT;
			else if (strcmp(optarg, "source") == 0)
				format = VT_C_SOURCE;
			else if (strcmp(optarg, "compressed-source") == 0)
				format = VT_C_COMPRESSED;
			else
				errx(1, "Invalid format: %s", optarg);
			break;
		case 'h':
			val = atoi(optarg);
			if (val <= 0 || val > 128)
				errx(1, "Invalid height %d", val);
			height = val;
			break;
		case 'n':
			filter = false;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'w':
			set_width(atoi(optarg));
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (outfile == NULL || argc < 1 || argc > 2)
		usage();

	wbytes = howmany(width, 8);

	if (parse_file(argv[0], VFNT_MAP_NORMAL) != 0)
		return (1);
	argc--;
	argv++;
	if (argc == 1) {
		if (parse_file(argv[0], VFNT_MAP_BOLD) != 0)
			return (1);
		argc--;
		argv++;
	}
	number_glyphs();
	dedup_mapping(VFNT_MAP_BOLD);
	dedup_mapping(VFNT_MAP_BOLD_RH);
	fold_mappings(0);
	fold_mappings(1);
	fold_mappings(2);
	fold_mappings(3);

	switch (format) {
	case VT_FONT:
		rv = write_fnt(outfile);
		break;
	case VT_C_SOURCE:
		rv = write_fnt_source(false, outfile);
		break;
	case VT_C_COMPRESSED:
		rv = write_fnt_source(true, outfile);
		break;
	}

	if (verbose)
		print_font_info();

	return (rv);
}
