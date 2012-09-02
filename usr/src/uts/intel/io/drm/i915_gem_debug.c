/* BEGIN CSTYLED */

/*
 * Copyright (c) 2009, Intel Corporation.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Authors:
 *    Keith Packard <keithp@keithp.com>
 *
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "drmP.h"
#include "drm.h"
#include "i915_drm.h"
#include "i915_drv.h"

#define BUFFER_FAIL(_count, _len, _name) { 			\
	DRM_ERROR("Buffer size too small in %s (%d < %d)\n",	\
	    (_name), (_count), (_len));				\
	(*failures)++;						\
	return count;						\
}


static uint32_t saved_s2 = 0, saved_s4 = 0;
static char saved_s2_set = 0, saved_s4_set = 0;

static void
instr_out(uint32_t *data, uint32_t hw_offset, unsigned int index,
	  const char *fmt, ...)
{

    DRM_ERROR("0x%08x: 0x%08x:%s ", hw_offset + index * 4, data[index],
	    index == 0 ? "" : "  ");
        va_list ap;

        va_start(ap, fmt);
        vcmn_err(CE_WARN, fmt, ap);
        va_end(ap);

}

static int
decode_mi(uint32_t *data, int count, uint32_t hw_offset, int *failures)
{
    unsigned int opcode;

    struct {
	uint32_t opcode;
	int min_len;
	int max_len;
	char *name;
    } opcodes_mi[] = {
	{ 0x08, 1, 1, "MI_ARB_ON_OFF" },
	{ 0x0a, 1, 1, "MI_BATCH_BUFFER_END" },
	{ 0x31, 2, 2, "MI_BATCH_BUFFER_START" },
	{ 0x14, 3, 3, "MI_DISPLAY_BUFFER_INFO" },
	{ 0x04, 1, 1, "MI_FLUSH" },
	{ 0x22, 3, 3, "MI_LOAD_REGISTER_IMM" },
	{ 0x13, 2, 2, "MI_LOAD_SCAN_LINES_EXCL" },
	{ 0x12, 2, 2, "MI_LOAD_SCAN_LINES_INCL" },
	{ 0x00, 1, 1, "MI_NOOP" },
	{ 0x11, 2, 2, "MI_OVERLAY_FLIP" },
	{ 0x07, 1, 1, "MI_REPORT_HEAD" },
	{ 0x18, 2, 2, "MI_SET_CONTEXT" },
	{ 0x20, 3, 4, "MI_STORE_DATA_IMM" },
	{ 0x21, 3, 4, "MI_STORE_DATA_INDEX" },
	{ 0x24, 3, 3, "MI_STORE_REGISTER_MEM" },
	{ 0x02, 1, 1, "MI_USER_INTERRUPT" },
	{ 0x03, 1, 1, "MI_WAIT_FOR_EVENT" },
    };


    for (opcode = 0; opcode < sizeof(opcodes_mi) / sizeof(opcodes_mi[0]);
	 opcode++) {
	if ((data[0] & 0x1f800000) >> 23 == opcodes_mi[opcode].opcode) {
	    unsigned int len = 1, i;

	    instr_out(data, hw_offset, 0, "%s\n", opcodes_mi[opcode].name);
	    if (opcodes_mi[opcode].max_len > 1) {
		len = (data[0] & 0x000000ff) + 2;
		if (len < opcodes_mi[opcode].min_len ||
		    len > opcodes_mi[opcode].max_len)
		{
		    DRM_ERROR("Bad length in %s\n",
			    opcodes_mi[opcode].name);
		}
	    }

	    for (i = 1; i < len; i++) {
		if (i >= count)
		    BUFFER_FAIL(count, len, opcodes_mi[opcode].name);
		instr_out(data, hw_offset, i, "dword %d\n", i);
	    }

	    return len;
	}
    }

    instr_out(data, hw_offset, 0, "MI UNKNOWN\n");
    (*failures)++;
    return 1;
}

static int
decode_2d(uint32_t *data, int count, uint32_t hw_offset, int *failures)
{
    unsigned int opcode, len;
    char *format = NULL;

    struct {
	uint32_t opcode;
	int min_len;
	int max_len;
	char *name;
    } opcodes_2d[] = {
	{ 0x40, 5, 5, "COLOR_BLT" },
	{ 0x43, 6, 6, "SRC_COPY_BLT" },
	{ 0x01, 8, 8, "XY_SETUP_BLT" },
	{ 0x11, 9, 9, "XY_SETUP_MONO_PATTERN_SL_BLT" },
	{ 0x03, 3, 3, "XY_SETUP_CLIP_BLT" },
	{ 0x24, 2, 2, "XY_PIXEL_BLT" },
	{ 0x25, 3, 3, "XY_SCANLINES_BLT" },
	{ 0x26, 4, 4, "Y_TEXT_BLT" },
	{ 0x31, 5, 134, "XY_TEXT_IMMEDIATE_BLT" },
	{ 0x50, 6, 6, "XY_COLOR_BLT" },
	{ 0x51, 6, 6, "XY_PAT_BLT" },
	{ 0x76, 8, 8, "XY_PAT_CHROMA_BLT" },
	{ 0x72, 7, 135, "XY_PAT_BLT_IMMEDIATE" },
	{ 0x77, 9, 137, "XY_PAT_CHROMA_BLT_IMMEDIATE" },
	{ 0x52, 9, 9, "XY_MONO_PAT_BLT" },
	{ 0x59, 7, 7, "XY_MONO_PAT_FIXED_BLT" },
	{ 0x53, 8, 8, "XY_SRC_COPY_BLT" },
	{ 0x54, 8, 8, "XY_MONO_SRC_COPY_BLT" },
	{ 0x71, 9, 137, "XY_MONO_SRC_COPY_IMMEDIATE_BLT" },
	{ 0x55, 9, 9, "XY_FULL_BLT" },
	{ 0x55, 9, 137, "XY_FULL_IMMEDIATE_PATTERN_BLT" },
	{ 0x56, 9, 9, "XY_FULL_MONO_SRC_BLT" },
	{ 0x75, 10, 138, "XY_FULL_MONO_SRC_IMMEDIATE_PATTERN_BLT" },
	{ 0x57, 12, 12, "XY_FULL_MONO_PATTERN_BLT" },
	{ 0x58, 12, 12, "XY_FULL_MONO_PATTERN_MONO_SRC_BLT" },
    };

    switch ((data[0] & 0x1fc00000) >> 22) {
    case 0x50:
	instr_out(data, hw_offset, 0,
		  "XY_COLOR_BLT (rgb %sabled, alpha %sabled, dst tile %d)\n",
		  (data[0] & (1 << 20)) ? "en" : "dis",
		  (data[0] & (1 << 21)) ? "en" : "dis",
		  (data[0] >> 11) & 1);

	len = (data[0] & 0x000000ff) + 2;
	if (len != 6)
	    DRM_ERROR("Bad count in XY_COLOR_BLT\n");
	if (count < 6)
	    BUFFER_FAIL(count, len, "XY_COLOR_BLT");

	switch ((data[1] >> 24) & 0x3) {
	case 0:
	    format="8";
	    break;
	case 1:
	    format="565";
	    break;
	case 2:
	    format="1555";
	    break;
	case 3:
	    format="8888";
	    break;
	}

	instr_out(data, hw_offset, 1, "format %s, pitch %d, "
		  "clipping %sabled\n", format,
		  (short)(data[1] & 0xffff),
		  data[1] & (1 << 30) ? "en" : "dis");
	instr_out(data, hw_offset, 2, "(%d,%d)\n",
		  data[2] & 0xffff, data[2] >> 16);
	instr_out(data, hw_offset, 3, "(%d,%d)\n",
		  data[3] & 0xffff, data[3] >> 16);
	instr_out(data, hw_offset, 4, "offset 0x%08x\n", data[4]);
	instr_out(data, hw_offset, 5, "color\n");
	return len;
    case 0x53:
	instr_out(data, hw_offset, 0,
		  "XY_SRC_COPY_BLT (rgb %sabled, alpha %sabled, "
		  "src tile %d, dst tile %d)\n",
		  (data[0] & (1 << 20)) ? "en" : "dis",
		  (data[0] & (1 << 21)) ? "en" : "dis",
		  (data[0] >> 15) & 1,
		  (data[0] >> 11) & 1);

	len = (data[0] & 0x000000ff) + 2;
	if (len != 8)
	    DRM_ERROR("Bad count in XY_SRC_COPY_BLT\n");
	if (count < 8)
	    BUFFER_FAIL(count, len, "XY_SRC_COPY_BLT");

	switch ((data[1] >> 24) & 0x3) {
	case 0:
	    format="8";
	    break;
	case 1:
	    format="565";
	    break;
	case 2:
	    format="1555";
	    break;
	case 3:
	    format="8888";
	    break;
	}

	instr_out(data, hw_offset, 1, "format %s, dst pitch %d, "
		  "clipping %sabled\n", format,
		  (short)(data[1] & 0xffff),
		  data[1] & (1 << 30) ? "en" : "dis");
	instr_out(data, hw_offset, 2, "dst (%d,%d)\n",
		  data[2] & 0xffff, data[2] >> 16);
	instr_out(data, hw_offset, 3, "dst (%d,%d)\n",
		  data[3] & 0xffff, data[3] >> 16);
	instr_out(data, hw_offset, 4, "dst offset 0x%08x\n", data[4]);
	instr_out(data, hw_offset, 5, "src (%d,%d)\n",
		  data[5] & 0xffff, data[5] >> 16);
	instr_out(data, hw_offset, 6, "src pitch %d\n",
		  (short)(data[6] & 0xffff));
	instr_out(data, hw_offset, 7, "src offset 0x%08x\n", data[7]);
	return len;
    }

    for (opcode = 0; opcode < sizeof(opcodes_2d) / sizeof(opcodes_2d[0]);
	 opcode++) {
	if ((data[0] & 0x1fc00000) >> 22 == opcodes_2d[opcode].opcode) {
	    unsigned int i;

	    len = 1;
	    instr_out(data, hw_offset, 0, "%s\n", opcodes_2d[opcode].name);
	    if (opcodes_2d[opcode].max_len > 1) {
		len = (data[0] & 0x000000ff) + 2;
		if (len < opcodes_2d[opcode].min_len ||
		    len > opcodes_2d[opcode].max_len)
		{
		    DRM_ERROR("Bad count in %s\n", opcodes_2d[opcode].name);
		}
	    }

	    for (i = 1; i < len; i++) {
		if (i >= count)
		    BUFFER_FAIL(count, len, opcodes_2d[opcode].name);
		instr_out(data, hw_offset, i, "dword %d\n", i);
	    }

	    return len;
	}
    }

    instr_out(data, hw_offset, 0, "2D UNKNOWN\n");
    (*failures)++;
    return 1;
}

/*ARGSUSED*/
static int
decode_3d_1c(uint32_t *data, int count, uint32_t hw_offset, int *failures)
{
    switch ((data[0] & 0x00f80000) >> 19) {
    case 0x11:
	instr_out(data, hw_offset, 0, "3DSTATE_DEPTH_SUBRECTANGLE_DISALBE\n");
	return 1;
    case 0x10:
	instr_out(data, hw_offset, 0, "3DSTATE_SCISSOR_ENABLE\n");
	return 1;
    case 0x01:
	instr_out(data, hw_offset, 0, "3DSTATE_MAP_COORD_SET_I830\n");
	return 1;
    case 0x0a:
	instr_out(data, hw_offset, 0, "3DSTATE_MAP_CUBE_I830\n");
	return 1;
    case 0x05:
	instr_out(data, hw_offset, 0, "3DSTATE_MAP_TEX_STREAM_I830\n");
	return 1;
    }

    instr_out(data, hw_offset, 0, "3D UNKNOWN\n");
    (*failures)++;
    return 1;
}

static int
decode_3d_1d(uint32_t *data, int count, uint32_t hw_offset, int *failures, int i830)
{
    unsigned int len, i, c, opcode, word, map, sampler, instr;

    struct {
	uint32_t opcode;
	int i830_only;
	int min_len;
	int max_len;
	char *name;
    } opcodes_3d_1d[] = {
	{ 0x8e, 0, 3, 3, "3DSTATE_BUFFER_INFO" },
	{ 0x86, 0, 4, 4, "3DSTATE_CHROMA_KEY" },
	{ 0x9c, 0, 1, 1, "3DSTATE_CLEAR_PARAMETERS" },
	{ 0x88, 0, 2, 2, "3DSTATE_CONSTANT_BLEND_COLOR" },
	{ 0x99, 0, 2, 2, "3DSTATE_DEFAULT_DIFFUSE" },
	{ 0x9a, 0, 2, 2, "3DSTATE_DEFAULT_SPECULAR" },
	{ 0x98, 0, 2, 2, "3DSTATE_DEFAULT_Z" },
	{ 0x97, 0, 2, 2, "3DSTATE_DEPTH_OFFSET_SCALE" },
	{ 0x85, 0, 2, 2, "3DSTATE_DEST_BUFFER_VARIABLES" },
	{ 0x80, 0, 5, 5, "3DSTATE_DRAWING_RECTANGLE" },
	{ 0x8e, 0, 3, 3, "3DSTATE_BUFFER_INFO" },
	{ 0x9d, 0, 65, 65, "3DSTATE_FILTER_COEFFICIENTS_4X4" },
	{ 0x9e, 0, 4, 4, "3DSTATE_MONO_FILTER" },
	{ 0x89, 0, 4, 4, "3DSTATE_FOG_MODE" },
	{ 0x8f, 0, 2, 16, "3DSTATE_MAP_PALLETE_LOAD_32" },
	{ 0x81, 0, 3, 3, "3DSTATE_SCISSOR_RECTANGLE" },
	{ 0x83, 0, 2, 2, "3DSTATE_SPAN_STIPPLE" },
	{ 0x8c, 1, 2, 2, "3DSTATE_MAP_COORD_TRANSFORM_I830" },
	{ 0x8b, 1, 2, 2, "3DSTATE_MAP_VERTEX_TRANSFORM_I830" },
	{ 0x8d, 1, 3, 3, "3DSTATE_W_STATE_I830" },
	{ 0x01, 1, 2, 2, "3DSTATE_COLOR_FACTOR_I830" },
	{ 0x02, 1, 2, 2, "3DSTATE_MAP_COORD_SETBIND_I830" },
    };

    switch ((data[0] & 0x00ff0000) >> 16) {
    case 0x07:
	/* This instruction is unusual.  A 0 length means just 1 DWORD instead of
	 * 2.  The 0 length is specified in one place to be unsupported, but
	 * stated to be required in another, and 0 length LOAD_INDIRECTs appear
	 * to cause no harm at least.
	 */
	instr_out(data, hw_offset, 0, "3DSTATE_LOAD_INDIRECT\n");
	len = (data[0] & 0x000000ff) + 1;
	i = 1;
	if (data[0] & (0x01 << 8)) {
	    if (i + 2 >= count)
		BUFFER_FAIL(count, len, "3DSTATE_LOAD_INDIRECT");
	    instr_out(data, hw_offset, i++, "SIS.0\n");
	    instr_out(data, hw_offset, i++, "SIS.1\n");
	}
	if (data[0] & (0x02 << 8)) {
	    if (i + 1 >= count)
		BUFFER_FAIL(count, len, "3DSTATE_LOAD_INDIRECT");
	    instr_out(data, hw_offset, i++, "DIS.0\n");
	}
	if (data[0] & (0x04 << 8)) {
	    if (i + 2 >= count)
		BUFFER_FAIL(count, len, "3DSTATE_LOAD_INDIRECT");
	    instr_out(data, hw_offset, i++, "SSB.0\n");
	    instr_out(data, hw_offset, i++, "SSB.1\n");
	}
	if (data[0] & (0x08 << 8)) {
	    if (i + 2 >= count)
		BUFFER_FAIL(count, len, "3DSTATE_LOAD_INDIRECT");
	    instr_out(data, hw_offset, i++, "MSB.0\n");
	    instr_out(data, hw_offset, i++, "MSB.1\n");
	}
	if (data[0] & (0x10 << 8)) {
	    if (i + 2 >= count)
		BUFFER_FAIL(count, len, "3DSTATE_LOAD_INDIRECT");
	    instr_out(data, hw_offset, i++, "PSP.0\n");
	    instr_out(data, hw_offset, i++, "PSP.1\n");
	}
	if (data[0] & (0x20 << 8)) {
	    if (i + 2 >= count)
		BUFFER_FAIL(count, len, "3DSTATE_LOAD_INDIRECT");
	    instr_out(data, hw_offset, i++, "PSC.0\n");
	    instr_out(data, hw_offset, i++, "PSC.1\n");
	}
	if (len != i) {
	    DRM_ERROR("Bad count in 3DSTATE_LOAD_INDIRECT\n");
	    (*failures)++;
	    return len;
	}
	return len;
    case 0x04:
	instr_out(data, hw_offset, 0, "3DSTATE_LOAD_STATE_IMMEDIATE_1\n");
	len = (data[0] & 0x0000000f) + 2;
	i = 1;
	for (word = 0; word <= 7; word++) {
	    if (data[0] & (1 << (4 + word))) {
		if (i >= count)
		    BUFFER_FAIL(count, len, "3DSTATE_LOAD_STATE_IMMEDIATE_1");

		/* save vertex state for decode */
		if (word == 2) {
		    saved_s2_set = 1;
		    saved_s2 = data[i];
		}
		if (word == 4) {
		    saved_s4_set = 1;
		    saved_s4 = data[i];
		}

		instr_out(data, hw_offset, i++, "S%d\n", word);
	    }
	}
	if (len != i) {
	    DRM_ERROR("Bad count in 3DSTATE_LOAD_INDIRECT\n");
	    (*failures)++;
	}
	return len;
    case 0x00:
	instr_out(data, hw_offset, 0, "3DSTATE_MAP_STATE\n");
	len = (data[0] & 0x0000003f) + 2;

	i = 1;
	for (map = 0; map <= 15; map++) {
	    if (data[1] & (1 << map)) {
		if (i + 3 >= count)
		    BUFFER_FAIL(count, len, "3DSTATE_MAP_STATE");
		instr_out(data, hw_offset, i++, "map %d MS2\n", map);
		instr_out(data, hw_offset, i++, "map %d MS3\n", map);
		instr_out(data, hw_offset, i++, "map %d MS4\n", map);
	    }
	}
	if (len != i) {
	    DRM_ERROR("Bad count in 3DSTATE_MAP_STATE\n");
	    (*failures)++;
	    return len;
	}
	return len;
    case 0x06:
	instr_out(data, hw_offset, 0, "3DSTATE_PIXEL_SHADER_CONSTANTS\n");
	len = (data[0] & 0x000000ff) + 2;

	i = 1;
	for (c = 0; c <= 31; c++) {
	    if (data[1] & (1 << c)) {
		if (i + 4 >= count)
		    BUFFER_FAIL(count, len, "3DSTATE_PIXEL_SHADER_CONSTANTS");
		instr_out(data, hw_offset, i, "C%d.X = %x float\n",
			  c, data[i]);
		i++;
		instr_out(data, hw_offset, i, "C%d.Y = %x float\n",
			  c, data[i]);
		i++;
		instr_out(data, hw_offset, i, "C%d.Z = %x float\n",
			  c, data[i]);
		i++;
		instr_out(data, hw_offset, i, "C%d.W = %x float\n",
			  c, data[i]);
		i++;
	    }
	}
	if (len != i) {
	    DRM_ERROR("Bad count in 3DSTATE_MAP_STATE\n");
	    (*failures)++;
	}
	return len;
    case 0x05:
	instr_out(data, hw_offset, 0, "3DSTATE_PIXEL_SHADER_PROGRAM\n");
	len = (data[0] & 0x000000ff) + 2;
	if ((len - 1) % 3 != 0 || len > 370) {
	    DRM_ERROR("Bad count in 3DSTATE_PIXEL_SHADER_PROGRAM\n");
	    (*failures)++;
	}
	i = 1;
	for (instr = 0; instr < (len - 1) / 3; instr++) {
	    if (i + 3 >= count)
		BUFFER_FAIL(count, len, "3DSTATE_MAP_STATE");
	    instr_out(data, hw_offset, i++, "PS%03x\n", instr);
	    instr_out(data, hw_offset, i++, "PS%03x\n", instr);
	    instr_out(data, hw_offset, i++, "PS%03x\n", instr);
	}
	return len;
    case 0x01:
	if (i830)
	    break;
	instr_out(data, hw_offset, 0, "3DSTATE_SAMPLER_STATE\n");
	len = (data[0] & 0x0000003f) + 2;
	i = 1;
	for (sampler = 0; sampler <= 15; sampler++) {
	    if (data[1] & (1 << sampler)) {
		if (i + 3 >= count)
		    BUFFER_FAIL(count, len, "3DSTATE_SAMPLER_STATE");
		instr_out(data, hw_offset, i++, "sampler %d SS2\n",
			  sampler);
		instr_out(data, hw_offset, i++, "sampler %d SS3\n",
			  sampler);
		instr_out(data, hw_offset, i++, "sampler %d SS4\n",
			  sampler);
	    }
	}
	if (len != i) {
	    DRM_ERROR("Bad count in 3DSTATE_SAMPLER_STATE\n");
	    (*failures)++;
	}
	return len;
    }

    for (opcode = 0; opcode < sizeof(opcodes_3d_1d) / sizeof(opcodes_3d_1d[0]);
	 opcode++)
    {
	if (opcodes_3d_1d[opcode].i830_only && !i830)
	    continue;

	if (((data[0] & 0x00ff0000) >> 16) == opcodes_3d_1d[opcode].opcode) {
	    len = 1;

	    instr_out(data, hw_offset, 0, "%s\n", opcodes_3d_1d[opcode].name);
	    if (opcodes_3d_1d[opcode].max_len > 1) {
		len = (data[0] & 0x0000ffff) + 2;
		if (len < opcodes_3d_1d[opcode].min_len ||
		    len > opcodes_3d_1d[opcode].max_len)
		{
		    DRM_ERROR("Bad count in %s\n",
			    opcodes_3d_1d[opcode].name);
		    (*failures)++;
		}
	    }

	    for (i = 1; i < len; i++) {
		if (i >= count)
		    BUFFER_FAIL(count, len,  opcodes_3d_1d[opcode].name);
		instr_out(data, hw_offset, i, "dword %d\n", i);
	    }

	    return len;
	}
    }

    instr_out(data, hw_offset, 0, "3D UNKNOWN\n");
    (*failures)++;
    return 1;
}

static int
decode_3d_primitive(uint32_t *data, int count, uint32_t hw_offset,
		    int *failures)
{
    char immediate = (data[0] & (1 << 23)) == 0;
    unsigned int len, i;
    char *primtype;

    switch ((data[0] >> 18) & 0xf) {
    case 0x0: primtype = "TRILIST"; break;
    case 0x1: primtype = "TRISTRIP"; break;
    case 0x2: primtype = "TRISTRIP_REVERSE"; break;
    case 0x3: primtype = "TRIFAN"; break;
    case 0x4: primtype = "POLYGON"; break;
    case 0x5: primtype = "LINELIST"; break;
    case 0x6: primtype = "LINESTRIP"; break;
    case 0x7: primtype = "RECTLIST"; break;
    case 0x8: primtype = "POINTLIST"; break;
    case 0x9: primtype = "DIB"; break;
    case 0xa: primtype = "CLEAR_RECT"; break;
    default: primtype = "unknown"; break;
    }

    /* XXX: 3DPRIM_DIB not supported */
    if (immediate) {
	len = (data[0] & 0x0003ffff) + 2;
	instr_out(data, hw_offset, 0, "3DPRIMITIVE inline %s\n", primtype);
	if (count < len)
	    BUFFER_FAIL(count, len,  "3DPRIMITIVE inline");
	if (!saved_s2_set || !saved_s4_set) {
	    DRM_ERROR("unknown vertex format\n");
	    for (i = 1; i < len; i++) {
		instr_out(data, hw_offset, i,
			  "           vertex data (%x float)\n",
			  data[i]);
	    }
	} else {
	    unsigned int vertex = 0;
	    for (i = 1; i < len;) {
		unsigned int tc;

#define VERTEX_OUT(fmt, ...) {					\
    if (i < len)							\
	instr_out(data, hw_offset, i, " V%d."fmt"\n", vertex, __VA_ARGS__); \
    else								\
	DRM_ERROR(" missing data in V%d\n", vertex);			\
    i++;								\
}

		VERTEX_OUT("X = %x float", data[i]);
		VERTEX_OUT("Y = %x float", data[i]);
	        switch (saved_s4 >> 6 & 0x7) {
		case 0x1:
		    VERTEX_OUT("Z = %x float", data[i]);
		    break;
		case 0x2:
		    VERTEX_OUT("Z = %x float", data[i]);
		    VERTEX_OUT("W = %x float", data[i]);
		    break;
		case 0x3:
		    break;
		case 0x4:
		    VERTEX_OUT("W = %x float", data[i]);
		    break;
		default:
		    DRM_ERROR("bad S4 position mask\n");
		}

		if (saved_s4 & (1 << 10)) {
		    VERTEX_OUT("color = (A=0x%02x, R=0x%02x, G=0x%02x, "
			       "B=0x%02x)",
			       data[i] >> 24,
			       (data[i] >> 16) & 0xff,
			       (data[i] >> 8) & 0xff,
			       data[i] & 0xff);
		}
		if (saved_s4 & (1 << 11)) {
		    VERTEX_OUT("spec = (A=0x%02x, R=0x%02x, G=0x%02x, "
			       "B=0x%02x)",
			       data[i] >> 24,
			       (data[i] >> 16) & 0xff,
			       (data[i] >> 8) & 0xff,
			       data[i] & 0xff);
		}
		if (saved_s4 & (1 << 12))
		    VERTEX_OUT("width = 0x%08x)", data[i]);

		for (tc = 0; tc <= 7; tc++) {
		    switch ((saved_s2 >> (tc * 4)) & 0xf) {
		    case 0x0:
			VERTEX_OUT("T%d.X = %x float", tc, data[i]);
			VERTEX_OUT("T%d.Y = %x float", tc, data[i]);
			break;
		    case 0x1:
			VERTEX_OUT("T%d.X = %x float", tc, data[i]);
			VERTEX_OUT("T%d.Y = %x float", tc, data[i]);
			VERTEX_OUT("T%d.Z = %x float", tc, data[i]);
			break;
		    case 0x2:
			VERTEX_OUT("T%d.X = %x float", tc, data[i]);
			VERTEX_OUT("T%d.Y = %x float", tc, data[i]);
			VERTEX_OUT("T%d.Z = %x float", tc, data[i]);
			VERTEX_OUT("T%d.W = %x float", tc, data[i]);
			break;
		    case 0x3:
			VERTEX_OUT("T%d.X = %x float", tc, data[i]);
			break;
		    case 0x4:
			VERTEX_OUT("T%d.XY = 0x%08x half-float", tc, data[i]);
			break;
		    case 0x5:
			VERTEX_OUT("T%d.XY = 0x%08x half-float", tc, data[i]);
			VERTEX_OUT("T%d.ZW = 0x%08x half-float", tc, data[i]);
			break;
		    case 0xf:
			break;
		    default:
			DRM_ERROR("bad S2.T%d format\n", tc);
		    }
		}
		vertex++;
	    }
	}
    } else {
	/* indirect vertices */
	len = data[0] & 0x0000ffff; /* index count */
	if (data[0] & (1 << 17)) {
	    /* random vertex access */
	    if (count < (len + 1) / 2 + 1)
		BUFFER_FAIL(count, (len + 1) / 2 + 1, "3DPRIMITIVE random indirect");
	    instr_out(data, hw_offset, 0,
		      "3DPRIMITIVE random indirect %s (%d)\n", primtype, len);
	    if (len == 0) {
		/* vertex indices continue until 0xffff is found */
		for (i = 1; i < count; i++) {
		    if ((data[i] & 0xffff) == 0xffff) {
			instr_out(data, hw_offset, i,
				  "            indices: (terminator)\n");
			return i;
		    } else if ((data[i] >> 16) == 0xffff) {
			instr_out(data, hw_offset, i,
				  "            indices: 0x%04x, "
				  "(terminator)\n",
				  data[i] & 0xffff);
			return i;
		    } else {
			instr_out(data, hw_offset, i,
				  "            indices: 0x%04x, 0x%04x\n",
				  data[i] & 0xffff, data[i] >> 16);
		    }
		}
		DRM_ERROR("3DPRIMITIVE: no terminator found in index buffer\n");
		(*failures)++;
		return count;
	    } else {
		/* fixed size vertex index buffer */
		for (i = 0; i < len; i += 2) {
		    if (i * 2 == len - 1) {
			instr_out(data, hw_offset, i,
				  "            indices: 0x%04x\n",
				  data[i] & 0xffff);
		    } else {
			instr_out(data, hw_offset, i,
				  "            indices: 0x%04x, 0x%04x\n",
				  data[i] & 0xffff, data[i] >> 16);
		    }
		}
	    }
	    return (len + 1) / 2 + 1;
	} else {
	    /* sequential vertex access */
	    if (count < 2)
		BUFFER_FAIL(count, 2, "3DPRIMITIVE seq indirect");
	    instr_out(data, hw_offset, 0,
		      "3DPRIMITIVE sequential indirect %s, %d starting from "
		      "%d\n", primtype, len, data[1] & 0xffff);
	    instr_out(data, hw_offset, 1, "           start\n");
	    return 2;
	}
    }

    return len;
}

static int
decode_3d(uint32_t *data, int count, uint32_t hw_offset, int *failures)
{
    unsigned int opcode;

    struct {
	uint32_t opcode;
	int min_len;
	int max_len;
	char *name;
    } opcodes_3d[] = {
	{ 0x06, 1, 1, "3DSTATE_ANTI_ALIASING" },
	{ 0x08, 1, 1, "3DSTATE_BACKFACE_STENCIL_OPS" },
	{ 0x09, 1, 1, "3DSTATE_BACKFACE_STENCIL_MASKS" },
	{ 0x16, 1, 1, "3DSTATE_COORD_SET_BINDINGS" },
	{ 0x15, 1, 1, "3DSTATE_FOG_COLOR" },
	{ 0x0b, 1, 1, "3DSTATE_INDEPENDENT_ALPHA_BLEND" },
	{ 0x0d, 1, 1, "3DSTATE_MODES_4" },
	{ 0x0c, 1, 1, "3DSTATE_MODES_5" },
	{ 0x07, 1, 1, "3DSTATE_RASTERIZATION_RULES" },
    };

    switch ((data[0] & 0x1f000000) >> 24) {
    case 0x1f:
	return decode_3d_primitive(data, count, hw_offset, failures);
    case 0x1d:
	return decode_3d_1d(data, count, hw_offset, failures, 0);
    case 0x1c:
	return decode_3d_1c(data, count, hw_offset, failures);
    }

    for (opcode = 0; opcode < sizeof(opcodes_3d) / sizeof(opcodes_3d[0]);
	 opcode++) {
	if ((data[0] & 0x1f000000) >> 24 == opcodes_3d[opcode].opcode) {
	    unsigned int len = 1, i;

	    instr_out(data, hw_offset, 0, "%s\n", opcodes_3d[opcode].name);
	    if (opcodes_3d[opcode].max_len > 1) {
		len = (data[0] & 0xff) + 2;
		if (len < opcodes_3d[opcode].min_len ||
		    len > opcodes_3d[opcode].max_len)
		{
		    DRM_ERROR("Bad count in %s\n", opcodes_3d[opcode].name);
		}
	    }

	    for (i = 1; i < len; i++) {
		if (i >= count)
		    BUFFER_FAIL(count, len, opcodes_3d[opcode].name);
		instr_out(data, hw_offset, i, "dword %d\n", i);
	    }
	    return len;
	}
    }

    instr_out(data, hw_offset, 0, "3D UNKNOWN\n");
    (*failures)++;
    return 1;
}

static const char *
get_965_surfacetype(unsigned int surfacetype)
{
    switch (surfacetype) {
    case 0: return "1D";
    case 1: return "2D";
    case 2: return "3D";
    case 3: return "CUBE";
    case 4: return "BUFFER";
    case 7: return "NULL";
    default: return "unknown";
    }
}

static const char *
get_965_depthformat(unsigned int depthformat)
{
    switch (depthformat) {
    case 0: return "s8_z24float";
    case 1: return "z32float";
    case 2: return "z24s8";
    case 5: return "z16";
    default: return "unknown";
    }
}

static int
decode_3d_965(uint32_t *data, int count, uint32_t hw_offset, int *failures)
{
    unsigned int opcode, len;

    struct {
	uint32_t opcode;
	int min_len;
	int max_len;
	char *name;
    } opcodes_3d[] = {
	{ 0x6000, 3, 3, "URB_FENCE" },
	{ 0x6001, 2, 2, "CS_URB_STATE" },
	{ 0x6002, 2, 2, "CONSTANT_BUFFER" },
	{ 0x6101, 6, 6, "STATE_BASE_ADDRESS" },
	{ 0x6102, 2, 2 , "STATE_SIP" },
	{ 0x6104, 1, 1, "3DSTATE_PIPELINE_SELECT" },
	{ 0x680b, 1, 1, "3DSTATE_VF_STATISTICS" },
	{ 0x6904, 1, 1, "3DSTATE_PIPELINE_SELECT" },
	{ 0x7800, 7, 7, "3DSTATE_PIPELINED_POINTERS" },
	{ 0x7801, 6, 6, "3DSTATE_BINDING_TABLE_POINTERS" },
	{ 0x780b, 1, 1, "3DSTATE_VF_STATISTICS" },
	{ 0x7808, 5, 257, "3DSTATE_VERTEX_BUFFERS" },
	{ 0x7809, 3, 256, "3DSTATE_VERTEX_ELEMENTS" },
	/* 0x7808: 3DSTATE_VERTEX_BUFFERS */
	/* 0x7809: 3DSTATE_VERTEX_ELEMENTS */
	{ 0x7900, 4, 4, "3DSTATE_DRAWING_RECTANGLE" },
	{ 0x7901, 5, 5, "3DSTATE_CONSTANT_COLOR" },
	{ 0x7905, 5, 7, "3DSTATE_DEPTH_BUFFER" },
	{ 0x7906, 2, 2, "3DSTATE_POLY_STIPPLE_OFFSET" },
	{ 0x7907, 33, 33, "3DSTATE_POLY_STIPPLE_PATTERN" },
	{ 0x7908, 3, 3, "3DSTATE_LINE_STIPPLE" },
	{ 0x7909, 2, 2, "3DSTATE_GLOBAL_DEPTH_OFFSET_CLAMP" },
	{ 0x790a, 3, 3, "3DSTATE_AA_LINE_PARAMETERS" },
	{ 0x7b00, 6, 6, "3DPRIMITIVE" },
    };

    len = (data[0] & 0x0000ffff) + 2;

    switch ((data[0] & 0xffff0000) >> 16) {
    case 0x6101:
	if (len != 6)
	    DRM_ERROR("Bad count in STATE_BASE_ADDRESS\n");
	if (count < 6)
	    BUFFER_FAIL(count, len, "STATE_BASE_ADDRESS");

	instr_out(data, hw_offset, 0,
		  "STATE_BASE_ADDRESS\n");

	if (data[1] & 1) {
	    instr_out(data, hw_offset, 1, "General state at 0x%08x\n",
		      data[1] & ~1);
	} else
	    instr_out(data, hw_offset, 1, "General state not updated\n");

	if (data[2] & 1) {
	    instr_out(data, hw_offset, 2, "Surface state at 0x%08x\n",
		      data[2] & ~1);
	} else
	    instr_out(data, hw_offset, 2, "Surface state not updated\n");

	if (data[3] & 1) {
	    instr_out(data, hw_offset, 3, "Indirect state at 0x%08x\n",
		      data[3] & ~1);
	} else
	    instr_out(data, hw_offset, 3, "Indirect state not updated\n");

	if (data[4] & 1) {
	    instr_out(data, hw_offset, 4, "General state upper bound 0x%08x\n",
		      data[4] & ~1);
	} else
	    instr_out(data, hw_offset, 4, "General state not updated\n");

	if (data[5] & 1) {
	    instr_out(data, hw_offset, 5, "Indirect state upper bound 0x%08x\n",
		      data[5] & ~1);
	} else
	    instr_out(data, hw_offset, 5, "Indirect state not updated\n");

	return len;
    case 0x7800:
	if (len != 7)
	    DRM_ERROR("Bad count in 3DSTATE_PIPELINED_POINTERS\n");
	if (count < 7)
	    BUFFER_FAIL(count, len, "3DSTATE_PIPELINED_POINTERS");

	instr_out(data, hw_offset, 0,
		  "3DSTATE_PIPELINED_POINTERS\n");
	instr_out(data, hw_offset, 1, "VS state\n");
	instr_out(data, hw_offset, 2, "GS state\n");
	instr_out(data, hw_offset, 3, "Clip state\n");
	instr_out(data, hw_offset, 4, "SF state\n");
	instr_out(data, hw_offset, 5, "WM state\n");
	instr_out(data, hw_offset, 6, "CC state\n");
	return len;
    case 0x7801:
	if (len != 6)
	    DRM_ERROR("Bad count in 3DSTATE_BINDING_TABLE_POINTERS\n");
	if (count < 6)
	    BUFFER_FAIL(count, len, "3DSTATE_BINDING_TABLE_POINTERS");

	instr_out(data, hw_offset, 0,
		  "3DSTATE_BINDING_TABLE_POINTERS\n");
	instr_out(data, hw_offset, 1, "VS binding table\n");
	instr_out(data, hw_offset, 2, "GS binding table\n");
	instr_out(data, hw_offset, 3, "Clip binding table\n");
	instr_out(data, hw_offset, 4, "SF binding table\n");
	instr_out(data, hw_offset, 5, "WM binding table\n");

	return len;

    case 0x7900:
	if (len != 4)
	    DRM_ERROR("Bad count in 3DSTATE_DRAWING_RECTANGLE\n");
	if (count < 4)
	    BUFFER_FAIL(count, len, "3DSTATE_DRAWING_RECTANGLE");

	instr_out(data, hw_offset, 0,
		  "3DSTATE_DRAWING_RECTANGLE\n");
	instr_out(data, hw_offset, 1, "top left: %d,%d\n",
		  data[1] & 0xffff,
		  (data[1] >> 16) & 0xffff);
	instr_out(data, hw_offset, 2, "bottom right: %d,%d\n",
		  data[2] & 0xffff,
		  (data[2] >> 16) & 0xffff);
	instr_out(data, hw_offset, 3, "origin: %d,%d\n",
		  (int)data[3] & 0xffff,
		  ((int)data[3] >> 16) & 0xffff);

	return len;

    case 0x7905:
	if (len != 5)
	    DRM_ERROR("Bad count in 3DSTATE_DEPTH_BUFFER\n");
	if (count < 5)
	    BUFFER_FAIL(count, len, "3DSTATE_DEPTH_BUFFER");

	instr_out(data, hw_offset, 0,
		  "3DSTATE_DEPTH_BUFFER\n");
	instr_out(data, hw_offset, 1, "%s, %s, pitch = %d bytes, %stiled\n",
		  get_965_surfacetype(data[1] >> 29),
		  get_965_depthformat((data[1] >> 18) & 0x7),
		  (data[1] & 0x0001ffff) + 1,
		  data[1] & (1 << 27) ? "" : "not ");
	instr_out(data, hw_offset, 2, "depth offset\n");
	instr_out(data, hw_offset, 3, "%dx%d\n",
		  ((data[3] & 0x0007ffc0) >> 6) + 1,
		  ((data[3] & 0xfff80000) >> 19) + 1);
	instr_out(data, hw_offset, 4, "volume depth\n");

	return len;
    }

    for (opcode = 0; opcode < sizeof(opcodes_3d) / sizeof(opcodes_3d[0]);
	 opcode++) {
	if ((data[0] & 0xffff0000) >> 16 == opcodes_3d[opcode].opcode) {
	    unsigned int i;
	    len = 1;

	    instr_out(data, hw_offset, 0, "%s\n", opcodes_3d[opcode].name);
	    if (opcodes_3d[opcode].max_len > 1) {
		len = (data[0] & 0xff) + 2;
		if (len < opcodes_3d[opcode].min_len ||
		    len > opcodes_3d[opcode].max_len)
		{
		    DRM_ERROR("Bad count in %s\n", opcodes_3d[opcode].name);
		}
	    }

	    for (i = 1; i < len; i++) {
		if (i >= count)
		    BUFFER_FAIL(count, len, opcodes_3d[opcode].name);
		instr_out(data, hw_offset, i, "dword %d\n", i);
	    }
	    return len;
	}
    }

    instr_out(data, hw_offset, 0, "3D UNKNOWN\n");
    (*failures)++;
    return 1;
}


static int
decode_3d_i830(uint32_t *data, int count, uint32_t hw_offset, int *failures)
{
    unsigned int opcode;

    struct {
	uint32_t opcode;
	int min_len;
	int max_len;
	char *name;
    } opcodes_3d[] = {
	{ 0x02, 1, 1, "3DSTATE_MODES_3" },
	{ 0x03, 1, 1, "3DSTATE_ENABLES_1"},
	{ 0x04, 1, 1, "3DSTATE_ENABLES_2"},
	{ 0x05, 1, 1, "3DSTATE_VFT0"},
	{ 0x06, 1, 1, "3DSTATE_AA"},
	{ 0x07, 1, 1, "3DSTATE_RASTERIZATION_RULES" },
	{ 0x08, 1, 1, "3DSTATE_MODES_1" },
	{ 0x09, 1, 1, "3DSTATE_STENCIL_TEST" },
	{ 0x0a, 1, 1, "3DSTATE_VFT1"},
	{ 0x0b, 1, 1, "3DSTATE_INDPT_ALPHA_BLEND" },
	{ 0x0c, 1, 1, "3DSTATE_MODES_5" },
	{ 0x0d, 1, 1, "3DSTATE_MAP_BLEND_OP" },
	{ 0x0e, 1, 1, "3DSTATE_MAP_BLEND_ARG" },
	{ 0x0f, 1, 1, "3DSTATE_MODES_2" },
	{ 0x15, 1, 1, "3DSTATE_FOG_COLOR" },
	{ 0x16, 1, 1, "3DSTATE_MODES_4" },
    };

    switch ((data[0] & 0x1f000000) >> 24) {
    case 0x1f:
	return decode_3d_primitive(data, count, hw_offset, failures);
    case 0x1d:
	return decode_3d_1d(data, count, hw_offset, failures, 1);
    case 0x1c:
	return decode_3d_1c(data, count, hw_offset, failures);
    }

    for (opcode = 0; opcode < sizeof(opcodes_3d) / sizeof(opcodes_3d[0]);
	 opcode++) {
	if ((data[0] & 0x1f000000) >> 24 == opcodes_3d[opcode].opcode) {
	    unsigned int len = 1, i;

	    instr_out(data, hw_offset, 0, "%s\n", opcodes_3d[opcode].name);
	    if (opcodes_3d[opcode].max_len > 1) {
		len = (data[0] & 0xff) + 2;
		if (len < opcodes_3d[opcode].min_len ||
		    len > opcodes_3d[opcode].max_len)
		{
		    DRM_ERROR("Bad count in %s\n", opcodes_3d[opcode].name);
		}
	    }

	    for (i = 1; i < len; i++) {
		if (i >= count)
		    BUFFER_FAIL(count, len, opcodes_3d[opcode].name);
		instr_out(data, hw_offset, i, "dword %d\n", i);
	    }
	    return len;
	}
    }

    instr_out(data, hw_offset, 0, "3D UNKNOWN\n");
    (*failures)++;
    return 1;
}

void i915_gem_command_decode(uint32_t *data, int count, uint32_t hw_offset, struct drm_device *dev)
{
    int index = 0;
    int failures = 0;

   while (index < count) {
	switch ((data[index] & 0xe0000000) >> 29) {
	case 0x0:
	    index += decode_mi(data + index, count - index,
			       hw_offset + index * 4, &failures);
	    break;
	case 0x2:
	    index += decode_2d(data + index, count - index,
			       hw_offset + index * 4, &failures);
	    break;
	case 0x3:
	    if (IS_I965G(dev)) {
		index += decode_3d_965(data + index, count - index,
				       hw_offset + index * 4, &failures);
	    } else if (IS_I9XX(dev)) {
		index += decode_3d(data + index, count - index,
				   hw_offset + index * 4, &failures);
	    } else {
		index += decode_3d_i830(data + index, count - index,
					hw_offset + index * 4, &failures);
	    }
	    break;
	default:
	    instr_out(data, hw_offset, index, "UNKNOWN\n");
	    failures++;
	    index++;
	    break;
	}
    }
}

