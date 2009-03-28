/*******************************************************************************
 * Copyright (C) 2004-2008 Intel Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corp. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corp. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include <dlfcn.h>
#include "glue.h"

#ifdef __sun
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif	// __sun

#define PARSER_MAX 32

typedef struct parser_s {
	unsigned int count;
	char *line[PARSER_MAX];
} parser_t;


static void parser_init(parser_t *cfg)
{
	if (!cfg) {
		return;
	}

	cfg->count = 0;
}

static int parser_add(parser_t *cfg, char *buf)
{
	if ((!cfg) || (cfg->count > PARSER_MAX)) {
		return -1;
	}

	cfg->line[cfg->count] = strdup(buf);
	if (cfg->line[cfg->count]) {
		cfg->count ++;
	}

	return 0;
}

static int parser_length(parser_t *cfg)
{
	if (!cfg) {
		return 0;
	}

	return cfg->count;
}

static char *parser_get(parser_t *cfg, unsigned int index)
{
	if ((!cfg) || (index >= cfg->count)) {
		return NULL;
	}

	return (cfg->line[index]);
}


static int parser_read(parser_t *cfg, FILE *fp)
{
	char line[512];
	char *head, *tail;
	int len;

	if ((!fp) || (!cfg)) {
		return -1;
	}

	while (fgets(line, 511, fp)) {
		head = line;
		while (*head == 0x20 || *head == '\t') {
			head ++;
		}
		if ((*head == '#') || (*head == '\n') ||
		    (*head == '\r') || (*head == '\0')) {
			continue;
		}
		len = strlen(head);
		tail = head + len - 1;
		if (tail <= head) {
			continue;
		}
		while ((*tail == '\r') || (*tail == '\n')) {
			tail --;
		}
		*(tail + 1) = '\0';

		parser_add(cfg, head);
	}
	return 0;
}

static void parser_free(parser_t *cfg)
{
	unsigned int i;

	for (i = 0; i < cfg->count; i ++) {
		free(cfg->line[i]);
	}
}


/*   glue functions */

void glue::handle_init(int index, const char *file)
{
	int i = index;

	if (!file) {
		return;
	}
	printf("file:%s\n", file);

	funcs[i].handle = dlopen(file, RTLD_NOW);
	if (!funcs[i].handle) {
		printf("can't open:%s, %s\n", file, dlerror());
		return;
	}

	funcs[i].init_funcs = (lms_init_t)dlsym(funcs[i].handle,
					LMS_INIT_FUNC_NAME);
	if (!funcs[i].init_funcs) {
		printf("dl error:%s\n", dlerror());
		return;
	}

	if (LMS_OK != funcs[i].init_funcs()) {
		return;
	}

	funcs[i].version_funcs = (lms_version_t)dlsym(funcs[i].handle,
					LMS_VERSION_FUNC_NAME);
	funcs[i].pre_funcs = (lms_pre_t)dlsym(funcs[i].handle,
					LMS_PRE_FUNC_NAME);
	funcs[i].retry_funcs = (lms_retry_t)dlsym(funcs[i].handle,
					LMS_RETRY_FUNC_NAME);
	funcs[i].post_funcs = (lms_post_t)dlsym(funcs[i].handle,
					LMS_POST_FUNC_NAME);
	funcs[i].deinit_funcs = (lms_deinit_t)dlsym(funcs[i].handle,
					LMS_DEINIT_FUNC_NAME);
}

int glue::mem_init(void)
{
	int i;

	funcs = new glue_funcs[cnt];
	if (!funcs) {
		return LMS_ERROR;
	}

	for (i = 0;i < cnt; i++) {
		funcs[i].handle = NULL;
		funcs[i].init_funcs = NULL;
		funcs[i].version_funcs = NULL;
		funcs[i].pre_funcs = NULL;
		funcs[i].retry_funcs = NULL;
		funcs[i].post_funcs = NULL;
		funcs[i].deinit_funcs = NULL;
	}

	return LMS_OK;
}

glue::glue() : funcs(NULL)
{
}

glue::~glue()
{
}


int glue::init(void)
{
	FILE *fp;
	parser_t cfg;
	int i;

	parser_init(&cfg);

	fp = fopen(LMS_PLUGIN_CONFIG_FILE, "rb");
	if ((!fp) || (parser_read(&cfg, fp) != 0)) {
		cnt = 0;
		if (fp) {
			fclose(fp);
		}
		return LMS_OK;
	}

	do {
		cnt = parser_length(&cfg);
		if (0 == cnt) {
			break;
		}
		if (mem_init()) {
			break;
		}
		for (i = 0; i < cnt; i++) {
			handle_init(i, parser_get(&cfg, i));
		}
	} while (0);

	fclose(fp);
	parser_free(&cfg);
	return LMS_OK;
}

void glue::deinit(void)
{
	int i;

	if (!funcs) {
		return;
	}

	for (i = 0; i < cnt; i++) {
		if (funcs[i].deinit_funcs) {
			funcs[i].deinit_funcs();
		}
		if (funcs[i].handle) {
			dlclose(funcs[i].handle);
		}
	}

	delete[] funcs;
}

void glue::version(unsigned char version)
{
	int i;

	if (!funcs) {
		return;
	}

	for (i = 0; i < cnt; i++) {
		if (!funcs[i].version_funcs) {
			continue;
		}
		funcs[i].version_funcs(version);
	}
}

int glue::preprocess(unsigned char *buff, int len)
{
	int i;
	int ret = LMS_ACCEPTED;

	if (!funcs) {
		return ret;
	}

	for (i = 0; i < cnt; i++) {
		if (!funcs[i].pre_funcs) {
			continue;
		}
		ret = funcs[i].pre_funcs(buff, len);
		if (ret != LMS_ACCEPTED) {
			return ret;
		}
	}

	return LMS_ACCEPTED;
}

int glue::retry(unsigned char *buff, int len)
{
	int i;
	int ret = LMS_ACCEPTED;

	if (!funcs) {
		return ret;
	}

	for (i = 0; i < cnt; i++) {
		if (!funcs[i].retry_funcs) {
			continue;
		}
		ret = funcs[i].retry_funcs(buff, len);
		if (ret != LMS_ACCEPTED) {
			return ret;
		}
	}

	return LMS_ACCEPTED;
}


int glue::postprocess(unsigned char *buff, int len, int status)
{
	int i;
	int ret = LMS_ACCEPTED;

	if (!funcs) {
		return ret;
	}

	for (i = 0; i < cnt; i++) {
		if (!funcs[i].post_funcs) {
			continue;
		}
		ret = funcs[i].post_funcs(buff, len, status);
		if (ret != LMS_ACCEPTED) {
			return ret;
		}
	}

	return LMS_ACCEPTED;
}

