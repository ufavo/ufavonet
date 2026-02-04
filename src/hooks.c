/*
 * Hooks impl.
 * Copyright (C) 2026  Luiz Gustavo Sassanovicz Borsoi
 *
 * This file is part of Ufavonet.
 *
 * Ufavonet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Ufavonet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/hooks.h"

static void log_default(void *ctx, int level, const char *restrict component, const char *restrict file, const char *restrict function, int line, const char *restrict fmt, ...);

static const ufavonet_hooks_t _hooks_default = {
	.free = free,
	.realloc = realloc,
	.log = log_default
};

static const ufavonet_log_conf_t _log_conf_default = {
	.level 	= LOG_INFO,
	.fd 	= NULL
};

ufavonet_global_t ufavonet_global = {
	.hooks = _hooks_default,
	.log_conf = _log_conf_default
};

void
ufavonet_set_hooks(const ufavonet_hooks_t hooks)
{
	if (hooks.realloc)
		ufavonet_global.hooks.realloc = hooks.realloc;
	if (hooks.free)
		ufavonet_global.hooks.free = hooks.free;
	if (hooks.log)
		ufavonet_global.hooks.log = hooks.log;
}

void
ufavonet_set_log_conf(const ufavonet_log_conf_t log)
{
	ufavonet_global.log_conf.fd = log.fd? log.fd : stderr;
	ufavonet_global.log_conf.level = log.level < 0? 0 : (log.level > LOG_DEBUG? LOG_DEBUG : log.level);
}

void
log_default(void *ctx, int level, const char *restrict component, const char *restrict file, const char *restrict function, int line, const char *restrict fmt, ...)
{
	(void)ctx;
	(void)level;

	FILE 			*stream;
	va_list 		ap;

	if (level > ufavonet_global.log_conf.level)
		return;

	stream = ufavonet_global.log_conf.fd;
	stream = stream? stream : stderr;

	if (component)
		fprintf(stream, "(%s) ", component);
	if (file && line && function)
		fprintf(stream, "[%s:%d at %s] ", file, line, function);

	va_start(ap, fmt);
	vfprintf(stream, fmt, ap);
	va_end(ap);
	size_t len = strlen(fmt);
	if (len > 0)
		if (fmt[len-1] != '\n')
			fputc('\n', stream);
	fflush(stream);
}
