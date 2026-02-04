/*
 * Hooks header.
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

#ifndef __UFAVONET_HOOKS_HEADER__
#define __UFAVONET_HOOKS_HEADER__

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#define	LOG_EMERG 	0
#define LOG_ALERT 	1
#define LOG_CRIT 	2
#define LOG_ERR 	3
#define LOG_WARNING 4
#define LOG_NOTICE 	5
#define LOG_INFO 	6
#define LOG_DEBUG 	7

typedef struct {
	void *(*realloc)(void *,size_t);
	void (*free)(void *);

	void (*log)(void *ctx, int level, const char *restrict component, const char *restrict file, const char *restrict function, int line, const char *restrict fmt, ...);
} ufavonet_hooks_t;

typedef struct {
	FILE 	*fd;
	int 	level;
} ufavonet_log_conf_t;

typedef struct {
	ufavonet_hooks_t 	hooks;
	ufavonet_log_conf_t log_conf;
	uint8_t 			uthash_oom;
} ufavonet_global_t;

void	ufavonet_set_hooks(const ufavonet_hooks_t hooks);
/* Sets the built-in log config. Only used when log hook isn't set */
void	ufavonet_set_log_conf(const ufavonet_log_conf_t log);

#endif
