/*
 * Hooks internal header.
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

#ifndef __ufavonet_hooks_internal_h__
#define __ufavonet_hooks_internal_h__

#include <stdint.h>
#include <inttypes.h>
#include "../include/hooks.h"

extern ufavonet_global_t ufavonet_global;

#define umalloc(size) 	ufavonet_global.hooks.realloc(NULL, (size))
#define urealloc 		ufavonet_global.hooks.realloc
#define ufree 			ufavonet_global.hooks.free

#define uthash_malloc 		umalloc
#define uthash_free(ptr,sz)	ufree(ptr)

#define HASH_NONFATAL_OOM 1
#define uthash_nonfatal_oom(elt) ufavonet_global.uthash_oom = 1

#define ulogf(lvl,...) 	ufavonet_global.hooks.log(NULL, (lvl), "ufavonet", __FILE__, __func__, __LINE__, __VA_ARGS__)

#define ulogf_dbg(...) ulogf(LOG_DEBUG,		__VA_ARGS__)
#define ulogf_inf(...) ulogf(LOG_INFO,		__VA_ARGS__)
#define ulogf_ntc(...) ulogf(LOG_NOTICE,	__VA_ARGS__)
#define ulogf_wrn(...) ulogf(LOG_WARNING,	__VA_ARGS__)
#define ulogf_err(...) ulogf(LOG_ERR,		__VA_ARGS__)
#define ulogf_crt(...) ulogf(LOG_CRIT,		__VA_ARGS__)
#define ulogf_alr(...) ulogf(LOG_ALERT,		__VA_ARGS__)
#define ulogf_emr(...) ulogf(LOG_EMERG,		__VA_ARGS__)

#ifdef LOG_STRIP
	#if LOG_STRIP <= LOG_DEBUG
		#undef ulogf_dbg
		#define ulogf_dbg(...)
	#endif
	#if LOG_STRIP <= LOG_INFO
		#undef	ulogf_inf
		#define ulogf_inf(...)
	#endif
	#if LOG_STRIP <= LOG_NOTICE
		#undef	ulogf_ntc
		#define ulogf_ntc(...)
	#endif
	#if LOG_STRIP <= LOG_WARNING
		#undef	ulogf_wrn
		#define ulogf_wrn(...)
	#endif
	#if LOG_STRIP <= LOG_ERR
		#undef	ulogf_err
		#define ulogf_err(...)
	#endif
	#if LOG_STRIP <= LOG_CRIT
		#undef	ulogf_crt
		#define ulogf_crt(...)
	#endif
	#if LOG_STRIP <= LOG_ALERT
		#undef	ulogf_alr
		#define ulogf_alr(...)
	#endif
	#if LOG_STRIP <= LOG_EMERG
		#undef	ulogf_emr
		#define ulogf_emr(...)
	#endif
#endif

#ifdef _WIN32
#define ulog_errnof(fmt,...) \
do { \
	char *x = NULL; \
	DWORD err = WSAGetLastError(); \
	if (!FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, (LPTSTR)&x, 0, NULL)) { \
		ulogf_err(fmt ". WSA error: %" PRIi32 , __VA_ARGS__, (int)(err)); \
	} else { \
		ulogf_err(fmt ": %s", __VA_ARGS__, x); \
	} \
	HeapFree(GetProcessHeap(), 0, x); \
} while (0)
#else
#define ulog_errnof(fmt,...) ulogf_err(fmt ": %s", __VA_ARGS__, strerror((errno)))
#endif

#define ulog_errno(str) ulog_errnof("%s",str)

#endif
