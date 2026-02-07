/*
 * Timing utility.
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

#ifndef __ufavonet_utime_h__
#define __ufavonet_utime_h__

#define _POSIX_C_SOURCE 199309L

#include <time.h>
#include <stdint.h>

typedef struct {
	struct timespec tp;
} utime_t;

static inline int_fast64_t
utime_remaining(utime_t *restrict t, const int_fast64_t target_us)
{
	struct timespec tp;

	clock_gettime(CLOCK_MONOTONIC, &tp);

	const int_fast64_t elapsed = ((tp.tv_sec - t->tp.tv_sec) * 1000000L) + ((tp.tv_nsec - t->tp.tv_nsec) / 1000L);
	if (elapsed >= target_us)
		t->tp = tp;
	return target_us - elapsed;
}

static inline void
utime_usleep(const int_fast64_t us)
{
	if (us <= 0) return;

	struct timespec tp = {
		.tv_sec		= us / 1000000L,
		.tv_nsec	= (us % 1000000L) * 1000L 
	};
	while (nanosleep(&tp, &tp) == -1);
}

#endif
