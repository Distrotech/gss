/* pack.h --- Data formatter.
 * Copyright (C) 2004 Simon Josefsson
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this file; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.
 *
 */

#ifndef PACK_H_
# define PACK_H_

#include <stddef.h>
#include <stdarg.h>

extern size_t
packvn (char *out, size_t outsize, const char *template, va_list ap);

extern size_t
packn (char *out, size_t outsize, const char *template, ...);

extern size_t
packav (char **out, const char *template, va_list ap);

extern size_t
packa (char **out, const char *template, ...);

extern size_t
packv (char *out, const char *template, va_list ap);

extern size_t
pack (char *out, const char *template, ...);

#endif /* PACK_H */
