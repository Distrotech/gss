/* pack.c --- Data formatter.
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

/* Get specification. */
#include "pack.h"

#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>

/* For packv. */
#include <limits.h>
#ifndef SIZE_MAX
# define SIZE_MAX (size_t)-1
#endif

/*
 * Pack a data buffer with data according to a printf-like template.
 *
 * %%    Write '%'.
 *
 * %c    Write 8-bit integer ('int').
 *
 * %i    Write 32-bit network byte order (little endian) integer ('int').
 *
 * [missing] Only valid together with 0-9+, in which case the
 *       character is repeated.
 *
 * NYI: %z    Write zero terminated C string ('char *').
 *
 * The modifiers are:
 *
 * 0-9+  Repeat value this many times.  Repeat count is stored in
 *       'size_t' and may wrap around if supplied value is too large.
 *
 * NYI: f     Free argument, only applies to pointer types.
 *
 * Examples:
 *
 * pack("%5c%fz", 0x41, strdup ("test"))
 *  => "AAAAAtest"
 *
 * pack("%14%")
 *  => "%%%%%%%%%%%%%%"
 *
 * pack("%7g")
 *  => "ggggggg"
 *
 */

/* Pack data in AP according to zero terminated TEMPLATE into OUT,
   which must have room for at most OUTSIZE octets.  Returns number of
   octets corresponding to expanded TEMPLATE, which can be both
   smaller and larger than OUTSIZE.  However, OUT is never written to
   out of bound, or at all if OUT is NULL (in which case OUTSIZE
   become irrelevant). */
size_t
packvn (char *out, size_t outsize, const char *template, va_list ap)
{
  size_t len = 0;

  while (*template)
    {
      int num;
      int do_free = 0;
      size_t repeat = 0;
      size_t i;

      if (*template != '%')
	{
	  if (out && len < outsize)
	    *out++ = *template;
	  len++;
	  continue;
	}

      /* Modifiers? */
      while (*++template)
	switch (*template)
	  {
	  case 'f':
	    do_free = 1;
	    break;

	  case '0':
	  case '1':
	  case '2':
	  case '3':
	  case '4':
	  case '5':
	  case '6':
	  case '7':
	  case '8':
	  case '9':
	    repeat = repeat * 10 + (*template - '0');
	    break;

	  default:
	    goto eom;
	  }
    eom:

      switch (*template)
	{
	case '%':
	  for (i = 0; i < repeat; i++)
	    {
	      if (out && len < outsize)
		*out++ = '%';
	      len++;
	    }
	  break;

	case 'c':
	  num = va_arg (ap, int);
	  for (i = 0; i < repeat; i++)
	    {
	      if (out && len < outsize)
		*out++ = num;
	      len++;
	    }
	  break;

	case 'i':
	  num = va_arg (ap, int);
	  for (i = 0; i < repeat; i++)
	    {
	      if (out && len < outsize)
		*out++ = num & 0xFF;
	      len++;
	      if (out && len < outsize)
		*out++ = num >> 8 & 0xFF;
	      len++;
	      if (out && len < outsize)
		*out++ = num >> 16 & 0xFF;
	      len++;
	      if (out && len < outsize)
		*out++ = num >> 24 & 0xFF;
	      len++;
	    }
	  break;

	default:
	  for (i = 0; i < repeat; i++)
	    {
	      if (out && len < outsize)
		*out++ = *template;
	      len++;
	    }
	  break;
	}
      template++;
    }

  return len;
}

size_t
packn (char *out, size_t outsize, const char *template, ...)
{
  va_list ap;
  size_t len;

  va_start (ap, template);
  len = packvn (out, outsize, template, ap);
  va_end (ap);

  return len;
}

size_t
packav (char **out, const char *template, va_list ap)
{
  size_t len;

  len = packvn (NULL, 0, template, ap);
  *out = malloc (len);
  len = packvn (*out, len, template, ap);

  return len;
}

size_t
packa (char **out, const char *template, ...)
{
  va_list ap;
  size_t len;

  va_start (ap, template);
  len = packav (out, template, ap);
  va_end (ap);

  return len;
}

size_t
packv (char *out, const char *template, va_list ap)
{
  return packvn (out, SIZE_MAX, template, ap);
}

size_t
pack (char *out, const char *template, ...)
{
  va_list ap;
  size_t len;

  va_start (ap, template);
  len = packv (out, template, ap);
  va_end (ap);

  return len;
}
