/* utils.c	GPL GSS-API self tests utilities.
 * Copyright (C) 2002, 2003  Simon Josefsson
 *
 * This file is part of GPL GSS-API.
 *
 * GPL GSS-API is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GPL GSS-API is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GPL GSS-API; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#endif

#include "gss/api.h"
#include "gss/ext.h"
#ifdef USE_KERBEROS5
#include "gss/krb5.h"
#endif

static int verbose = 0;
static int debug = 0;
static int error_count = 0;
static int break_on_error = 0;

typedef void diefn (const char *fmt, ...);
volatile diefn die;

void
die (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  exit (1);
}

static void
fail (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  error_count++;
  if (break_on_error)
    exit (1);
}

static void
success (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  if (verbose)
    vfprintf (stdout, format, arg_ptr);
  va_end (arg_ptr);
}

static void
escapeprint (const unsigned char *str, int len)
{
  int i;

  if (!str || !len)
    return;

  printf ("\t ;; `");
  for (i = 0; i < len; i++)
    if ((str[i] >= 'A' && str[i] <= 'Z') ||
	(str[i] >= 'a' && str[i] <= 'z') ||
	(str[i] >= '0' && str[i] <= '9') || str[i] == '.')
      printf ("%c", str[i]);
    else
      printf ("\\x%02x", str[i]);
  printf ("' (length %d bytes)\n", len);
}

static void
hexprint (const unsigned char *str, int len)
{
  int i;

  if (!str || !len)
    return;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%02x ", str[i]);
      if ((i + 1) % 8 == 0)
	printf (" ");
      if ((i + 1) % 16 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
}

static void
binprint (const unsigned char *str, int len)
{
  int i;

  if (!str || !len)
    return;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%d%d%d%d%d%d%d%d ",
	      str[i] & 0x80 ? 1 : 0,
	      str[i] & 0x40 ? 1 : 0,
	      str[i] & 0x20 ? 1 : 0,
	      str[i] & 0x10 ? 1 : 0,
	      str[i] & 0x08 ? 1 : 0,
	      str[i] & 0x04 ? 1 : 0,
	      str[i] & 0x02 ? 1 : 0, str[i] & 0x01 ? 1 : 0);
      if ((i + 1) % 3 == 0)
	printf (" ");
      if ((i + 1) % 6 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
}
