/* internal.h --- Internal header file for GSS.
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009  Simon Josefsson
 *
 * This file is part of the Generic Security Service (GSS).
 *
 * GSS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GSS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GSS; if not, see http://www.gnu.org/licenses or write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef _INTERNAL_H
#define _INTERNAL_H

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <errno.h>

/* Get specification. */
#include <gss/api.h>
#include <gss/ext.h>

typedef struct gss_name_struct
{
  size_t length;
  char *value;
  gss_OID type;
} gss_name_desc;

typedef struct gss_cred_id_struct
{
  gss_OID mech;
#ifdef USE_KERBEROS5
  struct _gss_krb5_cred_struct *krb5;
#endif
} gss_cred_id_desc;

typedef struct gss_ctx_id_struct
{
  gss_OID mech;
#ifdef USE_KERBEROS5
  struct _gss_krb5_ctx_struct *krb5;
#endif
} gss_ctx_id_desc;

#endif /* _INTERNAL_H */
