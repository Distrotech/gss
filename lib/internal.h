/* internal.h	Internal header file for GPL GSS-API.
 * Copyright (C) 2003  Simon Josefsson
 *
 * This file is part of GPL GSS-API.
 *
 * GPL GSS-API is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * GPL GSS-API is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GPL GSS-API; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _INTERNAL_H
#define _INTERNAL_H

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#endif

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif

#include "gettext.h"
#include "gss.h"
#include "gssapi.h"

#ifdef USE_KERBEROS5
#include <shishi.h>
#endif

#define _(String) dgettext (PACKAGE, String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

typedef struct gss_name_struct
{
  int length;
  char *value;
  gss_OID type;
} gss_name_desc;

typedef struct gss_cred_id_struct
{
#ifdef USE_KERBEROS5
  Shishi_tkt *tkt;
#endif
} gss_cred_id_desc;

typedef struct gss_ctx_id_struct
{
  gss_name_desc peer;
  gss_name_t peerptr;
#ifdef USE_KERBEROS5
  Shishi *sh;
  Shishi_ap *ap;
  Shishi_tkt *tkt;
#endif
} gss_ctx_id_desc;

int
_gss_wrap_token (char *oid, size_t oidlen,
		 char *in, size_t inlen,
		 char **out, size_t *outlen);

int
_gss_oid_equal (gss_OID first_oid, gss_OID second_oid);

OM_uint32
_gss_duplicate_oid (OM_uint32 * minor_status,
		    const gss_OID src_oid, gss_OID * dest_oid);

OM_uint32
krb5_gss_init_sec_context (OM_uint32 * minor_status,
			   const gss_cred_id_t initiator_cred_handle,
			   gss_ctx_id_t * context_handle,
			   const gss_name_t target_name,
			   const gss_OID mech_type,
			   OM_uint32 req_flags,
			   OM_uint32 time_req,
			   const gss_channel_bindings_t input_chan_bindings,
			   const gss_buffer_t input_token,
			   gss_OID * actual_mech_type,
			   gss_buffer_t output_token,
			   OM_uint32 * ret_flags, OM_uint32 * time_rec);

OM_uint32
krb5_gss_canonicalize_name (OM_uint32 * minor_status,
			    const gss_name_t input_name,
			    const gss_OID mech_type,
			    gss_name_t * output_name);


#endif /* _INTERNAL_H */
