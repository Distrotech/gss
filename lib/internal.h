/* internal.h --- Internal header file for GSS.
 * Copyright (C) 2003, 2004  Simon Josefsson
 *
 * This file is part of the Generic Security Service (GSS).
 *
 * GSS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GSS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GSS; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
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

/* Get i18n. */
#include <gettext.h>
#define _(String) dgettext (PACKAGE, String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

/* Get specification. */
#include "api.h"
#include "ext.h"

/* Get xmalloc etc. */
#include "xalloc.h"

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
  gss_name_desc peer;
  gss_name_t peerptr;
#ifdef USE_KERBEROS5
  struct _gss_krb5_ctx_struct *krb5;
#endif
} gss_ctx_id_desc;

#define MAX_NT 5

typedef struct _gss_mech_api_struct
{
  gss_OID mech;
  gss_OID name_types[MAX_NT];
    OM_uint32 (*init_sec_context)
    (OM_uint32 * minor_status,
     const gss_cred_id_t initiator_cred_handle,
     gss_ctx_id_t * context_handle,
     const gss_name_t target_name,
     const gss_OID mech_type,
     OM_uint32 req_flags,
     OM_uint32 time_req,
     const gss_channel_bindings_t
     input_chan_bindings,
     const gss_buffer_t input_token,
     gss_OID * actual_mech_type,
     gss_buffer_t output_token, OM_uint32 * ret_flags, OM_uint32 * time_rec);
    OM_uint32 (*canonicalize_name)
    (OM_uint32 * minor_status,
     const gss_name_t input_name,
     const gss_OID mech_type, gss_name_t * output_name);
  OM_uint32 (*export_name)
    (OM_uint32 * minor_status,
     const gss_name_t input_name, gss_buffer_t exported_name);
    OM_uint32 (*wrap)
    (OM_uint32 * minor_status,
     const gss_ctx_id_t context_handle, int conf_req_flag,
     gss_qop_t qop_req,
     const gss_buffer_t input_message_buffer,
     int *conf_state, gss_buffer_t output_message_buffer);
    OM_uint32 (*unwrap)
    (OM_uint32 * minor_status,
     const gss_ctx_id_t context_handle,
     const gss_buffer_t input_message_buffer,
     gss_buffer_t output_message_buffer, int *conf_state,
     gss_qop_t * qop_state);
    OM_uint32 (*get_mic)
    (OM_uint32 * minor_status,
     const gss_ctx_id_t context_handle,
     gss_qop_t qop_req,
     const gss_buffer_t message_buffer, gss_buffer_t message_token);
    OM_uint32 (*verify_mic)
    (OM_uint32 * minor_status,
     const gss_ctx_id_t context_handle,
     const gss_buffer_t message_buffer,
     const gss_buffer_t token_buffer, gss_qop_t * qop_state);
    OM_uint32 (*display_status)
    (OM_uint32 * minor_status,
     OM_uint32 status_value, int status_type,
     const gss_OID mech_type,
     OM_uint32 * message_context, gss_buffer_t status_string);
    OM_uint32 (*acquire_cred)
    (OM_uint32 * minor_status,
     const gss_name_t desired_name,
     OM_uint32 time_req,
     const gss_OID_set desired_mechs,
     gss_cred_usage_t cred_usage,
     gss_cred_id_t * output_cred_handle,
     gss_OID_set * actual_mechs, OM_uint32 * time_rec);
  OM_uint32 (*release_cred)
    (OM_uint32 * minor_status, gss_cred_id_t * cred_handle);
    OM_uint32 (*accept_sec_context)
    (OM_uint32 * minor_status,
     gss_ctx_id_t * context_handle,
     const gss_cred_id_t acceptor_cred_handle,
     const gss_buffer_t input_token_buffer,
     const gss_channel_bindings_t
     input_chan_bindings,
     gss_name_t * src_name,
     gss_OID * mech_type,
     gss_buffer_t output_token,
     OM_uint32 * ret_flags,
     OM_uint32 * time_rec, gss_cred_id_t * delegated_cred_handle);
    OM_uint32 (*delete_sec_context)
    (OM_uint32 * minor_status,
     gss_ctx_id_t * context_handle, gss_buffer_t output_token);
    OM_uint32 (*context_time)
    (OM_uint32 * minor_status,
     const gss_ctx_id_t context_handle, OM_uint32 * time_rec);
    OM_uint32 (*inquire_cred)
    (OM_uint32 * minor_status,
     const gss_cred_id_t cred_handle,
     gss_name_t * name, OM_uint32 * lifetime,
     gss_cred_usage_t * cred_usage, gss_OID_set * mechanisms);
} _gss_mech_api_desc, *_gss_mech_api_t;

_gss_mech_api_t _gss_find_mech (gss_OID oid);

#endif /* _INTERNAL_H */
