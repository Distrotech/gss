/* name.c	Implementation of GSS-API Name Manipulation functions.
 * Copyright (C) 2003  Simon Josefsson
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

#include "internal.h"

OM_uint32
gss_get_mic (OM_uint32 * minor_status,
	     const gss_ctx_id_t context_handle,
	     gss_qop_t qop_req,
	     const gss_buffer_t message_buffer, gss_buffer_t message_token)
{
  _gss_mech_api_t mech;

  if (!context_handle)
    return GSS_S_NO_CONTEXT;

  mech = _gss_find_mech (context_handle->mech);

  return mech->get_mic (minor_status, context_handle, qop_req,
			message_buffer, message_token);
}

OM_uint32
gss_verify_mic (OM_uint32 * minor_status,
		const gss_ctx_id_t context_handle,
		const gss_buffer_t message_buffer,
		const gss_buffer_t token_buffer, gss_qop_t * qop_state)
{
  _gss_mech_api_t mech;

  if (!context_handle)
    return GSS_S_NO_CONTEXT;

  mech = _gss_find_mech (context_handle->mech);

  return mech->verify_mic (minor_status, context_handle,
			   message_buffer, token_buffer, qop_state);
}

OM_uint32
gss_wrap (OM_uint32 * minor_status,
	  const gss_ctx_id_t context_handle,
	  int conf_req_flag,
	  gss_qop_t qop_req,
	  const gss_buffer_t input_message_buffer,
	  int *conf_state, gss_buffer_t output_message_buffer)
{
  _gss_mech_api_t mech;

  if (!context_handle)
    return GSS_S_NO_CONTEXT;

  mech = _gss_find_mech (context_handle->mech);

  return mech->wrap (minor_status, context_handle, conf_req_flag, qop_req,
		     input_message_buffer, conf_state,
		     output_message_buffer);
}

OM_uint32
gss_unwrap (OM_uint32 * minor_status,
	    const gss_ctx_id_t context_handle,
	    const gss_buffer_t input_message_buffer,
	    gss_buffer_t output_message_buffer,
	    int *conf_state, gss_qop_t * qop_state)
{
  _gss_mech_api_t mech;

  if (!context_handle)
    return GSS_S_NO_CONTEXT;

  mech = _gss_find_mech (context_handle->mech);

  return mech->unwrap (minor_status, context_handle, input_message_buffer,
		       output_message_buffer, conf_state, qop_state);
}
