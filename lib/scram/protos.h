/* protos.h --- Export SCRAM GSS functions to core GSS library.
 * Copyright (C) 2012 Simon Josefsson
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

#ifndef GSS_SCRAM_PROTOS_H
#define GSS_SCRAM_PROTOS_H

/* See context.c. */
extern OM_uint32
gss_scram_init_sec_context (OM_uint32 * minor_status,
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
			    OM_uint32 * ret_flags,
			    OM_uint32 * time_rec);

extern OM_uint32
gss_scram_accept_sec_context (OM_uint32 * minor_status,
			      gss_ctx_id_t * context_handle,
			      const gss_cred_id_t acceptor_cred_handle,
			      const gss_buffer_t input_token_buffer,
			      const gss_channel_bindings_t input_chan_bindings,
			      gss_name_t * src_name,
			      gss_OID * mech_type,
			      gss_buffer_t output_token,
			      OM_uint32 * ret_flags,
			      OM_uint32 * time_rec,
			      gss_cred_id_t * delegated_cred_handle);

extern OM_uint32
gss_scram_delete_sec_context (OM_uint32 * minor_status,
			      gss_ctx_id_t * context_handle,
			      gss_buffer_t output_token);

#endif /* GSS_SCRAM_PROTOS_H */
