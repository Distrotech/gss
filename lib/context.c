/* context.c	Implementation of GSS-API Context functions.
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

#include "internal.h"

/**
 * gss_init_sec_context:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @initiator_cred_handle: (gss_cred_id_t, read, optional) Handle for
 *   credentials claimed.  Supply GSS_C_NO_CREDENTIAL to act as a
 *   default initiator principal.  If no default initiator is defined,
 *   the function will return GSS_S_NO_CRED.
 * @context_handle: (gss_ctx_id_t, read/modify) Context handle for new
 *   context.  Supply GSS_C_NO_CONTEXT for first call; use value
 *   returned by first call in continuation calls.  Resources
 *   associated with this context-handle must be released by the
 *   application after use with a call to gss_delete_sec_context().
 * @target_name: (gss_name_t, read) Name of target.
 * @mech_type: (OID, read, optional) Object ID of desired
 *   mechanism. Supply GSS_C_NO_OID to obtain an implementation
 *   specific default.
 * @req_flags: (bit-mask, read) Contains various independent flags,
 *   each of which requests that the context support a specific
 *   service option.  Symbolic names are provided for each flag, and
 *   the symbolic names corresponding to the required flags should be
 *   logically-ORed together to form the bit-mask value.  See below
 *   for the flags.
 * @time_req: (Integer, read, optional) Desired number of seconds for
 *   which context should remain valid.  Supply 0 to request a default
 *   validity period.
 * @input_chan_bindings: (channel bindings, read, optional)
 *   Application-specified bindings.  Allows application to securely
 *   bind channel identification information to the security context.
 *   Specify GSS_C_NO_CHANNEL_BINDINGS if channel bindings are not
 *   used.
 * @input_token: (buffer, opaque, read, optional) Token received from
 *   peer application.  Supply GSS_C_NO_BUFFER, or a pointer to a
 *   buffer containing the value GSS_C_EMPTY_BUFFER on initial call.
 * @actual_mech_type: (OID, modify, optional) Actual mechanism used.
 *   The OID returned via this parameter will be a pointer to static
 *   storage that should be treated as read-only; In particular the
 *   application should not attempt to free it.  Specify NULL if not
 *   required.
 * @output_token: (buffer, opaque, modify) Token to be sent to peer
 *   application.  If the length field of the returned buffer is zero,
 *   no token need be sent to the peer application.  Storage
 *   associated with this buffer must be freed by the application
 *   after use with a call to gss_release_buffer().
 * @ret_flags: (bit-mask, modify, optional) Contains various
 *   independent flags, each of which indicates that the context
 *   supports a specific service option.  Specify NULL if not
 *   required.  Symbolic names are provided for each flag, and the
 *   symbolic names corresponding to the required flags should be
 *   logically-ANDed with the ret_flags value to test whether a given
 *   option is supported by the context.  See below for the flags.
 * @time_rec: (Integer, modify, optional) Number of seconds for which
 *   the context will remain valid. If the implementation does not
 *   support context expiration, the value GSS_C_INDEFINITE will be
 *   returned.  Specify NULL if not required.
 *
 * Initiates the establishment of a security context between the
 * application and a remote peer.  Initially, the input_token
 * parameter should be specified either as GSS_C_NO_BUFFER, or as a
 * pointer to a gss_buffer_desc object whose length field contains the
 * value zero.  The routine may return a output_token which should be
 * transferred to the peer application, where the peer application
 * will present it to gss_accept_sec_context.  If no token need be
 * sent, gss_init_sec_context will indicate this by setting the length
 * field of the output_token argument to zero. To complete the context
 * establishment, one or more reply tokens may be required from the
 * peer application; if so, gss_init_sec_context will return a status
 * containing the supplementary information bit GSS_S_CONTINUE_NEEDED.
 * In this case, gss_init_sec_context should be called again when the
 * reply token is received from the peer application, passing the
 * reply token to gss_init_sec_context via the input_token parameters.
 *
 * Portable applications should be constructed to use the token length
 * and return status to determine whether a token needs to be sent or
 * waited for.  Thus a typical portable caller should always invoke
 * gss_init_sec_context within a loop:
 *
 * ---------------------------------------------------
 * int context_established = 0;
 * gss_ctx_id_t context_hdl = GSS_C_NO_CONTEXT;
 *        ...
 * input_token->length = 0;
 *
 * while (!context_established) {
 *   maj_stat = gss_init_sec_context(&min_stat,
 *                                   cred_hdl,
 *                                   &context_hdl,
 *                                   target_name,
 *                                   desired_mech,
 *                                   desired_services,
 *                                   desired_time,
 *                                   input_bindings,
 *                                   input_token,
 *                                   &actual_mech,
 *                                   output_token,
 *                                   &actual_services,
 *                                   &actual_time);
 *   if (GSS_ERROR(maj_stat)) {
 *     report_error(maj_stat, min_stat);
 *   };
 *
 *   if (output_token->length != 0) {
 *     send_token_to_peer(output_token);
 *     gss_release_buffer(&min_stat, output_token)
 *   };
 *   if (GSS_ERROR(maj_stat)) {
 *
 *     if (context_hdl != GSS_C_NO_CONTEXT)
 *       gss_delete_sec_context(&min_stat,
 *                              &context_hdl,
 *                              GSS_C_NO_BUFFER);
 *     break;
 *   };
 *
 *   if (maj_stat & GSS_S_CONTINUE_NEEDED) {
 *     receive_token_from_peer(input_token);
 *   } else {
 *     context_established = 1;
 *   };
 * };
 * ---------------------------------------------------
 *
 * Whenever the routine returns a major status that includes the value
 * GSS_S_CONTINUE_NEEDED, the context is not fully established and the
 * following restrictions apply to the output parameters:
 *
 * - The value returned via the time_rec parameter is undefined unless
 * the accompanying ret_flags parameter contains the bit
 * GSS_C_PROT_READY_FLAG, indicating that per-message services may be
 * applied in advance of a successful completion status, the value
 * returned via the actual_mech_type parameter is undefined until the
 * routine returns a major status value of GSS_S_COMPLETE.
 *
 * - The values of the GSS_C_DELEG_FLAG, GSS_C_MUTUAL_FLAG,
 * GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG, GSS_C_CONF_FLAG,
 * GSS_C_INTEG_FLAG and GSS_C_ANON_FLAG bits returned via the
 * ret_flags parameter should contain the values that the
 * implementation expects would be valid if context establishment were
 * to succeed.  In particular, if the application has requested a
 * service such as delegation or anonymous authentication via the
 * req_flags argument, and such a service is unavailable from the
 * underlying mechanism, gss_init_sec_context should generate a token
 * that will not provide the service, and indicate via the ret_flags
 * argument that the service will not be supported.  The application
 * may choose to abort the context establishment by calling
 * gss_delete_sec_context (if it cannot continue in the absence of the
 * service), or it may choose to transmit the token and continue
 * context establishment (if the service was merely desired but not
 * mandatory).
 *
 * - The values of the GSS_C_PROT_READY_FLAG and GSS_C_TRANS_FLAG bits
 * within ret_flags should indicate the actual state at the time
 * gss_init_sec_context returns, whether or not the context is fully
 * established.
 *
 * - GSS-API implementations that support per-message protection are
 * encouraged to set the GSS_C_PROT_READY_FLAG in the final ret_flags
 * returned to a caller (i.e. when accompanied by a GSS_S_COMPLETE
 * status code).  However, applications should not rely on this
 * behavior as the flag was not defined in Version 1 of the GSS-API.
 * Instead, applications should determine what per-message services
 * are available after a successful context establishment according to
 * the GSS_C_INTEG_FLAG and GSS_C_CONF_FLAG values.
 *
 * - All other bits within the ret_flags argument should be set to
 * zero.
 *
 * If the initial call of gss_init_sec_context() fails, the
 * implementation should not create a context object, and should leave
 * the value of the context_handle parameter set to GSS_C_NO_CONTEXT
 * to indicate this.  In the event of a failure on a subsequent call,
 * the implementation is permitted to delete the "half-built" security
 * context (in which case it should set the context_handle parameter
 * to GSS_C_NO_CONTEXT), but the preferred behavior is to leave the
 * security context untouched for the application to delete (using
 * gss_delete_sec_context).
 *
 * During context establishment, the informational status bits
 * GSS_S_OLD_TOKEN and GSS_S_DUPLICATE_TOKEN indicate fatal errors,
 * and GSS-API mechanisms should always return them in association
 * with a routine error of GSS_S_FAILURE.  This requirement for
 * pairing did not exist in version 1 of the GSS-API specification, so
 * applications that wish to run over version 1 implementations must
 * special-case these codes.
 *
 * The `req_flags` values:
 *
 * `GSS_C_DELEG_FLAG`::
 * - True - Delegate credentials to remote peer.
 * - False - Don't delegate.
 *
 * `GSS_C_MUTUAL_FLAG`::
 * - True - Request that remote peer authenticate itself.
 * - False - Authenticate self to remote peer only.
 *
 * `GSS_C_REPLAY_FLAG`::
 * - True - Enable replay detection for messages protected with
 * gss_wrap or gss_get_mic.
 * - False - Don't attempt to detect replayed messages.
 *
 * `GSS_C_SEQUENCE_FLAG`::
 * - True - Enable detection of out-of-sequence protected messages.
 * - False - Don't attempt to detect out-of-sequence messages.
 *
 * `GSS_C_CONF_FLAG`::
 * - True - Request that confidentiality service be made available
 * (via gss_wrap).
 * - False - No per-message confidentiality service is required.
 *
 * `GSS_C_INTEG_FLAG`::
 * - True - Request that integrity service be made available (via
 * gss_wrap or gss_get_mic).
 * - False - No per-message integrity service is required.
 *
 * `GSS_C_ANON_FLAG`::
 * - True - Do not reveal the initiator's identity to the acceptor.
 * - False - Authenticate normally.
 *
 * The `ret_flags` values:
 *
 * `GSS_C_DELEG_FLAG`::
 * - True - Credentials were delegated to the remote peer.
 * - False - No credentials were delegated.
 *
 * `GSS_C_MUTUAL_FLAG`::
 * - True - The remote peer has authenticated itself.
 * - False - Remote peer has not authenticated itself.
 *
 * `GSS_C_REPLAY_FLAG`::
 * - True - replay of protected messages will be detected.
 * - False - replayed messages will not be detected.
 *
 * `GSS_C_SEQUENCE_FLAG`::
 * - True - out-of-sequence protected messages will be detected.
 * - False - out-of-sequence messages will not be detected.
 *
 * `GSS_C_CONF_FLAG`::
 * - True - Confidentiality service may be invoked by calling gss_wrap
 * routine.
 * - False - No confidentiality service (via gss_wrap)
 * available. gss_wrap will provide message encapsulation, data-origin
 * authentication and integrity services only.
 *
 * `GSS_C_INTEG_FLAG`::
 * - True - Integrity service may be invoked by calling either
 * gss_get_mic or gss_wrap routines.
 * - False - Per-message integrity service unavailable.
 *
 * `GSS_C_ANON_FLAG`::
 * - True - The initiator's identity has not been revealed, and will
 * not be revealed if any emitted token is passed to the acceptor.
 * - False - The initiator's identity has been or will be
 * authenticated normally.
 *
 * `GSS_C_PROT_READY_FLAG`::
 * - True - Protection services (as specified by the states of the
 * GSS_C_CONF_FLAG and GSS_C_INTEG_FLAG) are available for use if the
 * accompanying major status return value is either GSS_S_COMPLETE or
 * GSS_S_CONTINUE_NEEDED.
 * - False - Protection services (as specified by the states of the
 * GSS_C_CONF_FLAG and GSS_C_INTEG_FLAG) are available only if the
 * accompanying major status return value is GSS_S_COMPLETE.
 *
 * `GSS_C_TRANS_FLAG`::
 * - True - The resultant security context may be transferred to other
 * processes via a call to gss_export_sec_context().
 * - False - The security context is not transferable.
 *
 * All other bits should be set to zero.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_CONTINUE_NEEDED`: Indicates that a token from the peer
 * application is required to complete the context, and that
 * gss_init_sec_context must be called again with that token.
 *
 * `GSS_S_DEFECTIVE_TOKEN`: Indicates that consistency checks
 * performed on the input_token failed.
 *
 * `GSS_S_DEFECTIVE_CREDENTIAL`: Indicates that consistency checks
 * performed on the credential failed.
 *
 * `GSS_S_NO_CRED`: The supplied credentials were not valid for
 * context initiation, or the credential handle did not reference any
 * credentials.
 *
 * `GSS_S_CREDENTIALS_EXPIRED`: The referenced credentials have
 * expired.
 *
 * `GSS_S_BAD_BINDINGS`: The input_token contains different channel
 * bindings to those specified via the input_chan_bindings parameter.
 *
 * `GSS_S_BAD_SIG`: The input_token contains an invalid MIC, or a MIC
 * that could not be verified.
 *
 * `GSS_S_OLD_TOKEN`: The input_token was too old.  This is a fatal
 * error during context establishment.
 *
 * `GSS_S_DUPLICATE_TOKEN`: The input_token is valid, but is a
 * duplicate of a token already processed.  This is a fatal error
 * during context establishment.
 *
 * `GSS_S_NO_CONTEXT`: Indicates that the supplied context handle did
 * not refer to a valid context.
 *
 * `GSS_S_BAD_NAMETYPE`: The provided target_name parameter contained
 * an invalid or unsupported type of name.
 *
 * `GSS_S_BAD_NAME`: The provided target_name parameter was
 * ill-formed.
 *
 * `GSS_S_BAD_MECH`: The specified mechanism is not supported by the
 * provided credential, or is unrecognized by the implementation.
 **/
OM_uint32
gss_init_sec_context (OM_uint32 * minor_status,
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
		      OM_uint32 * ret_flags, OM_uint32 * time_rec)
{
  OM_uint32 maj_stat;
  _gss_mech_api_t mech;
  int freecontext = 0;

  if (!context_handle)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_NO_CONTEXT | GSS_S_CALL_INACCESSIBLE_READ;
    }

  if (output_token == GSS_C_NO_BUFFER)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_FAILURE | GSS_S_CALL_BAD_STRUCTURE;
    }

  if (*context_handle == GSS_C_NO_CONTEXT)
    mech = _gss_find_mech (mech_type);
  else
    mech = _gss_find_mech ((*context_handle)->mech);
  if (mech == NULL)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_MECH;
    }

  if (actual_mech_type)
    (*actual_mech_type) = mech->mech;

  if (*context_handle == GSS_C_NO_CONTEXT)
    {
      *context_handle = xcalloc (sizeof (**context_handle), 1);
      (*context_handle)->mech = mech->mech;
      freecontext = 1;
    }

  maj_stat = mech->init_sec_context (minor_status,
				     initiator_cred_handle,
				     context_handle,
				     target_name,
				     mech_type,
				     req_flags,
				     time_req,
				     input_chan_bindings,
				     input_token,
				     actual_mech_type,
				     output_token, ret_flags, time_rec);
  if (freecontext && GSS_ERROR (maj_stat))
    {
      free (*context_handle);
      *context_handle = GSS_C_NO_CONTEXT;
    }

  return maj_stat;
}

/**
 * gss_accept_sec_context:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @context_handle: (gss_ctx_id_t, read/modify) Context handle for new
 *   context.  Supply GSS_C_NO_CONTEXT for first call; use value
 *   returned in subsequent calls.  Once gss_accept_sec_context() has
 *   returned a value via this parameter, resources have been assigned
 *   to the corresponding context, and must be freed by the
 *   application after use with a call to gss_delete_sec_context().
 * @acceptor_cred_handle: (gss_cred_id_t, read) Credential handle
 *   claimed by context acceptor. Specify GSS_C_NO_CREDENTIAL to
 *   accept the context as a default principal.  If
 *   GSS_C_NO_CREDENTIAL is specified, but no default acceptor
 *   principal is defined, GSS_S_NO_CRED will be returned.
 * @input_token_buffer: (buffer, opaque, read) Token obtained from
 *   remote application.
 * @input_chan_bindings: (channel bindings, read, optional)
 *   Application- specified bindings.  Allows application to securely
 *   bind channel identification information to the security context.
 *   If channel bindings are not used, specify
 *   GSS_C_NO_CHANNEL_BINDINGS.
 * @src_name: (gss_name_t, modify, optional) Authenticated name of
 *   context initiator.  After use, this name should be deallocated by
 *   passing it to gss_release_name().  If not required, specify NULL.
 * @mech_type: (Object ID, modify, optional) Security mechanism used.
 *   The returned OID value will be a pointer into static storage, and
 *   should be treated as read-only by the caller (in particular, it
 *   does not need to be freed).  If not required, specify NULL.
 * @output_token: (buffer, opaque, modify) Token to be passed to peer
 *   application.  If the length field of the returned token buffer is
 *   0, then no token need be passed to the peer application.  If a
 *   non- zero length field is returned, the associated storage must
 *   be freed after use by the application with a call to
 *   gss_release_buffer().
 * @ret_flags: (bit-mask, modify, optional) Contains various
 *   independent flags, each of which indicates that the context
 *   supports a specific service option.  If not needed, specify NULL.
 *   Symbolic names are provided for each flag, and the symbolic names
 *   corresponding to the required flags should be logically-ANDed
 *   with the ret_flags value to test whether a given option is
 *   supported by the context.  See below for the flags.
 * @time_rec: (Integer, modify, optional) Number of seconds for which
 *   the context will remain valid. Specify NULL if not required.
 * @delegated_cred_handle: (gss_cred_id_t, modify, optional
 *   credential) Handle for credentials received from context
 *   initiator.  Only valid if deleg_flag in ret_flags is true, in
 *   which case an explicit credential handle (i.e. not
 *   GSS_C_NO_CREDENTIAL) will be returned; if deleg_flag is false,
 *   gss_accept_context() will set this parameter to
 *   GSS_C_NO_CREDENTIAL.  If a credential handle is returned, the
 *   associated resources must be released by the application after
 *   use with a call to gss_release_cred().  Specify NULL if not
 *   required.
 *
 * Allows a remotely initiated security context between the
 * application and a remote peer to be established.  The routine may
 * return a output_token which should be transferred to the peer
 * application, where the peer application will present it to
 * gss_init_sec_context.  If no token need be sent,
 * gss_accept_sec_context will indicate this by setting the length
 * field of the output_token argument to zero.  To complete the
 * context establishment, one or more reply tokens may be required
 * from the peer application; if so, gss_accept_sec_context will
 * return a status flag of GSS_S_CONTINUE_NEEDED, in which case it
 * should be called again when the reply token is received from the
 * peer application, passing the token to gss_accept_sec_context via
 * the input_token parameters.
 *
 * Portable applications should be constructed to use the token length
 * and return status to determine whether a token needs to be sent or
 * waited for.  Thus a typical portable caller should always invoke
 * gss_accept_sec_context within a loop:
 *
 * ---------------------------------------------------
 * gss_ctx_id_t context_hdl = GSS_C_NO_CONTEXT;
 *
 * do {
 *   receive_token_from_peer(input_token);
 *   maj_stat = gss_accept_sec_context(&min_stat,
 *                                     &context_hdl,
 *                                     cred_hdl,
 *                                     input_token,
 *                                     input_bindings,
 *                                     &client_name,
 *                                     &mech_type,
 *                                     output_token,
 *                                     &ret_flags,
 *                                     &time_rec,
 *                                     &deleg_cred);
 *   if (GSS_ERROR(maj_stat)) {
 *     report_error(maj_stat, min_stat);
 *   };
 *   if (output_token->length != 0) {
 *     send_token_to_peer(output_token);
 *
 *     gss_release_buffer(&min_stat, output_token);
 *   };
 *   if (GSS_ERROR(maj_stat)) {
 *     if (context_hdl != GSS_C_NO_CONTEXT)
 *       gss_delete_sec_context(&min_stat,
 *                              &context_hdl,
 *                              GSS_C_NO_BUFFER);
 *     break;
 *   };
 * } while (maj_stat & GSS_S_CONTINUE_NEEDED);
 * ---------------------------------------------------
 *
 *
 * Whenever the routine returns a major status that includes the value
 * GSS_S_CONTINUE_NEEDED, the context is not fully established and the
 * following restrictions apply to the output parameters:
 *
 * The value returned via the time_rec parameter is undefined Unless the
 * accompanying ret_flags parameter contains the bit
 * GSS_C_PROT_READY_FLAG, indicating that per-message services may be
 * applied in advance of a successful completion status, the value
 * returned via the mech_type parameter may be undefined until the
 * routine returns a major status value of GSS_S_COMPLETE.
 *
 * The values of the GSS_C_DELEG_FLAG,
 * GSS_C_MUTUAL_FLAG,GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG,
 * GSS_C_CONF_FLAG,GSS_C_INTEG_FLAG and GSS_C_ANON_FLAG bits returned
 * via the ret_flags parameter should contain the values that the
 * implementation expects would be valid if context establishment were
 * to succeed.
 *
 * The values of the GSS_C_PROT_READY_FLAG and GSS_C_TRANS_FLAG bits
 * within ret_flags should indicate the actual state at the time
 * gss_accept_sec_context returns, whether or not the context is fully
 * established.
 *
 * Although this requires that GSS-API implementations set the
 * GSS_C_PROT_READY_FLAG in the final ret_flags returned to a caller
 * (i.e. when accompanied by a GSS_S_COMPLETE status code), applications
 * should not rely on this behavior as the flag was not defined in
 * Version 1 of the GSS-API. Instead, applications should be prepared to
 * use per-message services after a successful context establishment,
 * according to the GSS_C_INTEG_FLAG and GSS_C_CONF_FLAG values.
 *
 * All other bits within the ret_flags argument should be set to zero.
 * While the routine returns GSS_S_CONTINUE_NEEDED, the values returned
 * via the ret_flags argument indicate the services that the
 * implementation expects to be available from the established context.
 *
 * If the initial call of gss_accept_sec_context() fails, the
 * implementation should not create a context object, and should leave
 * the value of the context_handle parameter set to GSS_C_NO_CONTEXT to
 * indicate this.  In the event of a failure on a subsequent call, the
 * implementation is permitted to delete the "half-built" security
 * context (in which case it should set the context_handle parameter to
 * GSS_C_NO_CONTEXT), but the preferred behavior is to leave the
 * security context (and the context_handle parameter) untouched for the
 * application to delete (using gss_delete_sec_context).
 *
 * During context establishment, the informational status bits
 * GSS_S_OLD_TOKEN and GSS_S_DUPLICATE_TOKEN indicate fatal errors, and
 * GSS-API mechanisms should always return them in association with a
 * routine error of GSS_S_FAILURE.  This requirement for pairing did not
 * exist in version 1 of the GSS-API specification, so applications that
 * wish to run over version 1 implementations must special-case these
 * codes.
 *
 * The `ret_flags` values:
 *
 * `GSS_C_DELEG_FLAG`::
 * - True - Delegated credentials are available via the
 * delegated_cred_handle parameter.
 * - False - No credentials were delegated.
 *
 * `GSS_C_MUTUAL_FLAG`::
 * - True - Remote peer asked for mutual authentication.
 * - False - Remote peer did not ask for mutual authentication.
 *
 * `GSS_C_REPLAY_FLAG`::
 * - True - replay of protected messages will be detected.
 * - False - replayed messages will not be detected.
 *
 * `GSS_C_SEQUENCE_FLAG`::
 * - True - out-of-sequence protected messages will be detected.
 * - False - out-of-sequence messages will not be detected.
 *
 * `GSS_C_CONF_FLAG`::
 * - True - Confidentiality service may be invoked by calling the
 * gss_wrap routine.
 * - False - No confidentiality service (via gss_wrap)
 * available. gss_wrap will provide message encapsulation, data-origin
 * authentication and integrity services only.
 *
 * `GSS_C_INTEG_FLAG`::
 * - True - Integrity service may be invoked by calling either
 * gss_get_mic or gss_wrap routines.
 * - False - Per-message integrity service unavailable.
 *
 * `GSS_C_ANON_FLAG`::
 * - True - The initiator does not wish to be authenticated; the
 * src_name parameter (if requested) contains an anonymous internal
 * name.
 * - False - The initiator has been authenticated normally.
 *
 * `GSS_C_PROT_READY_FLAG`::
 * - True - Protection services (as specified by the states of the
 * GSS_C_CONF_FLAG and GSS_C_INTEG_FLAG) are available if the
 * accompanying major status return value is either GSS_S_COMPLETE or
 * GSS_S_CONTINUE_NEEDED.
 * - False - Protection services (as specified by the states of the
 * GSS_C_CONF_FLAG and GSS_C_INTEG_FLAG) are available only if the
 * accompanying major status return value is GSS_S_COMPLETE.
 *
 * `GSS_C_TRANS_FLAG`::
 * - True - The resultant security context may be transferred to other
 * processes via a call to gss_export_sec_context().
 * - False - The security context is not transferable.
 *
 * All other bits should be set to zero.
 *
 * Return value:
 *
 * `GSS_S_CONTINUE_NEEDED`: Indicates that a token from the peer
 * application is required to complete the context, and that
 * gss_accept_sec_context must be called again with that token.
 *
 * `GSS_S_DEFECTIVE_TOKEN`: Indicates that consistency checks
 * performed on the input_token failed.
 *
 * `GSS_S_DEFECTIVE_CREDENTIAL`: Indicates that consistency checks
 * performed on the credential failed.
 *
 * `GSS_S_NO_CRED`: The supplied credentials were not valid for
 * context acceptance, or the credential handle did not reference any
 * credentials.
 *
 * `GSS_S_CREDENTIALS_EXPIRED`: The referenced credentials have
 * expired.
 *
 * `GSS_S_BAD_BINDINGS`: The input_token contains different channel
 * bindings to those specified via the input_chan_bindings parameter.
 *
 * `GSS_S_NO_CONTEXT`: Indicates that the supplied context handle did
 * not refer to a valid context.
 *
 * `GSS_S_BAD_SIG`: The input_token contains an invalid MIC.
 *
 * `GSS_S_OLD_TOKEN`: The input_token was too old.  This is a fatal
 * error during context establishment.
 *
 * `GSS_S_DUPLICATE_TOKEN`: The input_token is valid, but is a
 * duplicate of a token already processed.  This is a fatal error
 * during context establishment.
 *
 * `GSS_S_BAD_MECH`: The received token specified a mechanism that is
 * not supported by the implementation or the provided credential.
 **/
OM_uint32
gss_accept_sec_context (OM_uint32 * minor_status,
			gss_ctx_id_t * context_handle,
			const gss_cred_id_t acceptor_cred_handle,
			const gss_buffer_t input_token_buffer,
			const gss_channel_bindings_t input_chan_bindings,
			gss_name_t * src_name,
			gss_OID * mech_type,
			gss_buffer_t output_token,
			OM_uint32 * ret_flags,
			OM_uint32 * time_rec,
			gss_cred_id_t * delegated_cred_handle)
{
  _gss_mech_api_t mech;

  if (!context_handle)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_NO_CONTEXT | GSS_S_CALL_INACCESSIBLE_READ;
    }

  mech = (*context_handle == GSS_C_NO_CONTEXT) ?
    _gss_find_mech (mech_type ? *mech_type : GSS_C_NO_OID) :
    _gss_find_mech ((*context_handle)->mech);

  return mech->accept_sec_context (minor_status,
				   context_handle,
				   acceptor_cred_handle,
				   input_token_buffer,
				   input_chan_bindings,
				   src_name,
				   mech_type,
				   output_token,
				   ret_flags,
				   time_rec, delegated_cred_handle);
}

/**
 * gss_delete_sec_context:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @context_handle: (gss_ctx_id_t, modify) Context handle identifying
 *   context to delete.  After deleting the context, the GSS-API will
 *   set this context handle to GSS_C_NO_CONTEXT.
 * @output_token: (buffer, opaque, modify, optional) Token to be sent
 *   to remote application to instruct it to also delete the context.
 *   It is recommended that applications specify GSS_C_NO_BUFFER for
 *   this parameter, requesting local deletion only.  If a buffer
 *   parameter is provided by the application, the mechanism may
 *   return a token in it; mechanisms that implement only local
 *   deletion should set the length field of this token to zero to
 *   indicate to the application that no token is to be sent to the
 *   peer.
 *
 * Delete a security context.  gss_delete_sec_context will delete the
 * local data structures associated with the specified security
 * context, and may generate an output_token, which when passed to the
 * peer gss_process_context_token will instruct it to do likewise.  If
 * no token is required by the mechanism, the GSS-API should set the
 * length field of the output_token (if provided) to zero.  No further
 * security services may be obtained using the context specified by
 * context_handle.
 *
 * In addition to deleting established security contexts,
 * gss_delete_sec_context must also be able to delete "half-built"
 * security contexts resulting from an incomplete sequence of
 * gss_init_sec_context()/gss_accept_sec_context() calls.
 *
 * The output_token parameter is retained for compatibility with
 * version 1 of the GSS-API.  It is recommended that both peer
 * applications invoke gss_delete_sec_context passing the value
 * GSS_C_NO_BUFFER for the output_token parameter, indicating that no
 * token is required, and that gss_delete_sec_context should simply
 * delete local context data structures.  If the application does pass
 * a valid buffer to gss_delete_sec_context, mechanisms are encouraged
 * to return a zero-length token, indicating that no peer action is
 * necessary, and that no token should be transferred by the
 * application.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_NO_CONTEXT`: No valid context was supplied.
 **/
OM_uint32
gss_delete_sec_context (OM_uint32 * minor_status,
			gss_ctx_id_t * context_handle,
			gss_buffer_t output_token)
{
  _gss_mech_api_t mech;
  OM_uint32 ret;

  if (!context_handle)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_NO_CONTEXT | GSS_S_CALL_INACCESSIBLE_READ;
    }

  if (*context_handle == GSS_C_NO_CONTEXT)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_NO_CONTEXT | GSS_S_CALL_BAD_STRUCTURE;
    }

  if (output_token != GSS_C_NO_BUFFER)
    {
      output_token->length = 0;
      output_token->value = NULL;
    }

  mech = _gss_find_mech ((*context_handle)->mech);

  ret = mech->delete_sec_context (NULL, context_handle, output_token);
  if (GSS_ERROR (ret))
    /* XXX? Ignore error. */ ;

  (*context_handle)->peerptr = &(*context_handle)->peer;
  ret = gss_release_name (NULL, &(*context_handle)->peerptr);
  if (GSS_ERROR (ret))
    /* XXX? Ignore error. */ ;

  free (*context_handle);
  *context_handle = GSS_C_NO_CONTEXT;

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/**
 * gss_process_context_token:
 * @minor_status: (Integer, modify) Implementation specific status code.
 * @context_handle: (gss_ctx_id_t, read) Context handle of context on
 *   which token is to be processed
 * @token_buffer: (buffer, opaque, read) Token to process.
 *
 * Provides a way to pass an asynchronous token to the security
 * service.  Most context-level tokens are emitted and processed
 * synchronously by gss_init_sec_context and gss_accept_sec_context,
 * and the application is informed as to whether further tokens are
 * expected by the GSS_C_CONTINUE_NEEDED major status bit.
 * Occasionally, a mechanism may need to emit a context-level token at
 * a point when the peer entity is not expecting a token.  For
 * example, the initiator's final call to gss_init_sec_context may
 * emit a token and return a status of GSS_S_COMPLETE, but the
 * acceptor's call to gss_accept_sec_context may fail.  The acceptor's
 * mechanism may wish to send a token containing an error indication
 * to the initiator, but the initiator is not expecting a token at
 * this point, believing that the context is fully established.
 * Gss_process_context_token provides a way to pass such a token to
 * the mechanism at any time.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_DEFECTIVE_TOKEN`: Indicates that consistency checks
 * performed on the token failed.
 *
 * `GSS_S_NO_CONTEXT`: The context_handle did not refer to a valid
 * context.
 **/
OM_uint32
gss_process_context_token (OM_uint32 * minor_status,
			   const gss_ctx_id_t context_handle,
			   const gss_buffer_t token_buffer)
{
  return GSS_S_FAILURE;
}

/**
 * gss_context_time:
 * @minor_status: (Integer, modify) Implementation specific status
 *   code.
 * @context_handle: (gss_ctx_id_t, read) Identifies the context to be
 *   interrogated.
 * @time_rec: (Integer, modify) Number of seconds that the context
 *   will remain valid.  If the context has already expired, zero will
 *   be returned.
 *
 * Determines the number of seconds for which the specified context
 * will remain valid.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_CONTEXT_EXPIRED`: The context has already expired.
 *
 * `GSS_S_NO_CONTEXT`: The context_handle parameter did not identify a
 * valid context
 **/
OM_uint32
gss_context_time (OM_uint32 * minor_status,
		  const gss_ctx_id_t context_handle, OM_uint32 * time_rec)
{
  _gss_mech_api_t mech;

  if (context_handle == GSS_C_NO_CONTEXT)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_NO_CONTEXT | GSS_S_CALL_BAD_STRUCTURE;
    }

  mech = _gss_find_mech (context_handle->mech);

  return mech->context_time (minor_status, context_handle, time_rec);
}

/**
 * gss_inquire_context:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @context_handle: (gss_ctx_id_t, read) A handle that refers to the
 *   security context.
 * @src_name: (gss_name_t, modify, optional) The name of the context
 *   initiator.  If the context was established using anonymous
 *   authentication, and if the application invoking
 *   gss_inquire_context is the context acceptor, an anonymous name
 *   will be returned.  Storage associated with this name must be
 *   freed by the application after use with a call to
 *   gss_release_name().  Specify NULL if not required.
 * @targ_name: (gss_name_t, modify, optional) The name of the context
 *   acceptor.  Storage associated with this name must be freed by the
 *   application after use with a call to gss_release_name().  If the
 *   context acceptor did not authenticate itself, and if the
 *   initiator did not specify a target name in its call to
 *   gss_init_sec_context(), the value GSS_C_NO_NAME will be returned.
 *   Specify NULL if not required.
 * @lifetime_rec: (Integer, modify, optional) The number of seconds
 *   for which the context will remain valid.  If the context has
 *   expired, this parameter will be set to zero.  If the
 *   implementation does not support context expiration, the value
 *   GSS_C_INDEFINITE will be returned.  Specify NULL if not required.
 * @mech_type: (gss_OID, modify, optional) The security mechanism
 *   providing the context.  The returned OID will be a pointer to
 *   static storage that should be treated as read-only by the
 *   application; in particular the application should not attempt to
 *   free it.  Specify NULL if not required.
 * @ctx_flags: (bit-mask, modify, optional) Contains various
 *   independent flags, each of which indicates that the context
 *   supports (or is expected to support, if ctx_open is false) a
 *   specific service option.  If not needed, specify NULL.  Symbolic
 *   names are provided for each flag, and the symbolic names
 *   corresponding to the required flags should be logically-ANDed
 *   with the ret_flags value to test whether a given option is
 *   supported by the context.  See below for the flags.
 * @locally_initiated: (Boolean, modify) Non-zero if the invoking
 *   application is the context initiator.  Specify NULL if not
 *   required.
 * @open: (Boolean, modify) Non-zero if the context is fully
 *   established; Zero if a context-establishment token is expected
 *   from the peer application.  Specify NULL if not required.
 *
 * Obtains information about a security context.  The caller must
 * already have obtained a handle that refers to the context, although
 * the context need not be fully established.
 *
 * The `ctx_flags` values:
 *
 * `GSS_C_DELEG_FLAG`::
 * - True - Credentials were delegated from the initiator to the
 * acceptor.
 * - False - No credentials were delegated.
 *
 * `GSS_C_MUTUAL_FLAG`::
 * - True - The acceptor was authenticated to the initiator.
 * - False - The acceptor did not authenticate itself.
 *
 * `GSS_C_REPLAY_FLAG`::
 * - True - replay of protected messages will be detected.
 * - False - replayed messages will not be detected.
 *
 * `GSS_C_SEQUENCE_FLAG`::
 * - True - out-of-sequence protected messages will be detected.
 * - False - out-of-sequence messages will not be detected.
 *
 * `GSS_C_CONF_FLAG`::
 * - True - Confidentiality service may be invoked by calling gss_wrap
 * routine.
 * - False - No confidentiality service (via gss_wrap)
 * available. gss_wrap will provide message encapsulation, data-origin
 * authentication and integrity services only.
 *
 * `GSS_C_INTEG_FLAG`::
 * - True - Integrity service may be invoked by calling either
 * gss_get_mic or gss_wrap routines.
 * - False - Per-message integrity service unavailable.
 *
 * `GSS_C_ANON_FLAG`::
 * - True - The initiator's identity will not be revealed to the
 * acceptor.  The src_name parameter (if requested) contains an
 * anonymous internal name.
 * - False - The initiator has been authenticated normally.
 *
 * `GSS_C_PROT_READY_FLAG`::
 * - True - Protection services (as specified by the states of the
 * GSS_C_CONF_FLAG and GSS_C_INTEG_FLAG) are available for use.
 * - False - Protection services (as specified by the states of the
 * GSS_C_CONF_FLAG and GSS_C_INTEG_FLAG) are available only if the
 * context is fully established (i.e. if the open parameter is
 * non-zero).
 *
 * `GSS_C_TRANS_FLAG`::
 * - True - The resultant security context may be transferred to other
 * processes via a call to gss_export_sec_context().
 * - False - The security context is not transferable.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_NO_CONTEXT`: The referenced context could not be accessed.
 **/
OM_uint32
gss_inquire_context (OM_uint32 * minor_status,
		     const gss_ctx_id_t context_handle,
		     gss_name_t * src_name,
		     gss_name_t * targ_name,
		     OM_uint32 * lifetime_rec,
		     gss_OID * mech_type,
		     OM_uint32 * ctx_flags, int *locally_initiated, int *open)
{
  return GSS_S_FAILURE;
}

/**
 * gss_wrap_size_limit:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @context_handle: (gss_ctx_id_t, read) A handle that refers to the
 *   security over which the messages will be sent.
 * @conf_req_flag: (Boolean, read) Indicates whether gss_wrap will be
 *   asked to apply confidentiality protection in addition to
 *   integrity protection.  See the routine description for gss_wrap
 *   for more details.
 * @qop_req: (gss_qop_t, read) Indicates the level of protection that
 *   gss_wrap will be asked to provide.  See the routine description
 *   for gss_wrap for more details.
 * @req_output_size: (Integer, read) The desired maximum size for
 *   tokens emitted by gss_wrap.
 * @max_input_size: (Integer, modify) The maximum input message size
 *   that may be presented to gss_wrap in order to guarantee that the
 *   emitted token shall be no larger than req_output_size bytes.
 *
 * Allows an application to determine the maximum message size that,
 * if presented to gss_wrap with the same conf_req_flag and qop_req
 * parameters, will result in an output token containing no more than
 * req_output_size bytes.
 *
 * This call is intended for use by applications that communicate over
 * protocols that impose a maximum message size.  It enables the
 * application to fragment messages prior to applying protection.
 *
 * GSS-API implementations are recommended but not required to detect
 * invalid QOP values when gss_wrap_size_limit() is called. This
 * routine guarantees only a maximum message size, not the
 * availability of specific QOP values for message protection.
 *
 * Successful completion of this call does not guarantee that gss_wrap
 * will be able to protect a message of length max_input_size bytes,
 * since this ability may depend on the availability of system
 * resources at the time that gss_wrap is called.  However, if the
 * implementation itself imposes an upper limit on the length of
 * messages that may be processed by gss_wrap, the implementation
 * should not return a value via max_input_bytes that is greater than
 * this length.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_NO_CONTEXT`: The referenced context could not be accessed.
 *
 * `GSS_S_CONTEXT_EXPIRED`: The context has expired.
 *
 * `GSS_S_BAD_QOP`: The specified QOP is not supported by the
 * mechanism.
 **/
OM_uint32
gss_wrap_size_limit (OM_uint32 * minor_status,
		     const gss_ctx_id_t context_handle,
		     int conf_req_flag,
		     gss_qop_t qop_req,
		     OM_uint32 req_output_size, OM_uint32 * max_input_size)
{
  return GSS_S_FAILURE;
}

/**
 * gss_export_sec_context:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @context_handle: (gss_ctx_id_t, modify) Context handle identifying
 *   the context to transfer.
 * @interprocess_token: (buffer, opaque, modify) Token to be
 *   transferred to target process.  Storage associated with this
 *   token must be freed by the application after use with a call to
 *   gss_release_buffer().
 *
 * Provided to support the sharing of work between multiple processes.
 * This routine will typically be used by the context-acceptor, in an
 * application where a single process receives incoming connection
 * requests and accepts security contexts over them, then passes the
 * established context to one or more other processes for message
 * exchange. gss_export_sec_context() deactivates the security context
 * for the calling process and creates an interprocess token which,
 * when passed to gss_import_sec_context in another process, will
 * re-activate the context in the second process. Only a single
 * instantiation of a given context may be active at any one time; a
 * subsequent attempt by a context exporter to access the exported
 * security context will fail.
 *
 * The implementation may constrain the set of processes by which the
 * interprocess token may be imported, either as a function of local
 * security policy, or as a result of implementation decisions.  For
 * example, some implementations may constrain contexts to be passed
 * only between processes that run under the same account, or which
 * are part of the same process group.
 *
 * The interprocess token may contain security-sensitive information
 * (for example cryptographic keys).  While mechanisms are encouraged
 * to either avoid placing such sensitive information within
 * interprocess tokens, or to encrypt the token before returning it to
 * the application, in a typical object-library GSS-API implementation
 * this may not be possible. Thus the application must take care to
 * protect the interprocess token, and ensure that any process to
 * which the token is transferred is trustworthy.
 *
 * If creation of the interprocess token is successful, the
 * implementation shall deallocate all process-wide resources
 * associated with the security context, and set the context_handle to
 * GSS_C_NO_CONTEXT.  In the event of an error that makes it
 * impossible to complete the export of the security context, the
 * implementation must not return an interprocess token, and should
 * strive to leave the security context referenced by the
 * context_handle parameter untouched.  If this is impossible, it is
 * permissible for the implementation to delete the security context,
 * providing it also sets the context_handle parameter to
 * GSS_C_NO_CONTEXT.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_CONTEXT_EXPIRED`: The context has expired.
 *
 * `GSS_S_NO_CONTEXT`: The context was invalid.
 *
 * `GSS_S_UNAVAILABLE`: The operation is not supported.
 **/
OM_uint32
gss_export_sec_context (OM_uint32 * minor_status,
			gss_ctx_id_t * context_handle,
			gss_buffer_t interprocess_token)
{
  return GSS_S_UNAVAILABLE;
}

/**
 * gss_import_sec_context:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @interprocess_token: (buffer, opaque, modify) Token received from
 *   exporting process
 * @context_handle: (gss_ctx_id_t, modify) Context handle of newly
 *   reactivated context.  Resources associated with this context
 *   handle must be released by the application after use with a call
 *   to gss_delete_sec_context().
 *
 * Allows a process to import a security context established by
 * another process.  A given interprocess token may be imported only
 * once.  See gss_export_sec_context.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_NO_CONTEXT`: The token did not contain a valid context
 * reference.
 *
 * `GSS_S_DEFECTIVE_TOKEN`: The token was invalid.
 *
 * `GSS_S_UNAVAILABLE`: The operation is unavailable.
 *
 * `GSS_S_UNAUTHORIZED`: Local policy prevents the import of this
 *  context by the current process.
 **/
OM_uint32
gss_import_sec_context (OM_uint32 * minor_status,
			const gss_buffer_t interprocess_token,
			gss_ctx_id_t * context_handle)
{
  return GSS_S_UNAVAILABLE;
}
