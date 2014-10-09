/* cred.c --- Implementation of GSS-API Credential Management functions.
 * Copyright (C) 2003-2014 Simon Josefsson
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

#include "internal.h"

/* _gss_find_mech */
#include "meta.h"

/**
 * gss_acquire_cred:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @desired_name: (gss_name_t, read) Name of principal whose
 *   credential should be acquired.
 * @time_req: (Integer, read, optional) Number of seconds that
 *   credentials should remain valid. Specify GSS_C_INDEFINITE to
 *   request that the credentials have the maximum permitted lifetime.
 * @desired_mechs: (Set of Object IDs, read, optional) Set of
 *   underlying security mechanisms that may be used.
 *   GSS_C_NO_OID_SET may be used to obtain an implementation-specific
 *   default.
 * @cred_usage: (gss_cred_usage_t, read) GSS_C_BOTH - Credentials may
 *   be used either to initiate or accept security contexts.
 *   GSS_C_INITIATE - Credentials will only be used to initiate
 *   security contexts.  GSS_C_ACCEPT - Credentials will only be used
 *   to accept security contexts.
 * @output_cred_handle: (gss_cred_id_t, modify) The returned
 *   credential handle.  Resources associated with this credential
 *   handle must be released by the application after use with a call
 *   to gss_release_cred().
 * @actual_mechs: (Set of Object IDs, modify, optional) The set of
 *   mechanisms for which the credential is valid.  Storage associated
 *   with the returned OID-set must be released by the application
 *   after use with a call to gss_release_oid_set().  Specify NULL if
 *   not required.
 * @time_rec: (Integer, modify, optional) Actual number of seconds for
 *   which the returned credentials will remain valid.  If the
 *   implementation does not support expiration of credentials, the
 *   value GSS_C_INDEFINITE will be returned. Specify NULL if not
 *   required.
 *
 * Allows an application to acquire a handle for a pre-existing
 * credential by name.  GSS-API implementations must impose a local
 * access-control policy on callers of this routine to prevent
 * unauthorized callers from acquiring credentials to which they are
 * not entitled.  This routine is not intended to provide a "login to
 * the network" function, as such a function would involve the
 * creation of new credentials rather than merely acquiring a handle
 * to existing credentials.  Such functions, if required, should be
 * defined in implementation-specific extensions to the API.
 *
 * If desired_name is GSS_C_NO_NAME, the call is interpreted as a
 * request for a credential handle that will invoke default behavior
 * when passed to gss_init_sec_context() (if cred_usage is
 * GSS_C_INITIATE or GSS_C_BOTH) or gss_accept_sec_context() (if
 * cred_usage is GSS_C_ACCEPT or GSS_C_BOTH).
 *
 * Mechanisms should honor the desired_mechs parameter, and return a
 * credential that is suitable to use only with the requested
 * mechanisms.  An exception to this is the case where one underlying
 * credential element can be shared by multiple mechanisms; in this
 * case it is permissible for an implementation to indicate all
 * mechanisms with which the credential element may be used.  If
 * desired_mechs is an empty set, behavior is undefined.
 *
 * This routine is expected to be used primarily by context acceptors,
 * since implementations are likely to provide mechanism-specific ways
 * of obtaining GSS-API initiator credentials from the system login
 * process.  Some implementations may therefore not support the
 * acquisition of GSS_C_INITIATE or GSS_C_BOTH credentials via
 * gss_acquire_cred for any name other than GSS_C_NO_NAME, or a name
 * produced by applying either gss_inquire_cred to a valid credential,
 * or gss_inquire_context to an active context.
 *
 * If credential acquisition is time-consuming for a mechanism, the
 * mechanism may choose to delay the actual acquisition until the
 * credential is required (e.g. by gss_init_sec_context or
 * gss_accept_sec_context).  Such mechanism-specific implementation
 * decisions should be invisible to the calling application; thus a
 * call of gss_inquire_cred immediately following the call of
 * gss_acquire_cred must return valid credential data, and may
 * therefore incur the overhead of a deferred credential acquisition.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_BAD_MECH`: Unavailable mechanism requested.
 *
 * `GSS_S_BAD_NAMETYPE`: Type contained within desired_name parameter
 * is not supported.
 *
 * `GSS_S_BAD_NAME`: Value supplied for desired_name parameter is ill
 * formed.
 *
 * `GSS_S_CREDENTIALS_EXPIRED`: The credentials could not be acquired
 * Because they have expired.
 *
 * `GSS_S_NO_CRED`: No credentials were found for the specified name.
 **/
OM_uint32
gss_acquire_cred (OM_uint32 * minor_status,
		  const gss_name_t desired_name,
		  OM_uint32 time_req,
		  const gss_OID_set desired_mechs,
		  gss_cred_usage_t cred_usage,
		  gss_cred_id_t * output_cred_handle,
		  gss_OID_set * actual_mechs, OM_uint32 * time_rec)
{
  _gss_mech_api_t mech = NULL;
  OM_uint32 maj_stat;

  if (!output_cred_handle)
    return GSS_S_NO_CRED | GSS_S_CALL_INACCESSIBLE_WRITE;

  if (desired_mechs != GSS_C_NO_OID_SET)
    {
      size_t i;

      /* Is the desired_mechs an "OR" or "AND" list?  I.e., if the OID
         set contain several OIDs, MUST the credential work with all
         of them?  Or just any of them?  The specification isn't
         entirely clear on this, to me.  This implement an OR list,
         chosing the first mechanism in the OID set we support.  We
         need more information in meta.c to implement AND lists. */

      for (i = 0; mech == NULL && i < desired_mechs->count; i++)
	mech = _gss_find_mech ((&desired_mechs->elements)[i]);
    }
  else
    mech = _gss_find_mech (GSS_C_NO_OID);

  if (mech == NULL)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_MECH;
    }

  *output_cred_handle = calloc (sizeof (**output_cred_handle), 1);
  if (!*output_cred_handle)
    {
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }
  (*output_cred_handle)->mech = mech->mech;

  maj_stat = mech->acquire_cred (minor_status,
				 desired_name,
				 time_req,
				 desired_mechs,
				 cred_usage,
				 output_cred_handle, actual_mechs, time_rec);
  if (GSS_ERROR (maj_stat))
    {
      free (*output_cred_handle);
      *output_cred_handle = GSS_C_NO_CREDENTIAL;
      return maj_stat;
    }

  return GSS_S_COMPLETE;
}

/**
 * gss_add_cred:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @input_cred_handle: (gss_cred_id_t, read, optional) The credential
 *   to which a credential-element will be added.  If
 *   GSS_C_NO_CREDENTIAL is specified, the routine will compose the
 *   new credential based on default behavior (see text).
 *   Note that, while the credential-handle is not modified by
 *   gss_add_cred(), the underlying credential will be modified if
 *   output_credential_handle is NULL.
 * @desired_name: (gss_name_t, read.)  Name of principal whose
 *   credential should be acquired.
 * @desired_mech: (Object ID, read) Underlying security mechanism with
 *   which the credential may be used.
 * @cred_usage: (gss_cred_usage_t, read) GSS_C_BOTH - Credential may
 *   be used either to initiate or accept security contexts.
 *   GSS_C_INITIATE - Credential will only be used to initiate
 *   security contexts.  GSS_C_ACCEPT - Credential will only be used
 *   to accept security contexts.
 * @initiator_time_req: (Integer, read, optional) number of seconds
 *   that the credential should remain valid for initiating security
 *   contexts.  This argument is ignored if the composed credentials
 *   are of type GSS_C_ACCEPT.  Specify GSS_C_INDEFINITE to request
 *   that the credentials have the maximum permitted initiator
 *   lifetime.
 * @acceptor_time_req: (Integer, read, optional) number of seconds
 *   that the credential should remain valid for accepting security
 *   contexts.  This argument is ignored if the composed credentials
 *   are of type GSS_C_INITIATE.  Specify GSS_C_INDEFINITE to request
 *   that the credentials have the maximum permitted initiator
 *   lifetime.
 * @output_cred_handle: (gss_cred_id_t, modify, optional) The returned
 *   credential handle, containing the new credential-element and all
 *   the credential-elements from input_cred_handle.  If a valid
 *   pointer to a gss_cred_id_t is supplied for this parameter,
 *   gss_add_cred creates a new credential handle containing all
 *   credential-elements from the input_cred_handle and the newly
 *   acquired credential-element; if NULL is specified for this
 *   parameter, the newly acquired credential-element will be added to
 *   the credential identified by input_cred_handle.  The resources
 *   associated with any credential handle returned via this parameter
 *   must be released by the application after use with a call to
 *   gss_release_cred().
 * @actual_mechs: (Set of Object IDs, modify, optional) The complete
 *   set of mechanisms for which the new credential is valid.  Storage
 *   for the returned OID-set must be freed by the application after
 *   use with a call to gss_release_oid_set(). Specify NULL if not
 *   required.
 * @initiator_time_rec: (Integer, modify, optional) Actual number of
 *   seconds for which the returned credentials will remain valid for
 *   initiating contexts using the specified mechanism.  If the
 *   implementation or mechanism does not support expiration of
 *   credentials, the value GSS_C_INDEFINITE will be returned. Specify
 *   NULL if not required
 * @acceptor_time_rec: (Integer, modify, optional) Actual number of
 *   seconds for which the returned credentials will remain valid for
 *   accepting security contexts using the specified mechanism.  If
 *   the implementation or mechanism does not support expiration of
 *   credentials, the value GSS_C_INDEFINITE will be returned. Specify
 *   NULL if not required
 *
 * Adds a credential-element to a credential.  The credential-element is
 * identified by the name of the principal to which it refers.  GSS-API
 * implementations must impose a local access-control policy on callers
 * of this routine to prevent unauthorized callers from acquiring
 * credential-elements to which they are not entitled. This routine is
 * not intended to provide a "login to the network" function, as such a
 * function would involve the creation of new mechanism-specific
 * authentication data, rather than merely acquiring a GSS-API handle to
 * existing data.  Such functions, if required, should be defined in
 * implementation-specific extensions to the API.
 *
 * If desired_name is GSS_C_NO_NAME, the call is interpreted as a
 * request to add a credential element that will invoke default behavior
 * when passed to gss_init_sec_context() (if cred_usage is
 * GSS_C_INITIATE or GSS_C_BOTH) or gss_accept_sec_context() (if
 * cred_usage is GSS_C_ACCEPT or GSS_C_BOTH).
 *
 * This routine is expected to be used primarily by context acceptors,
 * since implementations are likely to provide mechanism-specific ways
 * of obtaining GSS-API initiator credentials from the system login
 * process.  Some implementations may therefore not support the
 * acquisition of GSS_C_INITIATE or GSS_C_BOTH credentials via
 * gss_acquire_cred for any name other than GSS_C_NO_NAME, or a name
 * produced by applying either gss_inquire_cred to a valid credential,
 * or gss_inquire_context to an active context.
 *
 * If credential acquisition is time-consuming for a mechanism, the
 * mechanism may choose to delay the actual acquisition until the
 * credential is required (e.g. by gss_init_sec_context or
 * gss_accept_sec_context).  Such mechanism-specific implementation
 * decisions should be invisible to the calling application; thus a call
 * of gss_inquire_cred immediately following the call of gss_add_cred
 * must return valid credential data, and may therefore incur the
 * overhead of a deferred credential acquisition.
 *
 * This routine can be used to either compose a new credential
 * containing all credential-elements of the original in addition to the
 * newly-acquire credential-element, or to add the new credential-
 * element to an existing credential. If NULL is specified for the
 * output_cred_handle parameter argument, the new credential-element
 * will be added to the credential identified by input_cred_handle; if a
 * valid pointer is specified for the output_cred_handle parameter, a
 * new credential handle will be created.
 *
 * If GSS_C_NO_CREDENTIAL is specified as the input_cred_handle,
 * gss_add_cred will compose a credential (and set the
 * output_cred_handle parameter accordingly) based on default behavior.
 * That is, the call will have the same effect as if the application had
 * first made a call to gss_acquire_cred(), specifying the same usage
 * and passing GSS_C_NO_NAME as the desired_name parameter to obtain an
 * explicit credential handle embodying default behavior, passed this
 * credential handle to gss_add_cred(), and finally called
 * gss_release_cred() on the first credential handle.
 *
 * If GSS_C_NO_CREDENTIAL is specified as the input_cred_handle
 * parameter, a non-NULL output_cred_handle must be supplied.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_BAD_MECH`: Unavailable mechanism requested.
 *
 * `GSS_S_BAD_NAMETYPE`: Type contained within desired_name parameter
 * is not supported.
 *
 * `GSS_S_BAD_NAME`: Value supplied for desired_name parameter is
 * ill-formed.
 *
 * `GSS_S_DUPLICATE_ELEMENT`: The credential already contains an
 * element for the requested mechanism with overlapping usage and
 * validity period.
 *
 * `GSS_S_CREDENTIALS_EXPIRED`: The required credentials could not be
 * added because they have expired.
 *
 * `GSS_S_NO_CRED`: No credentials were found for the specified name.
 **/
OM_uint32
gss_add_cred (OM_uint32 * minor_status,
	      const gss_cred_id_t input_cred_handle,
	      const gss_name_t desired_name,
	      const gss_OID desired_mech,
	      gss_cred_usage_t cred_usage,
	      OM_uint32 initiator_time_req,
	      OM_uint32 acceptor_time_req,
	      gss_cred_id_t * output_cred_handle,
	      gss_OID_set * actual_mechs,
	      OM_uint32 * initiator_time_rec, OM_uint32 * acceptor_time_rec)
{
  return GSS_S_UNAVAILABLE;
}

/**
 * gss_inquire_cred:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @cred_handle: (gss_cred_id_t, read) A handle that refers to the
 *   target credential.  Specify GSS_C_NO_CREDENTIAL to inquire about
 *   the default initiator principal.
 * @name: (gss_name_t, modify, optional) The name whose identity the
 *   credential asserts.  Storage associated with this name should be
 *   freed by the application after use with a call to
 *   gss_release_name().  Specify NULL if not required.
 * @lifetime: (Integer, modify, optional) The number of seconds for
 *   which the credential will remain valid.  If the credential has
 *   expired, this parameter will be set to zero.  If the
 *   implementation does not support credential expiration, the value
 *   GSS_C_INDEFINITE will be returned.  Specify NULL if not required.
 * @cred_usage: (gss_cred_usage_t, modify, optional) How the
 *   credential may be used.  One of the following: GSS_C_INITIATE,
 *   GSS_C_ACCEPT, GSS_C_BOTH. Specify NULL if not required.
 * @mechanisms: (gss_OID_set, modify, optional) Set of mechanisms
 *   supported by the credential.  Storage associated with this OID
 *   set must be freed by the application after use with a call to
 *   gss_release_oid_set().  Specify NULL if not required.
 *
 * Obtains information about a credential.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_NO_CRED`: The referenced credentials could not be accessed.
 *
 * `GSS_S_DEFECTIVE_CREDENTIAL`: The referenced credentials were invalid.
 *
 * `GSS_S_CREDENTIALS_EXPIRED`: The referenced credentials have
 * expired.  If the lifetime parameter was not passed as NULL, it will
 * be set to 0.
 **/
OM_uint32
gss_inquire_cred (OM_uint32 * minor_status,
		  const gss_cred_id_t cred_handle,
		  gss_name_t * name,
		  OM_uint32 * lifetime,
		  gss_cred_usage_t * cred_usage, gss_OID_set * mechanisms)
{
  gss_cred_id_t credh = cred_handle;
  _gss_mech_api_t mech;
  OM_uint32 maj_stat;

  if (cred_handle == GSS_C_NO_CREDENTIAL)
    {
      maj_stat = gss_acquire_cred (minor_status, GSS_C_NO_NAME,
				   GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
				   GSS_C_INITIATE, &credh, NULL, NULL);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  mech = _gss_find_mech (credh->mech);
  if (mech == NULL)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_MECH;
    }

  maj_stat = mech->inquire_cred (minor_status, credh, name, lifetime,
				 cred_usage, mechanisms);

  if (cred_handle == GSS_C_NO_CREDENTIAL)
    gss_release_cred (NULL, &credh);

  return maj_stat;
}

/**
 * gss_inquire_cred_by_mech:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @cred_handle: (gss_cred_id_t, read) A handle that refers to the
 *   target credential.  Specify GSS_C_NO_CREDENTIAL to inquire about
 *   the default initiator principal.
 * @mech_type: (gss_OID, read) The mechanism for which information
 *  should be returned.
 * @name: (gss_name_t, modify, optional) The name whose identity the
 *   credential asserts.  Storage associated with this name must be
 *   freed by the application after use with a call to
 *   gss_release_name().  Specify NULL if not required.
 * @initiator_lifetime: (Integer, modify, optional) The number of
 *   seconds for which the credential will remain capable of
 *   initiating security contexts under the specified mechanism.  If
 *   the credential can no longer be used to initiate contexts, or if
 *   the credential usage for this mechanism is GSS_C_ACCEPT, this
 *   parameter will be set to zero.  If the implementation does not
 *   support expiration of initiator credentials, the value
 *   GSS_C_INDEFINITE will be returned.  Specify NULL if not required.
 * @acceptor_lifetime: (Integer, modify, optional) The number of
 *   seconds for which the credential will remain capable of accepting
 *   security contexts under the specified mechanism.  If the
 *   credential can no longer be used to accept contexts, or if the
 *   credential usage for this mechanism is GSS_C_INITIATE, this
 *   parameter will be set to zero.  If the implementation does not
 *   support expiration of acceptor credentials, the value
 *   GSS_C_INDEFINITE will be returned.  Specify NULL if not required.
 * @cred_usage: (gss_cred_usage_t, modify, optional) How the
 *   credential may be used with the specified mechanism.  One of the
 *   following: GSS_C_INITIATE, GSS_C_ACCEPT, GSS_C_BOTH. Specify NULL
 *   if not required.
 *
 * Obtains per-mechanism information about a credential.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_NO_CRED`: The referenced credentials could not be accessed.
 *
 * `GSS_S_DEFECTIVE_CREDENTIAL`: The referenced credentials were invalid.
 *
 * `GSS_S_CREDENTIALS_EXPIRED`: The referenced credentials have
 * expired.  If the lifetime parameter was not passed as NULL, it will
 * be set to 0.
 **/
OM_uint32
gss_inquire_cred_by_mech (OM_uint32 * minor_status,
			  const gss_cred_id_t cred_handle,
			  const gss_OID mech_type,
			  gss_name_t * name,
			  OM_uint32 * initiator_lifetime,
			  OM_uint32 * acceptor_lifetime,
			  gss_cred_usage_t * cred_usage)
{
  _gss_mech_api_t mech;
  gss_cred_id_t credh = cred_handle;
  OM_uint32 maj_stat;

  if (mech_type == GSS_C_NO_OID)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_MECH;
    }

  mech = _gss_find_mech (mech_type);
  if (mech == NULL)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_MECH;
    }

  if (cred_handle == GSS_C_NO_CREDENTIAL)
    {
      maj_stat = gss_acquire_cred (minor_status,
				   GSS_C_NO_NAME, GSS_C_INDEFINITE,
				   /* FIXME: We should create an OID
				      set with mech_type and pass it
				      as desired_mechs.  Maybe even
				      check actual_mechs too. */
				   GSS_C_NO_OID_SET,
				   GSS_C_INITIATE, &credh, NULL, NULL);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  maj_stat = mech->inquire_cred_by_mech (minor_status, credh, mech_type, name,
					 initiator_lifetime,
					 acceptor_lifetime, cred_usage);

  if (cred_handle == GSS_C_NO_CREDENTIAL)
    gss_release_cred (NULL, &credh);

  return maj_stat;
}

/**
 * gss_release_cred:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @cred_handle: (gss_cred_id_t, modify, optional) Opaque handle
 *   identifying credential to be released.  If GSS_C_NO_CREDENTIAL is
 *   supplied, the routine will complete successfully, but will do
 *   nothing.
 *
 * Informs GSS-API that the specified credential handle is no longer
 * required by the application, and frees associated resources.  The
 * cred_handle is set to GSS_C_NO_CREDENTIAL on successful completion
 * of this call.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_NO_CRED`: Credentials could not be accessed.
 **/
OM_uint32
gss_release_cred (OM_uint32 * minor_status, gss_cred_id_t * cred_handle)
{
  _gss_mech_api_t mech;
  OM_uint32 maj_stat;

  if (!cred_handle)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_NO_CRED | GSS_S_CALL_INACCESSIBLE_READ;
    }

  if (*cred_handle == GSS_C_NO_CREDENTIAL)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_COMPLETE;
    }

  mech = _gss_find_mech ((*cred_handle)->mech);
  if (mech == NULL)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_DEFECTIVE_CREDENTIAL;
    }

  maj_stat = mech->release_cred (minor_status, cred_handle);
  free (*cred_handle);
  *cred_handle = GSS_C_NO_CREDENTIAL;
  if (GSS_ERROR (maj_stat))
    return maj_stat;

  return GSS_S_COMPLETE;
}
