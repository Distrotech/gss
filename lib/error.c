/* error.c	Error handling functionality.
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

struct gss_status_codes
{
  gss_uint32 err;
  char *name;
  char *text;
};

struct gss_status_codes gss_calling_errors[] = {
  {GSS_S_CALL_INACCESSIBLE_READ, "GSS_S_CALL_INACCESSIBLE_READ",
   N_("A required input parameter could not be read")},
  {GSS_S_CALL_INACCESSIBLE_WRITE, "GSS_S_CALL_INACCESSIBLE_WRITE",
   N_("A required output parameter could not be written")},
  {GSS_S_CALL_BAD_STRUCTURE, "GSS_S_CALL_BAD_STRUCTURE",
   N_("A parameter was malformed")}
};

struct gss_status_codes gss_routine_errors[] = {
  {GSS_S_BAD_MECH, "GSS_S_BAD_MECH",
   N_("An unsupported mechanism was requested")},
  {GSS_S_BAD_NAME, "GSS_S_BAD_NAME",
   N_("An invalid name was supplied")},
  {GSS_S_BAD_NAMETYPE, "GSS_S_BAD_NAMETYPE",
   N_("A supplied name was of an unsupported type")},
  {GSS_S_BAD_BINDINGS, "GSS_S_BAD_BINDINGS",
   N_("Incorrect channel bindings were supplied")},
  {GSS_S_BAD_STATUS, "GSS_S_BAD_STATUS",
   N_("An invalid status code was supplied")},
  {GSS_S_BAD_SIG, "GSS_S_BAD_SIG",
   N_("A token had an invalid MIC")},
  {GSS_S_NO_CRED, "GSS_S_NO_CRED",
   N_("No credentials were supplied, or the credentials were unavailable "
      "or inaccessible")},
  {GSS_S_NO_CONTEXT, "GSS_S_NO_CONTEXT",
   N_("No context has been established")},
  {GSS_S_DEFECTIVE_TOKEN, "GSS_S_DEFECTIVE_TOKEN",
   N_("A token was invalid")},
  {GSS_S_DEFECTIVE_CREDENTIAL, "GSS_S_DEFECTIVE_CREDENTIAL",
   N_("A credential was invalid")},
  {GSS_S_CREDENTIALS_EXPIRED, "GSS_S_CREDENTIALS_EXPIRED",
   N_("The referenced credentials have expired")},
  {GSS_S_CONTEXT_EXPIRED, "GSS_S_CONTEXT_EXPIRED",
   N_("The context has expired")},
  {GSS_S_FAILURE, "GSS_S_FAILURE",
   N_("Unspecified error in underlying mechanism")},
  {GSS_S_BAD_QOP, "GSS_S_BAD_QOP",
   N_("The quality-of-protection requested could not be provided")},
  {GSS_S_UNAUTHORIZED, "GSS_S_UNAUTHORIZED",
   N_("The operation is forbidden by local security policy")},
  {GSS_S_UNAVAILABLE, "GSS_S_UNAVAILABLE",
   N_("The operation or option is unavailable")},
  {GSS_S_DUPLICATE_ELEMENT, "GSS_S_DUPLICATE_ELEMENT",
   N_("The requested credential element already exists")},
  {GSS_S_NAME_NOT_MN, "GSS_S_NAME_NOT_MN",
   N_("The provided name was not a mechanism name")}
};

struct gss_status_codes gss_supplementary_errors[] = {
  {GSS_S_CONTINUE_NEEDED, "GSS_S_CONTINUE_NEEDED",
   N_("The gss_init_sec_context() or gss_accept_sec_context() function "
      "must be called again to complete its function")},
  {GSS_S_DUPLICATE_TOKEN, "GSS_S_DUPLICATE_TOKEN",
   N_("The token was a duplicate of an earlier token")},
  {GSS_S_OLD_TOKEN, "GSS_S_OLD_TOKEN",
   N_("The token's validity period has expired")},
  {GSS_S_UNSEQ_TOKEN, "GSS_S_UNSEQ_TOKEN",
   N_("A later token has already been processed")},
  {GSS_S_GAP_TOKEN, "GSS_S_GAP_TOKEN",
   N_("An expected per-message token was not received")}
};

OM_uint32
gss_display_status (OM_uint32 * minor_status,
		    OM_uint32 status_value,
		    int status_type,
		    const gss_OID mech_type,
		    OM_uint32 * message_context,
		    gss_buffer_t status_string)
{
  if (minor_status)
    *minor_status = 0;

  switch (status_type)
    {
    case GSS_C_GSS_CODE:
      switch (GSS_CALLING_ERROR(status_value))
	{
	case 0:
	  break;

	case GSS_S_CALL_INACCESSIBLE_READ:
	case GSS_S_CALL_INACCESSIBLE_WRITE:
	case GSS_S_CALL_BAD_STRUCTURE:
	  status_string->value =
	    xstrdup(_(gss_calling_errors
		     [(GSS_CALLING_ERROR(status_value) >>
		       GSS_C_CALLING_ERROR_OFFSET)-1].text));
	  status_string->length = strlen(status_string->value);
	  return GSS_S_COMPLETE;
	  break;

	default:
	  status_string->value = xstrdup(_("Unknown calling error"));
	  status_string->length = strlen(status_string->value);
	  return GSS_S_COMPLETE;
	  break;
	}

      switch (GSS_ROUTINE_ERROR(status_value))
	{
	case 0:
	  break;

	case GSS_S_BAD_MECH:
	case GSS_S_BAD_NAME:
	case GSS_S_BAD_NAMETYPE:
	case GSS_S_BAD_BINDINGS:
	case GSS_S_BAD_STATUS:
	case GSS_S_BAD_SIG:
	case GSS_S_NO_CRED:
	case GSS_S_NO_CONTEXT:
	case GSS_S_DEFECTIVE_TOKEN:
	case GSS_S_DEFECTIVE_CREDENTIAL:
	case GSS_S_CREDENTIALS_EXPIRED:
	case GSS_S_CONTEXT_EXPIRED:
	case GSS_S_FAILURE:
	case GSS_S_BAD_QOP:
	case GSS_S_UNAUTHORIZED:
	case GSS_S_UNAVAILABLE:
	case GSS_S_DUPLICATE_ELEMENT:
	case GSS_S_NAME_NOT_MN:
	  status_string->value =
	    xstrdup(_(gss_routine_errors
		     [(GSS_ROUTINE_ERROR(status_value) >>
		       GSS_C_ROUTINE_ERROR_OFFSET)-1].text));
	  status_string->length = strlen(status_string->value);
	  return GSS_S_COMPLETE;
	  break;

	default:
	  status_string->value = xstrdup(_("Unknown routine error"));
	  status_string->length = strlen(status_string->value);
	  return GSS_S_COMPLETE;
	  break;
	}
      status_string->value = xstrdup(_("No error"));
      status_string->length = strlen(status_string->value);
      break;

    case GSS_C_MECH_CODE:
      {
	_gss_mech_api_t mech;

	mech = _gss_find_mech (mech_type);
	return mech->display_status (minor_status, status_value, status_type,
				     mech_type, message_context,
				     status_string);
      }
      break;

    default:
      return GSS_S_BAD_STATUS;
    }

  return GSS_S_COMPLETE;
}
