/* error.c --- Error handling functionality.
 * Copyright (C) 2003, 2004, 2005, 2006, 2007  Simon Josefsson
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
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "internal.h"

/* Get i18n. */
#include <gettext.h>
#define _(String) dgettext (PACKAGE, String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

/* _gss_find_mech */
#include "meta.h"

struct gss_status_codes
{
  gss_uint32 err;
  const char *name;
  const char *text;
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

/**
 * gss_display_status:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @status_value: (Integer, read) Status value to be converted.
 * @status_type: (Integer, read) GSS_C_GSS_CODE - status_value is a
 *   GSS status code. GSS_C_MECH_CODE - status_value is a mechanism
 *   status code.
 * @mech_type: (Object ID, read, optional) Underlying mechanism (used
 *   to interpret a minor status value). Supply GSS_C_NO_OID to obtain
 *   the system default.
 * @message_context: (Integer, read/modify) Should be initialized to
 *   zero by the application prior to the first call.  On return from
 *   gss_display_status(), a non-zero status_value parameter indicates
 *   that additional messages may be extracted from the status code
 *   via subsequent calls to gss_display_status(), passing the same
 *   status_value, status_type, mech_type, and message_context
 *   parameters.
 * @status_string: (buffer, character string, modify) Textual
 *   interpretation of the status_value.  Storage associated with this
 *   parameter must be freed by the application after use with a call
 *   to gss_release_buffer().
 *
 * Allows an application to obtain a textual representation of a
 * GSS-API status code, for display to the user or for logging
 * purposes.  Since some status values may indicate multiple
 * conditions, applications may need to call gss_display_status
 * multiple times, each call generating a single text string.  The
 * message_context parameter is used by gss_display_status to store
 * state information about which error messages have already been
 * extracted from a given status_value; message_context must be
 * initialized to 0 by the application prior to the first call, and
 * gss_display_status will return a non-zero value in this parameter
 * if there are further messages to extract.
 *
 * The message_context parameter contains all state information
 * required by gss_display_status in order to extract further messages
 * from the status_value; even when a non-zero value is returned in
 * this parameter, the application is not required to call
 * gss_display_status again unless subsequent messages are desired.
 * The following code extracts all messages from a given status code
 * and prints them to stderr:
 *
 *
 * ---------------------------------------------------
 * OM_uint32 message_context;
 * OM_uint32 status_code;
 * OM_uint32 maj_status;
 * OM_uint32 min_status;
 * gss_buffer_desc status_string;
 *
 *        ...
 *
 * message_context = 0;
 *
 * do {
 *   maj_status = gss_display_status (
 *                   &min_status,
 *                   status_code,
 *                   GSS_C_GSS_CODE,
 *                   GSS_C_NO_OID,
 *                   &message_context,
 *                   &status_string)
 *
 *   fprintf(stderr,
 *           "%.*s\n",
 *          (int)status_string.length,
 *
 *          (char *)status_string.value);
 *
 *   gss_release_buffer(&min_status, &status_string);
 *
 * } while (message_context != 0);
 * ---------------------------------------------------
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_BAD_MECH`: Indicates that translation in accordance with an
 * unsupported mechanism type was requested.
 *
 * `GSS_S_BAD_STATUS`: The status value was not recognized, or the
 * status type was neither GSS_C_GSS_CODE nor GSS_C_MECH_CODE.
 **/
OM_uint32
gss_display_status (OM_uint32 * minor_status,
		    OM_uint32 status_value,
		    int status_type,
		    const gss_OID mech_type,
		    OM_uint32 * message_context, gss_buffer_t status_string)
{
  size_t i;

  if (minor_status)
    *minor_status = 0;

  if (message_context)
    status_value &= ~*message_context;

  switch (status_type)
    {
    case GSS_C_GSS_CODE:
      if (message_context)
	{
	  *message_context |=
	    GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET;
	  if ((status_value & ~*message_context) == 0)
	    *message_context = 0;
	}

      switch (GSS_ROUTINE_ERROR (status_value))
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
	    xstrdup (_(gss_routine_errors
		       [(GSS_ROUTINE_ERROR (status_value) >>
			 GSS_C_ROUTINE_ERROR_OFFSET) - 1].text));
	  status_string->length = strlen (status_string->value);
	  return GSS_S_COMPLETE;
	  break;

	default:
	  return GSS_S_BAD_STATUS;
	  break;
	}

      if (message_context)
	{
	  *message_context |=
	    GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET;
	  if ((status_value & ~*message_context) == 0)
	    *message_context = 0;
	}

      switch (GSS_CALLING_ERROR (status_value))
	{
	case 0:
	  break;

	case GSS_S_CALL_INACCESSIBLE_READ:
	case GSS_S_CALL_INACCESSIBLE_WRITE:
	case GSS_S_CALL_BAD_STRUCTURE:
	  status_string->value =
	    xstrdup (_(gss_calling_errors
		       [(GSS_CALLING_ERROR (status_value) >>
			 GSS_C_CALLING_ERROR_OFFSET) - 1].text));
	  status_string->length = strlen (status_string->value);
	  return GSS_S_COMPLETE;
	  break;

	default:
	  return GSS_S_BAD_STATUS;
	  break;
	}

      for (i = 0; i < sizeof (gss_supplementary_errors) /
	   sizeof (gss_supplementary_errors[0]); i++)
	if (gss_supplementary_errors[i].err &
	    GSS_SUPPLEMENTARY_INFO (status_value))
	  {
	    status_string->value =
	      xstrdup (_(gss_supplementary_errors[i].text));
	    status_string->length = strlen (status_string->value);
	    *message_context |= gss_supplementary_errors[i].err;
	    if ((status_value & ~*message_context) == 0)
	      *message_context = 0;
	    return GSS_S_COMPLETE;
	  }

      if (GSS_SUPPLEMENTARY_INFO (status_value))
	return GSS_S_BAD_STATUS;

      if (message_context)
	*message_context = 0;
      status_string->value = xstrdup (_("No error"));
      status_string->length = strlen (status_string->value);
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
