/* krb5/error.c --- Kerberos 5 GSS-API error handling functionality.
 * Copyright (C) 2003-2011 Simon Josefsson
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

/* Get specification. */
#include "k5internal.h"

struct gss_status_codes
{
  gss_uint32 err;
  const char *name;
  const char *text;
};

static struct gss_status_codes gss_krb5_errors[] = {
  /* 4.1.1. Non-Kerberos-specific codes */
  {GSS_KRB5_S_G_BAD_SERVICE_NAME, "GSS_KRB5_S_G_BAD_SERVICE_NAME",
   N_("No @ in SERVICE-NAME name string")},
  {GSS_KRB5_S_G_BAD_STRING_UID, "GSS_KRB5_S_G_BAD_STRING_UID",
   N_("STRING-UID-NAME contains nondigits")},
  {GSS_KRB5_S_G_NOUSER, "GSS_KRB5_S_G_NOUSER",
   N_("UID does not resolve to username")},
  {GSS_KRB5_S_G_VALIDATE_FAILED, "GSS_KRB5_S_G_VALIDATE_FAILED",
   N_("Validation error")},
  {GSS_KRB5_S_G_BUFFER_ALLOC, "GSS_KRB5_S_G_BUFFER_ALLOC",
   N_("Couldn't allocate gss_buffer_t data")},
  {GSS_KRB5_S_G_BAD_MSG_CTX, "GSS_KRB5_S_G_BAD_MSG_CTX",
   N_("Message context invalid")},
  {GSS_KRB5_S_G_WRONG_SIZE, "GSS_KRB5_S_G_WRONG_SIZE",
   N_("Buffer is the wrong size")},
  {GSS_KRB5_S_G_BAD_USAGE, "GSS_KRB5_S_G_BAD_USAGE",
   N_("Credential usage type is unknown")},
  {GSS_KRB5_S_G_UNKNOWN_QOP, "GSS_KRB5_S_G_UNKNOWN_QOP",
   N_("Unknown quality of protection specified")},
  /* 4.1.2. Kerberos-specific-codes */
  {GSS_KRB5_S_KG_CCACHE_NOMATCH, "GSS_KRB5_S_KG_CCACHE_NOMATCH",
   N_("Principal in credential cache does not match desired name")},
  {GSS_KRB5_S_KG_KEYTAB_NOMATCH, "GSS_KRB5_S_KG_KEYTAB_NOMATCH",
   N_("No principal in keytab matches desired name")},
  {GSS_KRB5_S_KG_TGT_MISSING, "GSS_KRB5_S_KG_TGT_MISSING",
   N_("Credential cache has no TGT")},
  {GSS_KRB5_S_KG_NO_SUBKEY, "GSS_KRB5_S_KG_NO_SUBKEY",
   N_("Authenticator has no subkey")},
  {GSS_KRB5_S_KG_CONTEXT_ESTABLISHED, "GSS_KRB5_S_KG_CONTEXT_ESTABLISHED",
   N_("Context is already fully established")},
  {GSS_KRB5_S_KG_BAD_SIGN_TYPE, "GSS_KRB5_S_KG_BAD_SIGN_TYPE",
   N_("Unknown signature type in token")},
  {GSS_KRB5_S_KG_BAD_LENGTH, "GSS_KRB5_S_KG_BAD_LENGTH",
   N_("Invalid field length in token")},
  {GSS_KRB5_S_KG_CTX_INCOMPLETE, "GSS_KRB5_S_KG_CTX_INCOMPLETE",
   N_("Attempt to use incomplete security context")}
};

OM_uint32
gss_krb5_display_status (OM_uint32 * minor_status,
			 OM_uint32 status_value,
			 int status_type,
			 const gss_OID mech_type,
			 OM_uint32 * message_context,
			 gss_buffer_t status_string)
{
  if (minor_status)
    *minor_status = 0;

  switch (status_value)
    {
    case 0:
      status_string->value = strdup (_("No krb5 error"));
      if (!status_string->value)
	{
	  if (minor_status)
	    *minor_status = ENOMEM;
	  return GSS_S_FAILURE;
	}
      status_string->length = strlen (status_string->value);
      break;

      /* 4.1.1. Non-Kerberos-specific codes */
    case GSS_KRB5_S_G_BAD_SERVICE_NAME:
    case GSS_KRB5_S_G_BAD_STRING_UID:
    case GSS_KRB5_S_G_NOUSER:
    case GSS_KRB5_S_G_VALIDATE_FAILED:
    case GSS_KRB5_S_G_BUFFER_ALLOC:
    case GSS_KRB5_S_G_BAD_MSG_CTX:
    case GSS_KRB5_S_G_WRONG_SIZE:
    case GSS_KRB5_S_G_BAD_USAGE:
    case GSS_KRB5_S_G_UNKNOWN_QOP:
      /* 4.1.2. Kerberos-specific-codes */
    case GSS_KRB5_S_KG_CCACHE_NOMATCH:
    case GSS_KRB5_S_KG_KEYTAB_NOMATCH:
    case GSS_KRB5_S_KG_TGT_MISSING:
    case GSS_KRB5_S_KG_NO_SUBKEY:
    case GSS_KRB5_S_KG_CONTEXT_ESTABLISHED:
    case GSS_KRB5_S_KG_BAD_SIGN_TYPE:
    case GSS_KRB5_S_KG_BAD_LENGTH:
    case GSS_KRB5_S_KG_CTX_INCOMPLETE:
      status_string->value =
	strdup (_(gss_krb5_errors[status_value - 1].text));
      if (!status_string->value)
	{
	  if (minor_status)
	    *minor_status = ENOMEM;
	  return GSS_S_FAILURE;
	}
      status_string->length = strlen (status_string->value);
      break;

    default:
      status_string->value = strdup (_("Unknown krb5 error"));
      if (!status_string->value)
	{
	  if (minor_status)
	    *minor_status = ENOMEM;
	  return GSS_S_FAILURE;
	}
      status_string->length = strlen (status_string->value);
      break;
    }

  return GSS_S_COMPLETE;
}
