/* error.c	error handling functionality
 * Copyright (C) 2003  Simon Josefsson
 *
 * This file is part of GPL GSS-API.
 *
 * GPL GSS-API is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * GPL GSS-API is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with GPL GSS-API; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

struct gss_status_codes {
  gss_uint32 err;
  int value;
  char *name;
  char *text;
};

struct gss_status_codes gss_calling_errors[] = {
  { GSS_S_CALL_INACCESSIBLE_READ, 1, "GSS_S_CALL_INACCESSIBLE_READ",
    "A required input parameter could not be read" },
  { GSS_S_CALL_INACCESSIBLE_WRITE, 2, "GSS_S_CALL_INACCESSIBLE_WRITE",
    "A required output parameter could not be written." },
  { GSS_S_CALL_BAD_STRUCTURE, 3, "GSS_S_CALL_BAD_STRUCTURE",
    "A parameter was malformed" }
};

struct gss_status_codes gss_routine_errors[] = {
  { GSS_S_BAD_MECH, 1, "GSS_S_BAD_MECH",
    "An unsupported mechanism was requested" },
  { GSS_S_BAD_NAME, 2, "GSS_S_BAD_NAME"
    "An invalid name was supplied" },
  { GSS_S_BAD_NAMETYPE, 3, "GSS_S_BAD_NAMETYPE",
    "A supplied name was of an unsupported type" },
  { GSS_S_BAD_BINDINGS, 4, "GSS_S_BAD_BINDINGS",
    "Incorrect channel bindings were supplied" },
  { GSS_S_BAD_STATUS, 5, "GSS_S_BAD_STATUS",
    "An invalid status code was supplied" },
  { GSS_S_BAD_SIG, 6, "GSS_S_BAD_SIG",
    "A token had an invalid MIC" },
  { GSS_S_NO_CRED, 7, "GSS_S_NO_CRED",
    "No credentials were supplied, or the credentials were unavailable "
    "or inaccessible." },
  { GSS_S_NO_CONTEXT, 8, "GSS_S_NO_CONTEXT",
    "No context has been established" },
  { GSS_S_DEFECTIVE_TOKEN, 9, "GSS_S_DEFECTIVE_TOKEN",
    "A token was invalid" },
  { GSS_S_DEFECTIVE_CREDENTIAL, 10, "GSS_S_DEFECTIVE_CREDENTIAL",
    "A credential was invalid" },
  { GSS_S_CREDENTIALS_EXPIRED, 11, "GSS_S_CREDENTIALS_EXPIRED",
    "The referenced credentials have expired" },
  { GSS_S_CONTEXT_EXPIRED, 12, "GSS_S_CONTEXT_EXPIRED",
    "The context has expired" },
  { GSS_S_FAILURE, 13, "GSS_S_FAILURE",
    "Unspecified error in underlying mechanism" },
  { GSS_S_BAD_QOP, 14, "GSS_S_BAD_QOP",
    "The quality-of-protection requested could not be provided" },
  { GSS_S_UNAUTHORIZED, 15, "GSS_S_UNAUTHORIZED",
    "The operation is forbidden by local security policy" },
  { GSS_S_UNAVAILABLE, 16, "GSS_S_UNAVAILABLE",
    "The operation or option is unavailable" },
  { GSS_S_DUPLICATE_ELEMENT, 17, "GSS_S_DUPLICATE_ELEMENT",
    "The requested credential element already exists" },
  { GSS_S_NAME_NOT_MN, 18, "GSS_S_NAME_NOT_MN",
    "The provided name was not a mechanism name" }
};

struct gss_status_codes gss_supplementary_errors[] = {
  { GSS_S_CONTINUE_NEEDED, 0, "GSS_S_CONTINUE_NEEDED",
    "The gss_init_sec_context() or gss_accept_sec_context() function "
    "must be called again to complete its function." },
  { GSS_S_DUPLICATE_TOKEN, 1, "GSS_S_DUPLICATE_TOKEN",
    "The token was a duplicate of an earlier token" },
  { GSS_S_OLD_TOKEN, 2, "GSS_S_OLD_TOKEN",
    "The token's validity period has expired" },
  { GSS_S_UNSEQ_TOKEN, 3, "GSS_S_UNSEQ_TOKEN",
    "A later token has already been processed" },
  { GSS_S_GAP_TOKEN, 4, "GSS_S_GAP_TOKEN",
    "An expected per-message token was not received" }
};

/**
 * ggssapi_strerror:
 * @err: libgsasl error code
 *
 * Return value: Returns a pointer to a statically allocated string
 * containing a description of the error with the error value @err.
 * This string can be used to output a diagnostic message to the user.
 **/
const char *
ggssapi_strerror (gss_uint32 err)
{
  const char *p;

  switch (err)
    {
    case GSS_S_CALL_INACCESSIBLE_READ:
      p = _("A required input parameter could not be read");
      break;

    default:
      p = _("Unknown GSS-API error");
      break;
    }

  return p;

}
