/* gss/krb5.h --- Header file for Kerberos 5 GSS-API mechanism.
 * Copyright (C) 2003-2013 Simon Josefsson
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

/*
 * This file contains official Kerberos V5 GSS-API mechanism related
 * prototypes defined as in RFC 1964 and RFC 4121.  For GNU GSS
 * specific extensions, see gss/krb5-ext.h.
 *
 */

#ifndef GSS_KRB5_H
# define GSS_KRB5_H

/* 4.1.1. Non-Kerberos-specific codes */

#define GSS_KRB5_S_G_BAD_SERVICE_NAME 1
/* "No @ in SERVICE-NAME name string" */
#define GSS_KRB5_S_G_BAD_STRING_UID 2
/* "STRING-UID-NAME contains nondigits" */
#define GSS_KRB5_S_G_NOUSER 3
/* "UID does not resolve to username" */
#define GSS_KRB5_S_G_VALIDATE_FAILED 4
/* "Validation error" */
#define GSS_KRB5_S_G_BUFFER_ALLOC 5
/* "Couldn't allocate gss_buffer_t data" */
#define GSS_KRB5_S_G_BAD_MSG_CTX 6
/* "Message context invalid" */
#define GSS_KRB5_S_G_WRONG_SIZE 7
/* "Buffer is the wrong size" */
#define GSS_KRB5_S_G_BAD_USAGE 8
/* "Credential usage type is unknown" */
#define GSS_KRB5_S_G_UNKNOWN_QOP 9
/* "Unknown quality of protection specified" */

/* 4.1.2. Kerberos-specific-codes */

#define GSS_KRB5_S_KG_CCACHE_NOMATCH 10
/* "Principal in credential cache does not match desired name" */
#define GSS_KRB5_S_KG_KEYTAB_NOMATCH 11
/* "No principal in keytab matches desired name" */
#define GSS_KRB5_S_KG_TGT_MISSING 12
/* "Credential cache has no TGT" */
#define GSS_KRB5_S_KG_NO_SUBKEY 13
/* "Authenticator has no subkey" */
#define GSS_KRB5_S_KG_CONTEXT_ESTABLISHED 14
/* "Context is already fully established" */
#define GSS_KRB5_S_KG_BAD_SIGN_TYPE 15
/* "Unknown signature type in token" */
#define GSS_KRB5_S_KG_BAD_LENGTH 16
/* "Invalid field length in token" */
#define GSS_KRB5_S_KG_CTX_INCOMPLETE 17
/* "Attempt to use incomplete security context" */

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) user_name(1)}.  The recommended symbolic name
 * for this type is "GSS_KRB5_NT_USER_NAME".
 */
extern gss_OID GSS_KRB5_NT_USER_NAME;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) service_name(4)}.  The previously recommended
 * symbolic name for this type is
 * "GSS_KRB5_NT_HOSTBASED_SERVICE_NAME".  The currently preferred
 * symbolic name for this type is "GSS_C_NT_HOSTBASED_SERVICE".
 */
extern gss_OID GSS_KRB5_NT_HOSTBASED_SERVICE_NAME;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) krb5(2) krb5_name(1)}.  The recommended symbolic name for
 * this type is "GSS_KRB5_NT_PRINCIPAL_NAME".
 */
extern gss_OID GSS_KRB5_NT_PRINCIPAL_NAME;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) machine_uid_name(2)}.  The recommended
 * symbolic name for this type is "GSS_KRB5_NT_MACHINE_UID_NAME".
 */
extern gss_OID GSS_KRB5_NT_MACHINE_UID_NAME;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) string_uid_name(3)}.  The recommended symbolic
 * name for this type is "GSS_KRB5_NT_STRING_UID_NAME".
 */
extern gss_OID GSS_KRB5_NT_STRING_UID_NAME;

#endif /* GSS_KRB5_H */
