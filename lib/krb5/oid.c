/* krb5/oid.c --- Definition of static Kerberos 5 GSS-API OIDs.
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

#include "k5internal.h"

/*
 * To support ongoing experimentation, testing, and evolution of the
 * specification, the Kerberos V5 GSS-API mechanism as defined in this
 * and any successor memos will be identified with the following
 * Object Identifier, as defined in RFC-1510, until the specification
 * is advanced to the level of Proposed Standard RFC:
 *
 * {iso(1), org(3), dod(5), internet(1), security(5), kerberosv5(2)}
 *
 * Upon advancement to the level of Proposed Standard RFC, the
 * Kerberos V5 GSS-API mechanism will be identified by an Object
 * Identifier having the value:
 *
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) krb5(2)}
 */
gss_OID_desc GSS_KRB5_static = {
  9, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
};
gss_OID GSS_KRB5 = &GSS_KRB5_static;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) user_name(1)}.  The recommended symbolic name
 * for this type is "GSS_KRB5_NT_USER_NAME".
 */
gss_OID_desc GSS_KRB5_NT_USER_NAME_static = {
  10, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"
};
gss_OID GSS_KRB5_NT_USER_NAME = &GSS_KRB5_NT_USER_NAME_static;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) service_name(4)}.  The previously recommended
 * symbolic name for this type is
 * "GSS_KRB5_NT_HOSTBASED_SERVICE_NAME".  The currently preferred
 * symbolic name for this type is "GSS_C_NT_HOSTBASED_SERVICE".
 */
gss_OID GSS_KRB5_NT_HOSTBASED_SERVICE_NAME =
  &GSS_C_NT_HOSTBASED_SERVICE_static;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) krb5(2) krb5_name(1)}.  The recommended symbolic name for
 * this type is "GSS_KRB5_NT_PRINCIPAL_NAME".
 */
gss_OID_desc GSS_KRB5_NT_PRINCIPAL_NAME_static = {
  10, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01"
};
gss_OID GSS_KRB5_NT_PRINCIPAL_NAME = &GSS_KRB5_NT_PRINCIPAL_NAME_static;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) string_uid_name(3)}.  The recommended symbolic
 * name for this type is "GSS_KRB5_NT_STRING_UID_NAME".
 */
gss_OID_desc GSS_KRB5_NT_STRING_UID_NAME_static = {
  10, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03"
};
gss_OID GSS_KRB5_NT_STRING_UID_NAME = &GSS_KRB5_NT_STRING_UID_NAME_static;
