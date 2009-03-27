/* gss/krb5-ext.h --- Header file for Kerberos 5 GSS-API mechanism.
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009  Simon Josefsson
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
 * This file contains GNU GSS specific Kerberos V5 related GSS-API
 * mechanism prototypes.  See gss/krb5.h for official prototypes.
 *
 */

#ifndef GSS_KRB5_EXT_H
# define GSS_KRB5_EXT_H

extern gss_OID GSS_KRB5;

/* Static symbols for other gss_OID types.  These are useful in static
   declarations. */
extern gss_OID_desc GSS_KRB5_static;
extern gss_OID_desc GSS_KRB5_NT_USER_NAME_static;
extern gss_OID_desc GSS_KRB5_NT_HOSTBASED_SERVICE_NAME_static;
extern gss_OID_desc GSS_KRB5_NT_PRINCIPAL_NAME_static;
extern gss_OID_desc GSS_KRB5_NT_MACHINE_UID_NAME_static;
extern gss_OID_desc GSS_KRB5_NT_STRING_UID_NAME_static;

#endif /* GSS_KRB5_EXT_H */
