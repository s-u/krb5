#include <krb5.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <Rinternals.h>

static char err_buf[768];

static krb5_context kcontext;

static void krb_error(errcode_t code, const char *cm)
{
    const char *msg;
    msg = krb5_get_error_message(kcontext, code);
    snprintf(err_buf, sizeof(err_buf), "%s%s%s", cm, (*cm) ? ": " : "", msg);
    krb5_free_error_message(kcontext, msg);
    krb5_free_context(kcontext);
    Rf_error(err_buf);
}

static void krb_warn(errcode_t code, const char *cm)
{
    const char *msg;
    msg = krb5_get_error_message(kcontext, code);
    snprintf(err_buf, sizeof(err_buf), "%s%s%s", cm, (*cm) ? ": " : "", msg);
    krb5_free_error_message(kcontext, msg);
    krb5_free_context(kcontext);
    Rf_warning(err_buf);
}

static int data_eq(krb5_data d1, krb5_data d2)
{
    return (d1.length == d2.length &&
	    (d1.length == 0 || !memcmp(d1.data, d2.data, d1.length)));
}

static int data_eq_string(krb5_data d, const char *s)
{
    return (d.length == strlen(s) &&
	    (d.length == 0 || !memcmp(d.data, s, d.length)));
}

static krb5_boolean is_local_tgt(krb5_principal princ, krb5_data *realm)
{
    return princ->length == 2 && data_eq(princ->realm, *realm) &&
        data_eq_string(princ->data[0], KRB5_TGS_NAME) &&
        data_eq(princ->data[1], *realm);
}

static int check_cache(krb5_ccache cache, krb5_principal princ) {
    krb5_error_code ret;
    krb5_cc_cursor cur;
    krb5_creds creds;
    krb5_boolean found_tgt, found_current_tgt, found_current_cred;
    krb5_int32 now = (krb5_int32) time(NULL);

    if (krb5_cc_start_seq_get(kcontext, cache, &cur) != 0)
        return 1;
    found_tgt = found_current_tgt = found_current_cred = 0;
    while (!(ret = krb5_cc_next_cred(kcontext, cache, &cur, &creds))) {
        if (is_local_tgt(creds.server, &princ->realm)) {
            found_tgt = 1;
            if (creds.times.endtime > now)
                found_current_tgt = 1;
        } else if (!krb5_is_config_principal(kcontext, creds.server) &&
                   creds.times.endtime > now) {
            found_current_cred = 1;
        }
        krb5_free_cred_contents(kcontext, &creds);
    }

    if (ret != KRB5_CC_END)
        return 1;
    if (krb5_cc_end_seq_get(kcontext, cache, &cur) != 0)
        return 1;
    
    if (found_tgt)
        return found_current_tgt ? 0 : 1;
    return found_current_cred ? 0 : 1;
}

#define MAX_LIST 128

SEXP C_klist() {
    krb5_error_code kec;
    krb5_ccache cache;
    krb5_cccol_cursor cursor;
    char *prinl[MAX_LIST];
    int  expl[MAX_LIST];
    int  pent = 0;

    if ((kec = krb5_init_context(&kcontext)))
	krb_error(kec, "ERROR: cannot create Kerberos context");

    if ((kec = krb5_cccol_cursor_new(kcontext, &cursor)))
	krb_error(kec, "ERROR: cannot get Kerberos cache");
    
    while (!(kec = krb5_cccol_cursor_next(kcontext, cursor, &cache)) && cache) {
	krb5_principal princ = NULL;
	char *princname = NULL;

	if (pent >= MAX_LIST) {
	    Rf_warning("WARNING: more than %d cache entries are not supported, truncating", MAX_LIST);
	    krb5_cc_close(kcontext, cache);
	    break;
	}
	if ((kec = krb5_cc_get_principal(kcontext, cache, &princ))) {
	    krb_warn(kec, "WARNING: cannot get Kerberos principal for cache entry");
	    krb5_cc_close(kcontext, cache);
	    continue;
	}
	if ((kec = krb5_unparse_name(kcontext, princ, &princname)) || !princname) {
	    krb_warn(kec, "WARNING: cannot get Kerberos principal name");
	    krb5_free_principal(kcontext, princ);
	    krb5_cc_close(kcontext, cache);
	    continue;
	}
	prinl[pent] = strdup(princname);
	expl [pent] = check_cache(cache, princ);
	pent++;
	krb5_free_principal(kcontext, princ);
        krb5_cc_close(kcontext, cache);
    }
    krb5_cccol_cursor_free(kcontext, &cursor);
    krb5_free_context(kcontext);

    /* nothing from Kerberos is allocated at this point */
    {
	SEXP res = PROTECT(mkNamed(VECSXP, (const char*[]) { "principal", "expired", "" }));
	int i = 0;
	SEXP sPrin = SET_VECTOR_ELT(res, 0, allocVector(STRSXP, pent));
	SEXP sExp  = SET_VECTOR_ELT(res, 1, allocVector(LGLSXP, pent));
	SEXP sRN = PROTECT(allocVector(INTSXP, 2));
	INTEGER(sRN)[0] = NA_INTEGER;
	INTEGER(sRN)[1] = pent;
	Rf_setAttrib(res, R_RowNamesSymbol, sRN);
	UNPROTECT(1);
	Rf_setAttrib(res, R_ClassSymbol, mkString("data.frame"));
	while (i < pent) {
	    SET_STRING_ELT(sPrin, i, mkChar(prinl[i]));
	    free(prinl[i]);
	    LOGICAL(sExp)[i] = expl[i];
	    i++;
	}
	UNPROTECT(1);
	return res;
    }
}

SEXP C_kinit(SEXP sCache, SEXP sPrinc, SEXP sPwd, SEXP sKeytab) {
    krb5_error_code kec;
    krb5_ccache cache;
    krb5_principal princ = 0;
    const char *cache_name = 0;
    const char *principal_name = 0;
    const char *pwd = 0;
    const char *keytab_name = 0;
    char *final_pname = 0;

    int flags = 0;

    if (TYPEOF(sCache) == STRSXP && LENGTH(sCache) > 0)
	cache_name = CHAR(STRING_ELT(sCache, 0));
    if (TYPEOF(sPrinc) == STRSXP && LENGTH(sPrinc) > 0)
	principal_name = CHAR(STRING_ELT(sPrinc, 0));
    if (TYPEOF(sPwd) == STRSXP && LENGTH(sPwd) > 0)
	pwd = CHAR(STRING_ELT(sPwd, 0));
    if (TYPEOF(sKeytab) == STRSXP && LENGTH(sKeytab) > 0)
	keytab_name = CHAR(STRING_ELT(sKeytab, 0));

    if (!keytab_name && !pwd) 
	Rf_error("missing both keytab and password - please specify at least one");
    if ((kec = krb5_init_context(&kcontext)))
        krb_error(kec, "ERROR: cannot create Kerberos context");
   
    if (cache_name) {
        if ((kec = krb5_cc_resolve(kcontext, cache_name, &cache)))
	    krb_error(kec, "ERROR: cannot resolve specified cache");
    } else {
        if ((kec = krb5_cc_default(kcontext, &cache)))
	    krb_error(kec, "ERROR: cannot get default cache");
    }

    /*    deftype = krb5_cc_get_type(k5->ctx, defcache);
    if (krb5_cc_get_principal(k5->ctx, defcache, &defcache_princ) != 0)
    defcache_princ = NULL; */


    if (principal_name) {
        if ((kec = krb5_parse_name_flags(kcontext, principal_name, flags, &princ)))
	    krb_error(kec, "ERROR: cannot parse principal");
    } else {
	if ((kec = krb5_cc_get_principal(kcontext, cache, &princ)))
	    krb_error(kec, "ERROR: cannot get principal from the cache");
    }

    if ((kec = krb5_unparse_name(kcontext, princ, &final_pname)))
	krb_error(kec, "ERROR: cannot deparse principal name");

    {
	krb5_keytab keytab = 0;
	krb5_creds my_creds;
	krb5_get_init_creds_opt *options = NULL;

	if (keytab_name && (kec = krb5_kt_resolve(kcontext, keytab_name, &keytab)))
	    krb_error(kec, "ERROR: cannot open keytab");
	
	memset(&my_creds, 0, sizeof(my_creds));
	if ((kec = krb5_get_init_creds_opt_alloc(kcontext, &options)))
	    krb_error(kec, "ERROR: cannot allocate credential options");

#ifndef __APPLE__
	if ((kec = krb5_get_init_creds_opt_set_out_ccache(kcontext, options, cache)))
	    krb_error(kec, "ERROR: cannot set output cache");
#endif
	
	if (pwd) {
	    if ((kec = krb5_get_init_creds_password(kcontext, &my_creds, princ, pwd,
						    0, 0, 0, 0, options)))
		krb_error(kec, "ERROR: getting initial credentials failed");
	} else if (keytab_name) {
	    if ((kec = krb5_get_init_creds_keytab(kcontext, &my_creds, princ, keytab,
						  0, 0, options)))
		krb_error(kec, "ERROR: getting initial credentials via keytab failed");
	}

#ifdef __APPLE__
	// Apple's GSS shim doesn't have krb5_get_init_creds_opt_set_out_ccache()
	if ((kec = krb5_cc_initialize(kcontext, cache, princ)))
	    krb_error(kec, "ERROR: could not initialize output cache");

	if ((kec = krb5_cc_store_cred(kcontext, cache, &my_creds)))
	    krb_error(kec, "ERROR: could not store credentials in cache");
#endif

	if (keytab)
	    krb5_kt_close(kcontext, keytab);
    }

    /* FIXME: we don't release any of the above on error */
    krb5_cc_close(kcontext, cache);

    {
	SEXP res = mkString(final_pname);
        krb5_free_unparsed_name(kcontext, final_pname);
	krb5_free_principal(kcontext, princ);
	krb5_free_context(kcontext);
	return res;
    }
}
