klist <- function() .Call(C_klist)

kinit <- function(user=Sys.getenv("USER"), realm=getOption("kerberos.realm"),
                  cache=NULL, password=NULL, keytab=if(file.exists("~/.keytab")) "~/.keytab" else NULL) {
    principal <- if (is.null(user) || is.null(realm)) NULL else paste(user, realm, sep='@')
    .Call(C_kinit, cache, principal, password, if (is.null(keytab)) NULL else path.expand(keytab))
}
