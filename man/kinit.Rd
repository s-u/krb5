\name{kinit}
\alias{kinit}
\title{
  Obtain initial Kerberos ticket
}
\description{
  \code{kinit} attepnts to authenticate with Kerberos and obtain a valid
  ticket either using password or keytab authentication.
}
\usage{
  kinit(user = Sys.getenv("USER"), realm = getOption("kerberos.realm"),
        cache = NULL, password = NULL,
        keytab = if(file.exists("~/.keytab")) "~/.keytab" else NULL)
}
\arguments{
  \item{user}{string, username of the principal}
  \item{realm}{string, Kerberos realm to authenticate}
  \item{cache}{string, name of the cache file, if \code{NULL} the
    default cache is used}
  \item{password}{string, if set, password authentication will be
    performed, \code{NULL} otherwise}
  \item{keytab}{string, if set, filename of the keytab file to use for
    authentication}
}
\details{
  The principal is constructed as \code{user@realm} and both have to be
  set. If either is missing, the first principal in the cache file is
  used. If there are no principals in th cache (inlcuding when the cache
  doesn't exist), both \code{user} and \code{realm} must be set.
}
\value{
  Full name of the authenticated principal.
  Failures to authenticate are signalled as errors.
}
\author{
  Simon Urbanek
}
\seealso{
  \code{\link{klist}}
}
%\examples{
%}
\keyword{manip}
