\name{klist}
\alias{klist}
\title{
  List credentials in Kerberos cache.
}
\description{
  \code{klist} lists credentials in the current Kerberos cache and
  report whether they are expired or not.
}
\usage{
klist()
}
%\details{
%}
\value{
  Data frame with columns \code{"principal"} and \code{"expired"}. In
  most cases Kerberos errors are converted into warnings. The only hard
  error is if no Kerberos context can be created at all.
}
\author{
  Simon Urbanek
}
%\seealso{
%}
\examples{
klist()
}
\keyword{manip}
