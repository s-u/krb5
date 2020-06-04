/* dummy file with no function whatsoever
   it just creates symbols to shut up
   false-positives in R CMD check */

extern void R_registerRoutines();
extern void R_useDynamicSymbols();

void dummy_() {
    R_registerRoutines();
    R_useDynamicSymbols();
}
