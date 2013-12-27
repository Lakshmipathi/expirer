version=`grep argp_program_version src/expirer.c | cut -f2 -d'=' | cut -f3 -d' '`
git archive --prefix=expirer/ master | bzip2 >expirer_${version}.tar.bz2
