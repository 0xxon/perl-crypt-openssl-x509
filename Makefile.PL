use inc::Module::Install;

use Config;
use Alien::OpenSSL;

name('Crypt-OpenSSL-X509');
license('perl');
perl_version('5.005');
all_from('X509.pm');

homepage 'https://github.com/dsully/perl-crypt-openssl-x509';
bugtracker 'https://github.com/dsully/perl-crypt-openssl-x509/issues';
configure_requires 'Alien::OpenSSL' => 0.02;

requires_external_cc();

if ($Config::Config{myuname} =~ /^Win(32|64) strawberry-perl\b/) {
    cc_lib_links("eay$1");
}
else {
    my $cflags = Alien::OpenSSL->cflags;
    my $ldflags = Alien::OpenSSL->libs;

    inc $cflags;
    libs $ldflags;

    cc_lib_links('crypto');

    cc_optimize_flags('-O2 -g -Wall -Werror');
}

auto_install();
WriteAll();
