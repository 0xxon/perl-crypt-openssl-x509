use strict;
use warnings;

use Test::More tests => 14;

use 5.10.1;

use Crypt::OpenSSL::X509;
use Data::Dumper;

my $rootstore = Crypt::OpenSSL::X509::Rootstore->new_from_file('certs/root.ca');
isa_ok($rootstore, 'Crypt::OpenSSL::X509::Rootstore');

my $selfsigned = Crypt::OpenSSL::X509->new_from_file('certs/selfsigned.pem');
isa_ok($selfsigned, 'Crypt::OpenSSL::X509');
my $rapidssl = Crypt::OpenSSL::X509->new_from_file('certs/rapidssl.pem');
isa_ok($rapidssl, 'Crypt::OpenSSL::X509');
my $google = Crypt::OpenSSL::X509->new_from_file('certs/google.pem');
isa_ok($google, 'Crypt::OpenSSL::X509');
my $thawte = Crypt::OpenSSL::X509->new_from_file('certs/thawte-intermediate.pem');
isa_ok($thawte, 'Crypt::OpenSSL::X509');

my $res = $rootstore->verify($selfsigned, [], Crypt::OpenSSL::X509::X509_PURPOSE_SSL_SERVER, 1355260606);
is ( $res, -18, 'Selfsigned certificate invalid');

$res = $rootstore->verify($rapidssl, [], Crypt::OpenSSL::X509::X509_PURPOSE_SSL_SERVER, 1355260606);
is ( $res, 1, 'RapidSSL is valid');

$res = $rootstore->verify($rapidssl, [], Crypt::OpenSSL::X509::X509_PURPOSE_CRL_SIGN, 1355260606);
is ( $res, -26, 'Invalid type');

$res = $rootstore->verify($rapidssl, [], Crypt::OpenSSL::X509::X509_PURPOSE_SSL_SERVER, 355260606);
is ( $res, -9, 'Not yet valid');

$res = $rootstore->verify($rapidssl, [], Crypt::OpenSSL::X509::X509_PURPOSE_SSL_SERVER, 1455260606);
is ( $res, -10, 'Expired');

$res = $rootstore->verify($google, [], Crypt::OpenSSL::X509::X509_PURPOSE_SSL_SERVER, 1355260606);
is ( $res, -20, 'Google needs an intermediate');

$res = $rootstore->verify($thawte, [], Crypt::OpenSSL::X509::X509_PURPOSE_ANY, 1355260606);
is ( $res, 1, 'Thawte is valid');

$res = $rootstore->verify($google, [$thawte], Crypt::OpenSSL::X509::X509_PURPOSE_SSL_SERVER, 1355260606);
is ( $res, 1, 'Google needs an intermediate');

$res = $rootstore->verify($google, [ $thawte ], Crypt::OpenSSL::X509::X509_PURPOSE_SMIME_SIGN, 1355260606);
is ( $res, -26, 'And it may not sign smime stuff');
