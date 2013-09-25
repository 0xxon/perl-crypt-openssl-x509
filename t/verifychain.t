use strict;
use warnings;

use Test::More tests => 17;

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

my $res = $rootstore->verify_chain($selfsigned, [], Crypt::OpenSSL::X509::X509_PURPOSE_SSL_SERVER, 1355260606);
is ( $res, -18, 'Selfsigned certificate invalid');
 
$res = $rootstore->verify_chain($rapidssl, [], Crypt::OpenSSL::X509::X509_PURPOSE_SSL_SERVER, 1355260606);
is ( ref($res), 'ARRAY', 'RapidSSL is valid, got array-ref');
is ( scalar @$res, 2, '2 certs');
is (  $res->[0]->subject, 'serialNumber=yt6kl9xkLw2fIY5OrbLCalG95MCJRgef, C=US, O=*.rapidssl.com, OU=GT23895939, OU=See www.rapidssl.com/resources/cps (c)10, OU=Domain Control Validated - RapidSSL(R), CN=*.rapidssl.com', 'end-host-cert');
is (  $res->[1]->subject, $res->[0]->issuer, 'ca-cert');

$res = $rootstore->verify_chain($google, [$thawte], Crypt::OpenSSL::X509::X509_PURPOSE_SSL_SERVER, 1355260606);
is ( ref($res), 'ARRAY', 'Google valid, got array-ref');
is ( scalar @$res, 3, '3 certs');
is (  $res->[0]->subject, 'C=US, ST=California, L=Mountain View, O=Google Inc, CN=www.google.com', 'end-host-cert');
is (  $res->[1]->subject, $res->[0]->issuer, 'ca-cert');
is (  $res->[1]->subject, 'C=ZA, O=Thawte Consulting (Pty) Ltd., CN=Thawte SGC CA');
is (  $res->[2]->subject, $res->[1]->issuer, 'ca-cert');
is (  $res->[2]->subject, 'C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority', 'root ca');
