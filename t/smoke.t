#!/usr/bin/env perl

use lib 't/lib';
use strictures 2;

use Authen::U2F;
use Crypt::Misc qw(write_rawfile);
use Crypt::OpenSSL::CA;
use Crypt::OpenSSL::X509;
use Crypt::PK::ECC;
use File::Slurp qw(read_file);
use JSON::MaybeXS qw(decode_json);
use MIME::Base64 qw(decode_base64url);
use Path::Tiny;
use Test::Exception;
use Test::More;

use aliased 'My::Test::Util';

use_ok 'Authen::U2F::Tester' or exit 1;

my $tmpdir = Path::Tiny->tempdir;
my $certfile = $tmpdir->child('cert.pem')->stringify;
my $keyfile  = $tmpdir->child('key.pem')->stringify;

Util->generate_key($keyfile);
Util->generate_certificate($keyfile, $certfile);

my $pk = Crypt::PK::ECC->new($keyfile);
isa_ok $pk, 'Crypt::PK::ECC';

my $cert = Crypt::OpenSSL::X509->new_from_file($certfile);
isa_ok $cert, 'Crypt::OpenSSL::X509';

my $tester = new_ok 'Authen::U2F::Tester', [
    certificate => $cert,
    keypair     => $pk
];

# also test using key_file and cert_file
$tester = new_ok 'Authen::U2F::Tester', [
    cert_file => $certfile,
    key_file  => $keyfile
];

my ($handle, $key);

subtest register => sub {
    my $challenge = Authen::U2F->challenge;
    my $app_id    = 'https://www.example.com';

    my $client_data = {
        typ        => 'navigator.id.finishEnrollment',
        challenge  => $challenge,
        origin     => $app_id,
        cid_pubkey => 'unused'
    };

    my $request = {
        type             => 'u2f_register_request',
        appId            => $app_id,
        registerRequests => [$client_data],
        registeredKeys   => [],
        timeoutSeconds   => 30
    };

    my $res;

    lives_ok { $res = $tester->register($app_id, $challenge) };

    isa_ok $res, 'Authen::U2F::Tester::RegisterResponse';

    cmp_ok $res->error_code, '==', 0, 'register request was successful';

    is_deeply decode_json(decode_base64url($res->client_data)), $client_data;

    lives_ok {
        ($handle, $key) = Authen::U2F->registration_verify(
            challenge         => $challenge,
            app_id            => $app_id,
            origin            => $app_id,
            registration_data => $res->registration_data,
            client_data       => $res->client_data);
    };
};

subtest sign => sub {
    my $challenge = Authen::U2F->challenge;
    my $app_id    = 'https://www.example.com';

    my $res;

    lives_ok { $res = $tester->sign($app_id, $challenge, $handle); };

    isa_ok $res, 'Authen::U2F::Tester::SignResponse';

    cmp_ok $res->error_code, '==', 0, 'sign request was successful';

    lives_ok {
        Authen::U2F->signature_verify(
            challenge      => $challenge,
            app_id         => $app_id,
            origin         => $app_id,
            key_handle     => $handle,
            key            => $key,
            signature_data => $res->signature_data,
            client_data    => $res->client_data);
    };
};

done_testing;