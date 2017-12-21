package My::Test::Util;

use strictures 2;
use Crypt::PK::ECC;
use File::Slurp qw(read_file);

sub generate_key {
    my ($self, $filename) = @_;

    my $pk = Crypt::PK::ECC->new;

    $pk->generate_key('secp256r1');

    open my $fh, '>', $filename;

    print $fh $pk->export_key_pem('private');

    close $fh;
}

sub generate_certificate {
    my ($self, $keyfile, $certfile) = @_;

    my $subject = Crypt::OpenSSL::CA::X509_NAME->new(
        C  => 'US',
        O  => 'test-u2f-manufacturer',
        ST => 'Texas',
        CN => 'virtual-u2f');

    my $issue = Crypt::OpenSSL::CA::X509_NAME->new(
        C  => 'US',
        O  => 'Test Untrustworthy CA Organization',
        ST => 'Texas',
        CN => 'Test Untrustworthy CA');

    my $key = Crypt::OpenSSL::CA::PrivateKey->parse(scalar read_file($keyfile));

    my $pubkey = $key->get_public_key;

    my $x509 = Crypt::OpenSSL::CA::X509->new($pubkey);

    $x509->set_serial('0x1');
    $x509->set_subject_DN($subject);
    $x509->set_issuer_DN($issue);

    my $startyear = (gmtime)[5] + 1900;
    my $endyear   = $startyear + 100;

    my $before = $startyear . '0101000000Z';
    my $after  = $endyear   . '0101000000Z';

    $x509->set_notBefore($before);
    $x509->set_notAfter($after);

    my $pem = $x509->sign($key, 'sha256');

    open my $fh, '>', $certfile;

    print $fh $pem;

    close $fh;
}

1;
