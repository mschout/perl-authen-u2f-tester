package My::Test::Util;

use strictures 2;
use Crypt::PK::ECC;
use File::Slurp qw(read_file);
use IPC::System::Simple qw(system);

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

    my $tmpdir = Path::Tiny->tempdir;

    my $subject = '/C=US/O=Untrusted U2F Organization/ST=Texas/CN=virtual-u2f';

    system qw(openssl req -x509 -days 365 -sha256),
        '-subj', $subject,
        '-key', $keyfile,
        '-out', $certfile;
}

1;
