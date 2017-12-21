# COPYRIGHT
package Authen::U2F::Tester::SignResponse;

# ABSTRACT: U2F Tester Sign Response

use Moose;
use MIME::Base64 qw(encode_base64url);
use namespace::autoclean;

with qw(Authen::U2F::Tester::Role::Response);

=method key_handle(): string

Get the key handle, in Base64 URL format.

=cut

has key_handle => (is => 'ro', isa => 'Str', required => 1);

=method signature_data(): string

Get the signature data from the response, in Base64 URL encoded format.

=cut

sub signature_data {
    encode_base64url(shift->response);
}

__PACKAGE__->meta->make_immutable;

__END__

=head1 SYNOPSIS

 my $res = $tester->sign($app_id, $challenge, @keyhandles);

 print $res->client_data;
 print $res->key_handle;

 print unpack 'H*', $res->response;

=head1 DESCRIPTION

This class is a signing response from a U2F signing request.

=head1 SEE ALSO

=for :list
* L<Authen::U2F::Tester::Role::Response>
* L<Authen::U2F::Tester>

