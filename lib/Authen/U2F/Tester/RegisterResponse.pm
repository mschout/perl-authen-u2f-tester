# COPYRIGHT
package Authen::U2F::Tester::RegisterResponse;

# ABSTRACT: U2F Tester Registration Response

use Moose;
use strictures 2;
use MIME::Base64 qw(encode_base64url);
use namespace::autoclean;

with qw(Authen::U2F::Tester::Role::Response);

=method registration_data(): string

Get the registration data from the tester's register request, in
Base64 URL encoding.

=cut

sub registration_data {
    return encode_base64url(shift->response);
}

__PACKAGE__->meta->make_immutable;

__END__

=head1 SYNOPSIS

 use Authen::U2F::Tester;

 my $tester = Authen::U2F::Tester->new(...);

 my $res = $tester->register(...);

 print $res->client_data;
 print $res->registration_data;

 # print the binary response in hex format
 print unpack 'H*', $res->response;

=head1 DESCRIPTION

This class represents a successful response to a registration request.

=head1 SEE ALSO

=for :list
* L<Authen::U2F::Tester::Role::Response>
* L<Authen::U2F::Tester>

