# COPYRIGHT
package Authen::U2F::Tester::Role::Response;

# ABSTRACT: U2F Successful Response Role

use Moose::Role;
use strictures 2;
use Authen::U2F::Tester::Const qw(OK);
use namespace::autoclean;

=method response(): scalar

Get the raw U2F register response.  This is a binary string representing a
successful registration response.  See
L<The FIDO Specification|https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#registration-response-message-success> for the details on the contents of this string.

=cut

has response => (is => 'ro', isa => 'Value', required => 1);

=method error_code(): int

Get the error code

=cut

has error_code => (is => 'ro', isa => 'Int', required => 1);

=method client_data()

Get the client data from the request, in Base64 URL format.

=cut

has client_data => (is => 'ro', isa => 'Str', required => 1);

=method is_success(): bool

Returns true if the response was successful, false otherwise.

=cut

sub is_success {
    my $self = shift;

    return $self->error_code == OK ? 1 : 0;
}

1;

__END__

=head1 SYNOPSIS

 # This is used by successful tester U2F responses

=head1 DESCRIPTION

This is a role used by successful L<Authen::U2F::Tester> responses.  Successful
responses consume this role.

=head1 SEE ALSO

=for :list
* L<Authen::U2F::Tester::RegisterResponse>
* L<Authen::U2F::Tester::SignResponse>
* L<Authen::U2F::Tester>

=cut
