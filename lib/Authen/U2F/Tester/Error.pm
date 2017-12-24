# COPYRIGHT
package Authen::U2F::Tester::Error;

# ABSTRACT: Authen::U2F::Tester Error Response

use Moose;
use MooseX::AttributeShortcuts;
use MooseX::SingleArg;

use Authen::U2F::Tester::Const ':all';
use namespace::autoclean;

=method new(int)

Single arg constructor.  Argument is a U2F error code.  See
L<Authen::U2F::Tester::Const> for constants that should be used for this.

=method error_code(): int

Get the error code

=cut

has error_code => (is => 'ro', isa => 'Int', required => 1);

=method error_message(): string

Get the error message

=cut

has error_message => (is => 'lazy', isa => 'Str');

single_arg 'error_code';

=method is_success(): bool

Returns false as this object is only returned for errors.

=cut

sub is_success { 0 }

sub _build_error_message {
    my $self = shift;

    my %errors = (
        OTHER_ERROR               => 'Other Error',
        BAD_REQUEST               => 'Bad Request',
        CONFIGURATION_UNSUPPORTED => 'Configuration Unsupported',
        DEVICE_INELIGIBLE         => 'Device Ineligible',
        TIMEOUT                   => 'Timeout');
}

__PACKAGE__->meta->make_immutable;

__END__

=head1 SYNOPSIS

 $r = $tester->register(...);

 # or

 $r = $tester->sign(...);

 unless ($r->is_success) {
     print $r->error_code;
     print $r->error_message;
 }

=head1 DESCRIPTION

This object is returned from L<Authen::U2F::Tester> sign or register requests
if the request resulted in an error.

=head1 SEE ALSO

=for :list
* L<Authen::U2F::Tester>

=cut
