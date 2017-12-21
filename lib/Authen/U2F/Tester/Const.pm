# COPYRIGHT
package Authen::U2F::Tester::Const;

# ABSTRACT: Constants for Authen::U2F::Tester

use base 'Exporter';
use strictures 2;

my %constants;

BEGIN {
    %constants = (
        OK                        => 0,
        OTHER_ERROR               => 1,
        BAD_REQUEST               => 2,
        CONFIGURATION_UNSUPPORTED => 3,
        DEVICE_INELIGIBLE         => 4,
        TIMEOUT                   => 5);
}

use constant \%constants;

our @EXPORT_OK = keys %constants;

our %EXPORT_TAGS = (
    all => \@EXPORT_OK
);

=attr OK

This error code indicates a successful response.

=attr OTHER_ERROR

This error indicates some other error happened.

=attr BAD_REQUEST

This error code indicates the request cannot be processed.

=attr CONFIGURATION_UNSUPPORTED

This error code indicates the client configuration is not supported.

=attr DEVICE_INELIGIBLE

This error code indicates that the device is not eligible for this request.
For a registration request, this may mean the device has already been
registered.  For a signing request, this may mean the device was never
registered.

=attr TIMEOUT

This error code indicates a timeout occurred waiting for the request to be
satisfied.

=cut

1;

__END__

=head1 SYNOPSIS

 # import constants explicitly by name
 use Authen::U2F::Tester::Const qw(OK DEVICE_INELIGIBLE);

 # import all constants
 use Authen::U2F::Tester::Const ':all';

 # example of a sign() request where the device has not been registered
 my $r = $tester->sign(...);

 if ($r->error_code == DEVICE_INELIGIBLE) {
    die "this device has not been registered";
 }

=head1 DESCRIPTION

This module provides error constants that are used by L<Authen::U2F::Tester>.

