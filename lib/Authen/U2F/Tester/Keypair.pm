# COPYRIGHT
package Authen::U2F::Tester::Keypair;

# ABSTRACT: Authen::U2F::Tester Keypair Object

use Moose;
use MooseX::AttributeShortcuts;
use MooseX::SingleArg;

use strictures 2;
use Crypt::PK::ECC;
use UUID::Tiny;
use namespace::autoclean;

=method keypair(): Crypt::PK::ECC

Gets the keypair for this object.  If a keypair was not passed to the
constructor, a new key will be generated.

=cut

has keypair => (is => 'lazy', isa => 'Crypt::PK::ECC');

=method handle(): string

Get the handle for this keyapair.  Handles are randomly generated strings
that uniquely identify the keypair.

=cut

has handle => (is => 'lazy', isa => 'Str');

=method public_key(): scalar

Get the public key (in C<DER> format) for this keypair.

=cut

=method private_key(): scalar

Get the private key (in C<DER> format) for this keypair.

=cut

has [qw(public_key private_key)] => (is => 'lazy', isa => 'Value');

=method new()

=method new($keypair)

Construct a new keypair object.  A L<Crypt::PK::ECC> object can be passed to
the constructor.  Otherwise a new keypair will be generated on demand.

=cut

single_arg 'keypair';

sub _build_keypair {
    my $pk = Crypt::PK::ECC->new;

    $pk->generate_key('nistp256');

    return $pk;
}

sub _build_public_key {
    shift->keypair->export_key_raw('public');
}

sub _build_private_key {
    shift->keypair->export_key_raw('private');
}

sub _build_handle {
    UUID::Tiny::create_uuid(UUID::Tiny::UUID_RANDOM);
}

__PACKAGE__->meta->make_immutable;

__END__

=head1 SYNOPSIS

 my $keypair = Authen::U2F::Tester::Keypair->new;

 # private key in DER format
 my $private_key = $keypair->private_key;

 # public key in DER format
 my $public_key = $keypair->public_key;

 print $keypair->handle;

=head1 DESCRIPTION

This module manages L<Crypt::PK::ECC> keypairs for L<Authen::U2F::Tester>.

=cut
