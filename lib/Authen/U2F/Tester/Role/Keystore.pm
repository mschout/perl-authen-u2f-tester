# COPYRIGHT
package Authen::U2F::Tester::Role::Keystore;

# ABSTRACT: U2F Tester Keystore Role.

use Moose::Role;

=method exists($handle): bool

Check if the given handle (in Base64 URL format) exists (or is valid) in the key store.

=method get($handle): Crypt::PK::ECC

Given the key handle (in Base64 URL format), return the private key (as a
L<Crypt::PK::ECC> object) associated with it in the key store.

=method put($private_key): scalar

Save the given keypair in the keystore, returning a unique key handle that
uniquely identifies the keypair.  The returned handle should B<NOT> be Base64
URL encoded.  C<$private_key> is a raw private key string.

=cut

requires qw(exists put get);

1;

__END__

=head1 SYNOPSIS

 package Authen::U2F::Tester::Keystore::Example;

 use Moose;
 use namespace::autoclean;

 with 'Authen::U2F::Tester::Role::Keystore';

 sub exists {
     my ($self, $handle) = @_;
     ...
     # if handle is valid and exists in the keystore:
     return 1;

     # else
     return 0;
 }

 sub put {
     my ($self, $private_key) = @_;

     # somehow generate a unique handle
     return $handle;
 }

 sub get {
     my ($self, $handle) = @_;

     $handle = decode_base64url($handle);

     # fetch the Crypt::PK::ECC private key object associated with this handle.
     return $pkec;
 }

 __PACKAGE__->meta->make_immutable;

=head1 DESCRIPTION

This is a L<Moose::Role> that L<Authen::U2F::Tester> keystore's must consume.
All required methods must be implemented by the consuming L<Moose> class.

