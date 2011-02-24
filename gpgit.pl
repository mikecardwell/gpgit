#!/usr/bin/perl

##############################################################################
#                                                                            #
# Copyright 2011, Mike Cardwell - https://grepular.com/                      #
#                                                                            #
# This program is free software; you can redistribute it and/or modify       #
# it under the terms of the GNU General Public License as published by       #
# the Free Software Foundation; either version 2 of the License, or          #
# any later version.                                                         #
#                                                                            #
# This program is distributed in the hope that it will be useful,            #
# but WITHOUT ANY WARRANTY; without even the implied warranty of             #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              #
# GNU General Public License for more details.                               #
#                                                                            #
# You should have received a copy of the GNU General Public License          #
# along with this program; if not, write to the Free Software                #
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA #
#                                                                            #
##############################################################################

use strict;
use warnings;
use Mail::GnuPG;
use MIME::Parser;

## Parse args
  my @recipients = @ARGV;
  die "Bad arguments. Missing email address\n" unless int(@recipients);
  die "Bad arguments. Invalid email address\n" if grep( !/^.+\@.+$/, @recipients );

## Object for GPG encryption
  my $gpg = new Mail::GnuPG();

## Make sure we have the appropriate public key for all recipients
  foreach( @recipients ){
     unless( $gpg->has_public_key( $_ ) ){
        while(<STDIN>){
           print;
        }
        exit 0;
     }
  }

## Read the plain text email
  my $plain;
  {
     local $/ = undef;
     $plain = <STDIN>;
  }

## Parse the email
  my $mime;
  {
     my $parser = new MIME::Parser();
     $parser->decode_bodies(1);
     $parser->output_to_core(1);
     $mime = $parser->parse_data( $plain );
  }

## Test if it is already encrypted
  if( $gpg->is_encrypted( $mime ) ){
     print $plain; exit 0;
  }

## Encrypt
  {
     $mime->make_singlepart;

     my $code = $mime->mime_type =~ /^text\/plain/
              ? $gpg->ascii_encrypt( $mime, @recipients )
              : $gpg->mime_encrypt(  $mime, @recipients );
     
     if( $code ){
        print $plain;
	exit 0;
     }
  }

## Remove some headers which might have been broken by the process of encryption
  $mime->head()->delete($_) foreach qw( DKIM-Signature DomainKey-Signature );

## Print out the encrypted version
  print $mime->stringify;
