//
//  CK2SSHCredential.m
//  Sandvox
//
//  Created by Mike on 02/09/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import "CK2SSHCredential.h"


@interface CK2SSHCredential : NSURLCredential
{
  @private
    NSURL           *_publicKey;
    NSURL           *_privateKey;
    NSURLCredential *_passphrase;
}

@property(nonatomic, copy, setter=setPassphraseCredential:) NSURLCredential *ck2_passphraseCredential;

@end



@implementation CK2SSHCredential

- (void)dealloc
{
    [_publicKey release];
    [_privateKey release];
    [_passphrase release];
    
    [super dealloc];
}

- (BOOL)ck2_isPublicKeyCredential; { return YES; }

- (void)setPublicKeyURL:(NSURL *)publicKey privateKeyURL:(NSURL *)privateKey;
{
    NSParameterAssert(publicKey);
    NSParameterAssert(privateKey);
    
    _publicKey = [publicKey copy];
    _privateKey = [privateKey copy];
}

@synthesize ck2_passphraseCredential = _passphrase;

@end


#pragma mark -


@implementation NSURLCredential (CK2SSHCredential)

+ (NSURLCredential *)ck2_credentialWithUser:(NSString *)user
                               publicKeyURL:(NSURL *)publicKey
                              privateKeyURL:(NSURL *)privateKey
                       passphraseCredential:(NSURLCredential *)passphrase;
{
    CK2SSHCredential *result = [[CK2SSHCredential alloc] initWithUser:user
                                                             password:nil
                                                          persistence:NSURLCredentialPersistenceNone];
    
    if (publicKey || privateKey)
    {
        [result setPublicKeyURL:publicKey privateKeyURL:privateKey];
    }
    
    [result setPassphraseCredential:passphrase];
    
    return [result autorelease];
}

- (BOOL)ck2_isPublicKeyCredential; { return NO; }
- (NSURLCredential *)ck2_passphraseCredential; { return NO; }
- (NSURL *)ck2_publicKeyURL; { return nil; }
- (NSURL *)ck2_privateKeyURL; { return nil; }

@end
