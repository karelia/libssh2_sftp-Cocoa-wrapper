//
//  CK2SSHCredential.h
//  Sandvox
//
//  Created by Mike on 02/09/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface NSURLCredential (CK2SSHCredential)

// Indicates that authentication should be public key, with the help of ssh-agent
+ (NSURLCredential *)ck2_SSHAgentCredentialWithUser:(NSString *)user;

// Authenticate using particular public & private key files
+ (NSURLCredential *)ck2_credentialWithUser:(NSString *)user
                               publicKeyURL:(NSURL *)publicKey
                              privateKeyURL:(NSURL *)privateKey;

+ (NSURLCredential *)ck2_credentialWithUser:(NSString *)user service:(NSString *)service;

- (BOOL)ck2_isPublicKeyCredential;

// These will be nil when using ssh-agent
- (NSURL *)ck2_publicKeyURL;
- (NSURL *)ck2_privateKeyURL;

@end
