//
//  CK2SSHCredential.h
//  Sandvox
//
//  Created by Mike on 02/09/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface NSURLCredential (CK2SSHCredential)

// Public and private key may be nil to indicate that standard keys should be used
+ (NSURLCredential *)ck2_credentialWithUser:(NSString *)user
                               publicKeyURL:(NSURL *)publicKey
                              privateKeyURL:(NSURL *)privateKey;

+ (NSURLCredential *)ck2_credentialWithUser:(NSString *)user service:(NSString *)service;

- (BOOL)ck2_isPublicKeyCredential;

- (NSURL *)ck2_publicKeyURL;
- (NSURL *)ck2_privateKeyURL;

@end
