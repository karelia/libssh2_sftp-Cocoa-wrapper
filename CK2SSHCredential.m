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
}

@end



@implementation CK2SSHCredential

- (void)dealloc
{
    [_publicKey release];
    [_privateKey release];
    
    [super dealloc];
}

- (BOOL)ck2_isPublicKeyCredential; { return YES; }

- (NSURL *)ck2_publicKeyURL; { return _publicKey; }
- (NSURL *)ck2_privateKeyURL; { return _privateKey; }

- (void)setPublicKeyURL:(NSURL *)publicKey privateKeyURL:(NSURL *)privateKey;
{
    NSParameterAssert(publicKey);
    NSParameterAssert(privateKey);
    
    _publicKey = [publicKey copy];
    _privateKey = [privateKey copy];
}

@end


#pragma mark -


@interface CK2GenericPasswordCredential : NSURLCredential
{
  @private
    NSString *_service;
}

- (id)initWithUser:(NSString *)user service:(NSString *)service;

@end


@implementation CK2GenericPasswordCredential

- (id)initWithUser:(NSString *)user service:(NSString *)service;
{
    if (self = [self initWithUser:user password:nil persistence:NSURLCredentialPersistencePermanent])
    {
        _service = [service copy];
    }
    
    return self;
}

- (void)dealloc
{
    [_service release];
    [super dealloc];
}

- (NSString *)password
{
    const char *serviceName = [_service UTF8String];
	const char *username = [[self user] UTF8String];
	
    UInt32 passwordLength = 0;
	void *password = nil;
	
    OSStatus status = SecKeychainFindGenericPassword(NULL, strlen(serviceName), serviceName, strlen(username), username, &passwordLength, &password, NULL);
    
    if (status != noErr) return nil;
    
    NSString *result = [[NSString alloc] initWithBytes:password length:passwordLength encoding:NSUTF8StringEncoding];
    
    SecKeychainItemFreeContent(NULL, password);
    
    return [result autorelease];
}

- (BOOL)hasPassword { return YES; }

@end



#pragma mark -


@implementation NSURLCredential (CK2SSHCredential)

+ (NSURLCredential *)ck2_SSHAgentCredentialWithUser:(NSString *)user;
{
    CK2SSHCredential *result = [[CK2SSHCredential alloc] initWithUser:user
                                                             password:nil
                                                          persistence:NSURLCredentialPersistenceNone];
    return [result autorelease];
}

+ (NSURLCredential *)ck2_credentialWithUser:(NSString *)user
                               publicKeyURL:(NSURL *)publicKey
                              privateKeyURL:(NSURL *)privateKey;
{
    NSParameterAssert(publicKey);
    NSParameterAssert(privateKey);
    
    CK2SSHCredential *result = [[CK2SSHCredential alloc] initWithUser:user
                                                             password:nil
                                                          persistence:NSURLCredentialPersistenceNone];
    
    [result setPublicKeyURL:publicKey privateKeyURL:privateKey];
    
    return [result autorelease];
}

+ (NSURLCredential *)ck2_credentialWithUser:(NSString *)user service:(NSString *)service;
{
    const char *serviceName = [service UTF8String];
	const char *username = [user UTF8String];
	
    OSStatus status = SecKeychainFindGenericPassword(NULL, strlen(serviceName), serviceName, strlen(username), username, NULL, NULL, NULL);
    
    if (status != noErr) return nil;
    
    return [[[CK2GenericPasswordCredential alloc] initWithUser:user service:service] autorelease];
}

- (BOOL)ck2_isPublicKeyCredential; { return NO; }
- (NSURL *)ck2_publicKeyURL; { return nil; }
- (NSURL *)ck2_privateKeyURL; { return nil; }

@end
