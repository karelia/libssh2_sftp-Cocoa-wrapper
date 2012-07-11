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
    NSParameterAssert(privateKey);
    
    _publicKey = [publicKey copy];
    _privateKey = [privateKey copy];
}

- (NSURLCredential *)ck2_credentialWithPassword:(NSString *)password persistence:(NSURLCredentialPersistence)persistence;
{
    id result = [super ck2_credentialWithPassword:password persistence:persistence];
    [result setPublicKeyURL:[self ck2_publicKeyURL] privateKeyURL:[self ck2_privateKeyURL]];
    return result;
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

- (NSURLCredential *)ck2_credentialWithPassword:(NSString *)password persistence:(NSURLCredentialPersistence)persistence;
{
    return [[[[self class] alloc] initWithUser:[self user]
                                      password:password
                                   persistence:persistence]
            autorelease];
}

@end


#pragma mark -


@implementation NSURLCredentialStorage (CK2SSHCredential)

- (NSURLCredential *)ck2_credentialForPrivateKeyAtURL:(NSURL *)privateKey user:(NSString *)user;
{
    // Try fetching passphrase from the keychain
    // The service & account name is entirely empirical based on what's in my keychain from SSH Agent. Sadly, I seem to be denied access to it though
    NSString *privateKeyPath = [privateKey path];
    NSString *service = [@"SSH: " stringByAppendingString:privateKeyPath];
    
    void *passwordData;
    UInt32 passwordLength;
    OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                     [service lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [service UTF8String],
                                                     [privateKeyPath lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [privateKeyPath UTF8String],
                                                     &passwordLength, &passwordData,
                                                     NULL);
    
    if (status != errSecSuccess) return nil;
    
    NSString *password = [[NSString alloc] initWithBytes:passwordData length:passwordLength encoding:NSUTF8StringEncoding];
    SecKeychainItemFreeContent(NULL, passwordData);
    
    CK2SSHCredential *result = [[CK2SSHCredential alloc] initWithUser:user password:password persistence:NSURLCredentialPersistencePermanent];
    [result setPublicKeyURL:nil privateKeyURL:privateKey];
    [password release];
    
    return [result autorelease];
}

- (BOOL)ck2_setPrivateKeyCredential:(NSURLCredential *)credential;
{
    NSURLCredentialPersistence persistence = [credential persistence];
    if (persistence == NSURLCredentialPersistenceNone) return YES;
    if ([credential persistence] != NSURLCredentialPersistencePermanent) return YES;
    
    NSString *privateKey = [[credential ck2_privateKeyURL] path];
    NSString *password = [credential password];
    
    if (privateKey && password)
    {
        // Time to store the passphrase. I'm making up a service name to match what SSH Agent does on my machine
        NSString *service = [@"SSH: " stringByAppendingString:privateKey];
        
        OSStatus status = SecKeychainAddGenericPassword(NULL,
                                                        [service lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [service UTF8String],
                                                        [privateKey lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [privateKey UTF8String],
                                                        [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [password UTF8String],
                                                        NULL);
        
        return status == errSecSuccess;
    }
    
    return NO;
}
    
@end
