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
    SecKeychainItemRef  _keychainItem;
    CFStringRef         _password;
    
    NSURL           *_publicKey;
    NSURL           *_privateKey;
}

@end



@implementation CK2SSHCredential

- (id)initWithUser:(NSString *)user keychainItem:(SecKeychainItemRef)item;
{
    NSParameterAssert(item);
    
    if (self = [self initWithUser:user password:nil persistence:NSURLCredentialPersistencePermanent])
    {
        _keychainItem = item;
        CFRetain(_keychainItem);
    }
    
    return self;
}

- (void)dealloc
{
    if (_keychainItem) CFRelease(_keychainItem);
    if (_password) CFRelease(_password);
    [_publicKey release];
    [_privateKey release];
    
    [super dealloc];
}

void freeKeychainContent(void *ptr, void *info)
{
    SecKeychainItemFreeContent(NULL, ptr);
}

- (NSString *)password
{
    if (!_keychainItem) return [super password];
    
    @synchronized((id)_keychainItem)
    {
        if (!_password)
        {
            void *passwordData;
            UInt32 passwordLength;
            OSStatus status = SecKeychainItemCopyContent(_keychainItem, NULL, NULL, &passwordLength, &passwordData);
            if (status != errSecSuccess) return nil;
        
            // Password data must be freed using special keychain APIs. Do so with a specially crafted CFString
            CFAllocatorContext context = { 0, NULL, NULL, NULL, NULL, NULL, NULL, freeKeychainContent, NULL };
            CFAllocatorRef allocator = CFAllocatorCreate(NULL, &context);
            _password = CFStringCreateWithBytesNoCopy(NULL, passwordData, passwordLength, kCFStringEncodingUTF8, false, allocator);
            CFRelease(allocator);
        }
    }
    
    return (NSString *)_password;
}

- (BOOL)hasPassword;
{
    // Super's implementation says there's no password if initted with nil, so we have correct it
    return (_keychainItem != nil || [super hasPassword]);
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

+ (NSURLCredential *)ck2_credentialWithUser:(NSString *)user keychainItem:(SecKeychainItemRef)item;
{
    return [[[CK2SSHCredential alloc] initWithUser:user keychainItem:item] autorelease];
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

- (NSError *)keychainErrorWithCode:(OSStatus)code;
{
    CFStringRef message = SecCopyErrorMessageString(code, NULL);
    
    // com.apple.Keychain was my logical guess at domain, and searching the internet reveals Apple are using it in a few places
    NSError *result = [NSError errorWithDomain:@"com.apple.Keychain"
                                          code:code
                                      userInfo:[NSDictionary dictionaryWithObjectsAndKeys:(NSString *)message, NSLocalizedDescriptionKey, nil]];
    
    if (message) CFRelease(message);
    return result;
}

- (BOOL)ck2_setCredential:(NSURLCredential *)credential forSSHHost:(NSString *)host port:(NSInteger)port error:(NSError **)error;
{
    // Can't do anything with non-persistent credentials
    if ([credential persistence] != NSURLCredentialPersistencePermanent) return YES;
    
    
    // Retrieve the keychain item
    NSString *user = [credential user];
    
    SecKeychainItemRef keychainItem;
    OSStatus status = SecKeychainFindInternetPassword(NULL,
                                                      [host lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [host UTF8String],
                                                      0, NULL,
                                                      [user lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [user UTF8String],
                                                      0, NULL,
                                                      port,
                                                      kSecProtocolTypeSSH,
                                                      kSecAuthenticationTypeDefault,
                                                      NULL, NULL,
                                                      &keychainItem);
    
    
    // Store the password
    NSString *password = [credential password];
    NSAssert(password, @"%@ was handed password-less credential", NSStringFromSelector(_cmd));
    
    if (status == errSecSuccess)
    {
        status = SecKeychainItemModifyAttributesAndData(keychainItem,
                                                        NULL, // no change to attributes
                                                        [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [password UTF8String]);
        
        CFRelease(keychainItem);
    }
    else
    {
        status = SecKeychainAddInternetPassword(NULL,
                                                [host lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [host UTF8String],
                                                0, NULL,
                                                [user lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [user UTF8String],
                                                0, NULL,
                                                port,
                                                kSecProtocolTypeSSH,
                                                kSecAuthenticationTypeDefault,
                                                [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [password UTF8String],
                                                NULL);
    }
    
    if (status == errSecSuccess) return YES;
    
    if (error) *error = [self keychainErrorWithCode:status];
    return NO;
}

- (SecKeychainItemRef)copyKeychainItemForPrivateKeyPath:(NSString *)privateKey;
{
    NSString *service = @"SSH";
    
    SecKeychainItemRef result;
    OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                     [service lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [service UTF8String],
                                                     [privateKey lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [privateKey UTF8String],
                                                     NULL, NULL,
                                                     &result);
    
    return (status == errSecSuccess ? result : NULL);
}

- (NSURLCredential *)ck2_credentialForPrivateKeyAtURL:(NSURL *)privateKey user:(NSString *)user;
{
    // Try fetching passphrase from the keychain
    // The service & account name is entirely empirical based on what's in my keychain from SSH Agent
    NSString *privateKeyPath = [privateKey path];
    
    SecKeychainItemRef item = [self copyKeychainItemForPrivateKeyPath:privateKeyPath];
    if (!item) return nil;
    
    CK2SSHCredential *result = [[CK2SSHCredential alloc] initWithUser:user keychainItem:item];
    [result setPublicKeyURL:nil privateKeyURL:privateKey];
    CFRelease(item);
    
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
        // Time to store the passphrase
        NSString *service = @"SSH";
        
        SecKeychainItemRef item = [self copyKeychainItemForPrivateKeyPath:privateKey];
        
        OSStatus status;
        if (item)
        {
            status = SecKeychainItemModifyAttributesAndData(item,
                                                            NULL, // no change to attributes
                                                            [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [password UTF8String]);
            
            CFRelease(item);
        }
        else
        {
            status = SecKeychainAddGenericPassword(NULL,
                                                   [service lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [service UTF8String],
                                                   [privateKey lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [privateKey UTF8String],
                                                   [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [password UTF8String],
                                                   NULL);
        }
        
        return status == errSecSuccess;
    }
    
    return NO;
}
    
@end
