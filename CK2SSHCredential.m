//
//  CK2SSHCredential.m
//  Sandvox
//
//  Created by Mike Abdullah on 02/09/2011.
//  Copyright © 2011 Karelia Software
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

#import "CK2SSHCredential.h"

#import <objc/runtime.h>


@interface CK2SSHCredential : NSURLCredential
{
  @private
    SecKeychainItemRef  _keychainItem;
    CFStringRef         _password;
    
    BOOL    _isPublicKey;
    NSURL   *_publicKey;
    NSURL   *_privateKey;
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

- (id)initWithUser:(NSString *)user;
{
    if (self = [self initWithUser:user password:nil persistence:NSURLCredentialPersistenceNone])
    {
        _isPublicKey = YES;
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
            if (status != errSecSuccess)
            {
                // HACK: let it be known there was a problem
                // make sure runs on main thread
                NSString *opFormat = NSLocalizedStringFromTableInBundle(@"The password for user %@ couldn't be retrieved.",
                                                                        nil,
                                                                        [NSBundle bundleForClass:[CK2SSHCredential class]],
                                                                        "error description");
                
                NSError *error = [NSURLCredential ck2_keychainErrorWithCode:status
                                              localizedOperationDescription:[NSString stringWithFormat:opFormat, [self user]]];
                
                [[NSClassFromString(@"NSApplication") sharedApplication] performSelectorOnMainThread:@selector(presentError:) withObject:error waitUntilDone:NO];
                
                return nil;
            }
        
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

- (BOOL)ck2_isPublicKeyCredential; { return _isPublicKey; }

- (NSURL *)ck2_publicKeyURL; { return _publicKey; }
- (NSURL *)ck2_privateKeyURL; { return _privateKey; }

- (void)setPublicKeyURL:(NSURL *)publicKey privateKeyURL:(NSURL *)privateKey;
{
    NSParameterAssert(privateKey);
    
    _publicKey = [publicKey copy];
    _privateKey = [privateKey copy];
    _isPublicKey = YES;
}

- (NSURLCredential *)ck2_credentialWithPassword:(NSString *)password persistence:(NSURLCredentialPersistence)persistence;
{
    id result = [super ck2_credentialWithPassword:password persistence:persistence];
    if ([self ck2_isPublicKeyCredential]) [result setPublicKeyURL:[self ck2_publicKeyURL] privateKeyURL:[self ck2_privateKeyURL]];
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
	
    OSStatus status = SecKeychainFindGenericPassword(NULL, (UInt32) strlen(serviceName), serviceName, (UInt32) strlen(username), username, &passwordLength, &password, NULL);
    
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
    return [[[CK2SSHCredential alloc] initWithUser:user] autorelease];
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
	
    OSStatus status = SecKeychainFindGenericPassword(NULL, (UInt32) strlen(serviceName), serviceName, (UInt32) strlen(username), username, NULL, NULL, NULL);
    
    if (status != noErr) return nil;
    
    return [[[CK2GenericPasswordCredential alloc] initWithUser:user service:service] autorelease];
}

+ (NSURLCredential *)ck2_credentialWithKeychainItem:(SecKeychainItemRef)item;
{
    // Retrieve username from keychain item
    CFTypeRef attributes;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)@{
                                          (NSString *)kSecClass : (NSString *)kSecClassInternetPassword,
                                          (NSString *)kSecMatchItemList : @[(id)item],
                                          (NSString *)kSecReturnAttributes : @YES
                                          }, &attributes);
    
    if (status != errSecSuccess) return nil;
    
    NSURLCredential *result = [[CK2SSHCredential alloc] initWithUser:CFDictionaryGetValue(attributes, kSecAttrAccount) keychainItem:item];
    CFRelease(attributes);
    return [result autorelease];
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

+ (NSError *)ck2_keychainErrorWithCode:(OSStatus)code localizedOperationDescription:(NSString *)opDescription;
{
    CFStringRef message = SecCopyErrorMessageString(code, NULL);
    
    NSMutableDictionary *userInfo = [[NSMutableDictionary alloc] initWithCapacity:2];
    if (message) [userInfo setObject:(NSString *)message forKey:NSLocalizedFailureReasonErrorKey];
    if (opDescription) [userInfo setObject:[opDescription stringByAppendingFormat:@" %@", message] forKey:NSLocalizedDescriptionKey];
    
    // com.apple.Keychain was my logical guess at domain, and searching the internet reveals Apple are using it in a few places
    NSError *result = [NSError errorWithDomain:@"com.apple.Keychain" code:code userInfo:userInfo];
    
    [userInfo release];
    if (message) CFRelease(message);
    
    return result;
}

@end


#pragma mark -


@implementation NSURLCredentialStorage (CK2SSHCredential)

- (SecKeychainItemRef)copyKeychainItemForPrivateKeyPath:(NSString *)privateKey;
{
    NSString *service = @"SSH";
    
    SecKeychainItemRef result;
    OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                     (UInt32) [service lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [service UTF8String],
                                                     (UInt32) [privateKey lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [privateKey UTF8String],
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
                                                            (UInt32) [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [password UTF8String]);
            
            CFRelease(item);
        }
        else
        {
            status = SecKeychainAddGenericPassword(NULL,
                                                   (UInt32) [service lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [service UTF8String],
                                                   (UInt32) [privateKey lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [privateKey UTF8String],
                                                   (UInt32) [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [password UTF8String],
                                                   NULL);
        }
        
        return status == errSecSuccess;
    }
    
    return NO;
}
    
@end


#pragma mark -


@implementation CK2SSHProtectionSpace

+ (void)initialize;
{
    // Stick in our custom SSH credential storage methods ahead of the regular ones
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        Class class = NSURLCredentialStorage.sharedCredentialStorage.class;
        Method originalMethod;
        Method overrideMethod;
        
        originalMethod = class_getInstanceMethod(class, @selector(setCredential:forProtectionSpace:));
        overrideMethod = class_getInstanceMethod(class, @selector(ck2_SSH_setCredential:forProtectionSpace:));
        method_exchangeImplementations(originalMethod, overrideMethod);
        
        originalMethod = class_getInstanceMethod(class, @selector(setDefaultCredential:forProtectionSpace:));
        overrideMethod = class_getInstanceMethod(class, @selector(ck2_SSH_setDefaultCredential:forProtectionSpace:));
        method_exchangeImplementations(originalMethod, overrideMethod);
        
        originalMethod = class_getInstanceMethod(class, @selector(defaultCredentialForProtectionSpace:));
        overrideMethod = class_getInstanceMethod(class, @selector(ck2_SSH_defaultCredentialForProtectionSpace:));
        method_exchangeImplementations(originalMethod, overrideMethod);
        
        originalMethod = class_getInstanceMethod(class, @selector(credentialsForProtectionSpace:));
        overrideMethod = class_getInstanceMethod(class, @selector(ck2_SSH_credentialsForProtectionSpace:));
        method_exchangeImplementations(originalMethod, overrideMethod);
    });
}

- (NSString *)protocol { return @"ssh"; }
- (BOOL)receivesCredentialSecurely; { return YES; }

/*	NSURLProtectionSpace is immutable. It probably implements -copyWithZone: in the exact same way we do, but have no guarantee, so re-implement here.
 */
- (id)copyWithZone:(NSZone *)zone { return [self retain]; }

@end


#pragma mark -


@implementation NSURLCredentialStorage (CK2SSHCredentialStorage)

#pragma mark Swizzled methods

- (NSURLCredential *)ck2_SSH_defaultCredentialForProtectionSpace:(NSURLProtectionSpace *)space;
{
    if ([space.protocol isEqualToString:@"ssh"])
    {
        SecKeychainItemRef item = [self ck2_copyKeychainItemForSSHHost:space.host port:space.port user:nil];
        // TODO: Actually search for a "default" item, rather than any old one
        if (!item) return nil;
        
        return [NSURLCredential ck2_credentialWithKeychainItem:item];
    }
    else
    {
        return [self ck2_SSH_defaultCredentialForProtectionSpace:space];  // calls through to pre-swizzling version
    }
}

- (NSDictionary *)ck2_SSH_credentialsForProtectionSpace:(NSURLProtectionSpace *)space {
    if ([space.protocol isEqualToString:@"ssh"])
    {
        SecKeychainItemRef item = [self ck2_copyKeychainItemForSSHHost:space.host port:space.port user:nil];
        // TODO: Actually search for a "default" item, rather than any old one
        if (!item) return nil;
        
        NSURLCredential *credential = [NSURLCredential ck2_credentialWithKeychainItem:item];
        return [NSDictionary dictionaryWithObject:credential forKey:credential.user];
    }
    else
    {
        return [self ck2_SSH_credentialsForProtectionSpace:space];  // calls through to pre-swizzling version
    }
}

- (void)ck2_SSH_setDefaultCredential:(NSURLCredential *)credential forProtectionSpace:(NSURLProtectionSpace *)protectionSpace
{
    if ([protectionSpace.protocol isEqualToString:@"ssh"])
    {
        // TODO: Actually record it as the default in some fashion
        [self ck2_setCredential:credential forSSHHost:protectionSpace.host port:protectionSpace.port error:NULL];
    }
    else
    {
        [self ck2_SSH_setDefaultCredential:credential forProtectionSpace:protectionSpace];  // calls through to pre-swizzling version
    }
}

- (void)ck2_SSH_setCredential:(NSURLCredential *)credential forProtectionSpace:(NSURLProtectionSpace *)protectionSpace
{
    if ([protectionSpace.protocol isEqualToString:@"ssh"])
    {
        [self ck2_setCredential:credential forSSHHost:protectionSpace.host port:protectionSpace.port error:NULL];
    }
    else
    {
        [self ck2_SSH_setCredential:credential forProtectionSpace:protectionSpace];  // calls through to pre-swizzling version
    }
}

#pragma mark SSH handling

- (BOOL)ck2_setCredential:(NSURLCredential *)credential forSSHHost:(NSString *)host port:(NSInteger)port error:(NSError **)error;
{
    // Can't do anything with non-persistent credentials
    if ([credential persistence] != NSURLCredentialPersistencePermanent) return YES;
    
    
    // Hand off private key passphrase storage elsewhere
    if (credential.ck2_isPublicKeyCredential)
    {
        if (credential.ck2_privateKeyURL) [self ck2_setPrivateKeyCredential:credential];
        return YES;
    }
    
    
    // Retrieve the keychain item
    NSString *user = [credential user];
    SecKeychainItemRef keychainItem = [self ck2_copyKeychainItemForSSHHost:host port:port user:user];
    
    
    // Store the password
    NSString *password = [credential password];
    NSAssert(password, @"%@ was handed password-less credential", NSStringFromSelector(_cmd));
    
    OSStatus status;
    NSString *opDescription;
    if (keychainItem)
    {
        status = SecKeychainItemModifyAttributesAndData(keychainItem,
                                                        NULL, // no change to attributes
                                                        (UInt32) [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [password UTF8String]);
        
        opDescription = NSLocalizedStringFromTableInBundle(@"The password stored in your keychain couldn't be updated.", nil, [NSBundle bundleForClass:CK2SSHProtectionSpace.class], "error description");
        
        CFRelease(keychainItem);    // know for sure keychainItem isn't nil as this line hasn't been reported to crash so far!
    }
    else
    {
        status = SecKeychainAddInternetPassword(NULL,
                                                (UInt32) [host lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [host UTF8String],
                                                0, NULL,
                                                (UInt32) [user lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [user UTF8String],
                                                0, NULL,
                                                port,
                                                kSecProtocolTypeSSH,
                                                kSecAuthenticationTypeDefault,
                                                (UInt32) [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [password UTF8String],
                                                NULL);
        
        opDescription = NSLocalizedStringFromTableInBundle(@"The password couldn't be added to your keychain.", nil, [NSBundle bundleForClass:CK2SSHProtectionSpace.class], "error description");
    }
    
    if (status == errSecSuccess) return YES;
    
    
    // Note the host etc. involved
    opDescription = [opDescription stringByAppendingFormat:
                     NSLocalizedStringFromTableInBundle(@" (%@@%@:%i).",
                                                        nil,
                                                        [NSBundle bundleForClass:CK2SSHProtectionSpace.class],
                                                        "error description"),
                     [credential user],
                     host,
                     (int)port];
    
    // Note a crazily empty password
    if (![password length]) opDescription = [opDescription stringByAppendingFormat:
                                             NSLocalizedStringFromTableInBundle(@" (%@ password.)",
                                                                                nil,
                                                                                [NSBundle bundleForClass:CK2SSHProtectionSpace.class],
                                                                                "error description"),
                                             password   /* don't worry, it's either nil or empty! */];
    
    if (error) *error = [NSURLCredential ck2_keychainErrorWithCode:status localizedOperationDescription:opDescription];
    return NO;
}

- (SecKeychainItemRef)ck2_copyKeychainItemForSSHHost:(NSString *)host port:(NSInteger)port user:(NSString *)user;
{
    SecKeychainItemRef result;
    OSStatus status = SecKeychainFindInternetPassword(NULL,
                                                      (UInt32) [host lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [host UTF8String],
                                                      0, NULL,
                                                      (UInt32) [user lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [user UTF8String],
                                                      0, NULL,
                                                      port,
                                                      kSecProtocolTypeSSH,
                                                      kSecAuthenticationTypeDefault,
                                                      NULL, NULL,
                                                      &result);
    
    return (status == errSecSuccess ? result : NULL);
}

@end
