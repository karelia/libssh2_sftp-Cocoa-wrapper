//
//  CK2SSHCredential.m
//  Sandvox
//
//  Created by Mike on 02/09/2011.
//  iOS support provided by Nicola Peduzzi
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import "CK2SSHCredential.h"


@interface CK2SSHCredential : NSURLCredential
{
  @private
#if TARGET_OS_IPHONE
    NSDictionary *_keychainQuery;
#else
    SecKeychainItemRef  _keychainItem;
#endif
    
    CFStringRef _password;
  
    BOOL    _isPublicKey;
    NSURL   *_publicKey;
    NSURL   *_privateKey;
}

@end



@implementation CK2SSHCredential

#if TARGET_OS_IPHONE
- (id)initWithUser:(NSString *)user keychainQuery:(NSDictionary *)keychainQuery {
  self = [self initWithUser:user password:nil persistence:NSURLCredentialPersistencePermanent];
  if (!self) {
    return nil;
  }
  _keychainQuery = keychainQuery;
  return self;
}
#else
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
#endif

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
#if TARGET_OS_IPHONE
    [_keychainQuery release];
#else
    if (_keychainItem) CFRelease(_keychainItem);
#endif
    
    if (_password) CFRelease(_password);
    [_publicKey release];
    [_privateKey release];
    
    [super dealloc];
}

void freeKeychainContent(void *ptr, void *info)
{
#if TARGET_OS_IPHONE
    CFRelease(info);    // info is the CFData supplied by the keychain
#else
    SecKeychainItemFreeContent(NULL, ptr);
#endif
}

- (NSString *)password
{
#if TARGET_OS_IPHONE
    @synchronized(_keychainQuery)
#else
    if (!_keychainItem) return [super password];
    @synchronized((id)_keychainItem)
#endif
    {
        if (!_password)
        {
#if TARGET_OS_IPHONE
            CFTypeRef passwordData;
            OSStatus status = SecItemCopyMatching((CFDictionaryRef)_keychainQuery, &passwordData);
            
            if (status != noErr)
            {
                return nil;
            }
            
            // Adapt my keychain data-handling technique http://www.mikeabdullah.net/handling-keychain-data-with.html to work with CFData for iOS. Avoids having two copies of the sensitive data in memory at once
            CFAllocatorContext context = { 0, (void *)passwordData, NULL, NULL, NULL, NULL, NULL, freeKeychainContent, NULL };
            CFAllocatorRef allocator = CFAllocatorCreate(NULL, &context);
            
            _password = CFStringCreateWithBytesNoCopy(NULL,
                                                      CFDataGetBytePtr(passwordData), CFDataGetLength(passwordData),
                                                      kCFStringEncodingUTF8, false,
                                                      allocator);
            
            CFRelease(allocator);
#else
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
                
                NSError *error = [NSURLCredentialStorage ck2_keychainErrorWithCode:status
                                                     localizedOperationDescription:[NSString stringWithFormat:opFormat, [self user]]];
                
                [[NSClassFromString(@"NSApplication") sharedApplication] performSelectorOnMainThread:@selector(presentError:) withObject:error waitUntilDone:NO];
                
                return nil;
            }
        
            // Password data must be freed using special keychain APIs. Do so with a specially crafted CFString as described in http://www.mikeabdullah.net/handling-keychain-data-with.html
            CFAllocatorContext context = { 0, NULL, NULL, NULL, NULL, NULL, NULL, freeKeychainContent, NULL };
            CFAllocatorRef allocator = CFAllocatorCreate(NULL, &context);
            _password = CFStringCreateWithBytesNoCopy(NULL, passwordData, passwordLength, kCFStringEncodingUTF8, false, allocator);
            CFRelease(allocator);
#endif
        }
    }
    
    return (NSString *)_password;
}

- (BOOL)hasPassword;
{
    // Super's implementation says there's no password if initted with nil, so we have correct it
#if TARGET_OS_IPHONE
    return (_keychainQuery != nil || [super hasPassword]);
#else
    return (_keychainItem != nil || [super hasPassword]);
#endif
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


@implementation NSURLCredential (CK2SSHCredential)

#if !TARGET_OS_IPHONE
+ (NSURLCredential *)ck2_SSHAgentCredentialWithUser:(NSString *)user;
{
    return [[[CK2SSHCredential alloc] initWithUser:user] autorelease];
}
#endif

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

#if !TARGET_OS_IPHONE
+ (NSURLCredential *)ck2_credentialWithUser:(NSString *)user keychainItem:(SecKeychainItemRef)item;
{
    return [[[CK2SSHCredential alloc] initWithUser:user keychainItem:item] autorelease];
}
#endif

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

+ (NSError *)ck2_keychainErrorWithCode:(OSStatus)code localizedOperationDescription:(NSString *)opDescription;
{
#if !TARGET_OS_IPHONE
    CFStringRef message = SecCopyErrorMessageString(code, NULL);
#else
	CFStringRef message = NULL;
#endif
    
    NSMutableDictionary *userInfo = [[NSMutableDictionary alloc] initWithCapacity:2];
    if (message) [userInfo setObject:(NSString *)message forKey:NSLocalizedFailureReasonErrorKey];
    if (opDescription) [userInfo setObject:[opDescription stringByAppendingFormat:@" %@", message] forKey:NSLocalizedDescriptionKey];
    
    // com.apple.Keychain was my logical guess at domain, and searching the internet reveals Apple are using it in a few places
    NSError *result = [NSError errorWithDomain:@"com.apple.Keychain" code:code userInfo:userInfo];
    
    [userInfo release];
    if (message) CFRelease(message);
    
    return result;
}

- (BOOL)ck2_setCredential:(NSURLCredential *)credential forSSHHost:(NSString *)host port:(NSInteger)port error:(NSError **)error;
{
    // Can't do anything with non-persistent credentials
    if ([credential persistence] != NSURLCredentialPersistencePermanent) return YES;
    
    
    // Retrieve the keychain item
    NSString *user = [credential user];
    
#if TARGET_OS_IPHONE
	CFTypeRef keychainItem = nil;
	NSDictionary *itemQuery = @{
	(id)kSecClass : (id)kSecClassInternetPassword,
	(id)kSecAttrServer : host,
	(id)kSecAttrAccount : user,
	(id)kSecAttrPort : @(port),
	(id)kSecAttrProtocol : (id)kSecAttrProtocolSSH,
	(id)kSecAttrAuthenticationType : (id)kSecAttrAuthenticationTypeDefault };
	
	// Store the password
	NSString *password = [credential password];
	NSAssert(password, @"%@ was handed password-less credential", NSStringFromSelector(_cmd));
	
	OSStatus status = SecItemUpdate((CFDictionaryRef)itemQuery, (CFDictionaryRef)@{(id)kSecValueData : [password dataUsingEncoding:NSUTF8StringEncoding] });
	
	NSString *opDescription;
	if (status != errSecSuccess) {
		NSMutableDictionary *addItemQuery = [itemQuery.mutableCopy autorelease];
		[addItemQuery setObject:[password dataUsingEncoding:NSUTF8StringEncoding] forKey:(id)kSecValueData];
		status = SecItemAdd((CFDictionaryRef)addItemQuery, &keychainItem);
		
		if (status != errSecSuccess) {
			opDescription = NSLocalizedStringFromTableInBundle(@"The password couldn't be added to your keychain.", nil, [NSBundle bundleForClass:[CK2SSHCredential class]], "error description");
		}
	}
	
	if (keychainItem) CFRelease(keychainItem);
    
#else
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
    
    NSString *opDescription;
    if (status == errSecSuccess)
    {
        status = SecKeychainItemModifyAttributesAndData(keychainItem,
                                                        NULL, // no change to attributes
                                                        [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [password UTF8String]);
        
        opDescription = NSLocalizedStringFromTableInBundle(@"The password stored in your keychain couldn't be updated.", nil, [NSBundle bundleForClass:[CK2SSHCredential class]], "error description");
        
        CFRelease(keychainItem);    // know for sure keychainItem isn't nil as this line hasn't been reported to crash so far!
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
        
        opDescription = NSLocalizedStringFromTableInBundle(@"The password couldn't be added to your keychain.", nil, [NSBundle bundleForClass:[CK2SSHCredential class]], "error description");
    }
#endif
    
    if (status == errSecSuccess) return YES;
    
    
    // Note the host etc. involved
    opDescription = [opDescription stringByAppendingFormat:
                     NSLocalizedStringFromTableInBundle(@" (%@@%@:%i).",
                                                        nil,
                                                        [NSBundle bundleForClass:[CK2SSHCredential class]],
                                                        "error description"),
                     [credential user],
                     host,
                     port];
    
    // Note a crazily empty password
    if (![password length]) opDescription = [opDescription stringByAppendingFormat:
                                             NSLocalizedStringFromTableInBundle(@" (%@ password.)",
                                                                                nil,
                                                                                [NSBundle bundleForClass:[CK2SSHCredential class]],
                                                                                "error description"),
                                             password   /* don't worry, it's either nil or empty! */];
    
    if (error) *error = [[self class] ck2_keychainErrorWithCode:status localizedOperationDescription:opDescription];
    return NO;
}

#if !TARGET_OS_IPHONE
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
#endif

- (NSURLCredential *)ck2_credentialForPrivateKeyAtURL:(NSURL *)privateKey user:(NSString *)user;
{
    // Try fetching passphrase from the keychain
    // The service & account name is entirely empirical based on what's in my keychain from SSH Agent
    
#if TARGET_OS_IPHONE
    // TODO: Return nil if there's nothing found in the keychain
	CK2SSHCredential *result = [[CK2SSHCredential alloc] initWithUser:user keychainQuery:@{
                              (id)kSecClass : (id)kSecClassGenericPassword,
                              (id)kSecAttrService : @"SSH",
                              (id)kSecAttrAccount : privateKey}];
#else
    NSString *privateKeyPath = [privateKey path];
    
    SecKeychainItemRef item = [self copyKeychainItemForPrivateKeyPath:privateKeyPath];
    if (!item) return nil;
    
    CK2SSHCredential *result = [[CK2SSHCredential alloc] initWithUser:user keychainItem:item];
    CFRelease(item);
#endif
    
    [result setPublicKeyURL:nil privateKeyURL:privateKey];
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
#if TARGET_OS_IPHONE
      NSDictionary *itemQuery = @{
			(id)kSecClass : (id)kSecClassGenericPassword,
			(id)kSecAttrService : @"SSH",
			(id)kSecAttrAccount : privateKey};
      
      OSStatus status = SecItemUpdate((CFDictionaryRef)itemQuery, (CFDictionaryRef)@{(id)kSecValueData : [password dataUsingEncoding:NSUTF8StringEncoding]});
      if (status != errSecSuccess) {
        NSMutableDictionary *itemAddQuery = [itemQuery mutableCopy];
        [itemAddQuery setObject:[password dataUsingEncoding:NSUTF8StringEncoding] forKey:(id)kSecValueData];
        status = SecItemAdd((CFDictionaryRef)itemAddQuery, NULL);
      }
      return status == noErr;
#else
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
#endif
    }
    
    return NO;
}
    
@end
