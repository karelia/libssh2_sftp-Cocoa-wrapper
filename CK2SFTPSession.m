//
//  CK2SFTPSession.m
//  Sandvox
//
//  Created by Mike on 03/07/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import "CK2SFTPSession.h"

#import "CK2SFTPFileHandle.h"
#import "CK2SSHCredential.h"

#include <arpa/inet.h>

#include <libssh2_sftp.h>
#include <libssh2.h>


NSString *const CK2SSHDisconnectErrorDomain = @"org.ietf.SSH.disconnect";
NSString *const CK2LibSSH2ErrorDomain = @"org.libssh2.libssh2";
NSString *const CK2LibSSH2SFTPErrorDomain = @"org.libssh2.libssh2.sftp";

NSString *const CK2SSHAuthenticationSchemePublicKey = @"publickey";
NSString *const CK2SSHAuthenticationSchemeKeyboardInteractive = @"keyboard-interactive";
NSString *const CK2SSHAuthenticationSchemePassword = @"password";


// NSURLProtectionSpace doesn't handle SSH properly, so override it do so
@interface CK2SSHProtectionSpace : NSURLProtectionSpace
@end


#pragma mark -


@interface CK2SFTPSession ()
- (void)failWithError:(NSError *)error;
- (void)startAuthentication;
@end



@implementation CK2SFTPSession

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;
    
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    
    FD_ZERO(&fd);
    
    FD_SET(socket_fd, &fd);
    
    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(session);
    
    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;
    
    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;
    
    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);
    
    return rc;
}

- (NSInteger)portForURL:(NSURL *)URL;
{
    NSNumber *result = [URL port];
    return (result ? [result integerValue] : 22);
}

#pragma mark Lifecycle

- (id)initWithURL:(NSURL *)URL delegate:(id <CK2SFTPSessionDelegate>)delegate;
{
    return [self initWithURL:URL delegate:delegate startImmediately:YES];
}

- (id)initWithURL:(NSURL *)URL delegate:(id <CK2SFTPSessionDelegate>)delegate startImmediately:(BOOL)startImmediately;
{
    NSParameterAssert(URL);
    
    if (self = [self init])
    {
        _URL = [URL copy];
        _delegate = delegate;
    }
    
    if (startImmediately) [self start];
    
    return self;
}

void disconnect_callback(LIBSSH2_SESSION *session, int reason, const char *message, int message_len, const char *language, int language_len, void **abstract)
{
    CK2SFTPSession *self = *abstract;
    
    // Build a raw error to encapsulate the disconnect
    NSMutableDictionary *userInfo = [[NSMutableDictionary alloc] initWithCapacity:2];
    if (message)
    {
        NSString *string = [[NSString alloc] initWithBytes:message length:message_len encoding:NSUTF8StringEncoding];
        [userInfo setObject:string forKey:NSLocalizedDescriptionKey];
        [string release];
    }
    if (language)
    {
        NSString *string = [[NSString alloc] initWithBytes:language length:language_len encoding:NSUTF8StringEncoding];
        [userInfo setObject:string forKey:@"language"];
        [string release];
    }
    
    NSError *error = [NSError errorWithDomain:CK2SSHDisconnectErrorDomain code:reason userInfo:userInfo];
    [userInfo release];
    
    [self failWithError:error];
}

- (void)start;
{
    if (_session) return;   // already started
    
    
    // Header
    NSBundle *bundle = [NSBundle mainBundle];
    NSString *transcriptHeader = [NSString stringWithFormat:
                                  @"%@ %@ (architecture unknown) Session Transcript [%@] (%@)",
                                  [bundle objectForInfoDictionaryKey:(NSString *)kCFBundleNameKey],
                                  [bundle objectForInfoDictionaryKey:(NSString *)kCFBundleVersionKey],
                                  [[NSProcessInfo processInfo] operatingSystemVersionString],
                                  [NSDate date]];
    [_delegate SFTPSession:self appendStringToTranscript:transcriptHeader];
    
    
    unsigned long hostaddr;
    struct sockaddr_in sin;
#if defined(HAVE_IOCTLSOCKET)
    long flag = 1;
#endif
    
    
    /* Create a session instance */
    _session = libssh2_session_init_ex(NULL, NULL, NULL, self);
    if (!_session)
    {
        NSError *error = [NSError errorWithDomain:CK2LibSSH2ErrorDomain
                                             code:0
                                         userInfo:[NSDictionary dictionaryWithObject:@"libssh2 session initialization failed"
                                                                              forKey:NSLocalizedDescriptionKey]];
        
        return [self failWithError:error];
    }
    
    
    /*
     * The application code is responsible for creating the socket
     * and establishing the connection
     */
    // FIXME: NSHost is not threadsafe; use CF-level API instead
    NSString *hostName = [_URL host];
    NSString *transcript = [NSString stringWithFormat:@"Connecting to %@", hostName];
    NSNumber *port = [_URL port];
    if (port) transcript = [transcript stringByAppendingFormat:@":%@", port];
    [_delegate SFTPSession:self appendStringToTranscript:transcript];
    
    NSHost *host = [NSHost hostWithName:hostName];
    NSString *address = [host address];
    if (!address)
    {
        NSError *error = [NSError errorWithDomain:NSURLErrorDomain
                                             code:NSURLErrorCannotFindHost
                                         userInfo:[NSDictionary dictionaryWithObject:@"Cannot find host"
                                                                              forKey:NSLocalizedDescriptionKey]];
        
        return [self failWithError:error];
    }
    
    hostaddr = inet_addr([address UTF8String]);
    
    _socket = CFSocketCreate(NULL, AF_INET, SOCK_STREAM, 0, 0, NULL, NULL);
    if (!_socket)
    {
        NSError *error = [NSError errorWithDomain:NSURLErrorDomain
                                             code:NSURLErrorUnknown
                                         userInfo:[NSDictionary dictionaryWithObject:@"Error creating socket"
                                                                              forKey:NSLocalizedDescriptionKey]];
        
        return [self failWithError:error];
    }
    
    sin.sin_family = AF_INET;
    sin.sin_port = htons([self portForURL:_URL]);
    sin.sin_addr.s_addr = hostaddr;
    
    CFDataRef addressData = CFDataCreate(NULL, (UInt8 *)&sin, sizeof(struct sockaddr_in));
    CFSocketError socketError = CFSocketConnectToAddress(_socket, addressData, 60.0);
    CFRelease(addressData);
    
    if (socketError != kCFSocketSuccess)
    {
        NSError *error = [NSError errorWithDomain:NSURLErrorDomain
                                             code:NSURLErrorCannotConnectToHost
                                         userInfo:[NSDictionary dictionaryWithObject:@"Cannot connect to host"
                                                                              forKey:NSLocalizedDescriptionKey]];
        
        return [self failWithError:error];
    }
    
    
    /* Since we have set non-blocking, tell libssh2 we are non-blocking */
    //libssh2_session_set_blocking(_session, 0);
    
    
    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    
    if (libssh2_session_handshake(_session, CFSocketGetNative(_socket)))
    {
        return [self failWithError:[self sessionError]];
    }
    
    
    // Want to know if get disconnected
    libssh2_session_callback_set(_session, LIBSSH2_CALLBACK_DISCONNECT, &disconnect_callback);
    
    
    [self startAuthentication];
}

- (void)cancel;
{
    _delegate = nil;
    
    [_URL release]; _URL = nil;
    
    libssh2_sftp_shutdown(_sftp); _sftp = NULL;
    
    
    BOOL logged = NO;
    if (_session)
    {
        [_delegate SFTPSession:self appendStringToTranscript:@"Disconnecting from server…"];
        logged = YES;
        
        libssh2_session_disconnect(_session, "Normal Shutdown, Thank you");
        libssh2_session_free(_session); _session = NULL;
    }
    
    if (_socket)
    {
        if (!logged) [_delegate SFTPSession:self appendStringToTranscript:@"Disconnecting from server…"];
        
        CFSocketInvalidate(_socket);
        CFRelease(_socket); _socket = NULL;
    }
    
    libssh2_exit();
}

- (void)dealloc
{
    [self cancel];  // performs all teardown of ivars
    [super dealloc];
}

#pragma mark Error Handling

- (NSError *)sessionErrorWithPath:(NSString *)path;
{
    if (!_session) return nil;
    
    char *errormsg;
    int code = libssh2_session_last_error(_session, &errormsg, NULL, 0);
    if (code == 0) return nil;
    
    NSString *description = [[NSString alloc] initWithCString:errormsg encoding:NSUTF8StringEncoding];
    
    NSError *result = [NSError errorWithDomain:CK2LibSSH2ErrorDomain
                                          code:code
                                      userInfo:[NSDictionary dictionaryWithObjectsAndKeys:
                                                description, NSLocalizedDescriptionKey,
                                                path, NSFilePathErrorKey,
                                                nil]];
    [description release];
    
    
    if (code == LIBSSH2_ERROR_SFTP_PROTOCOL)
    {
        code = libssh2_sftp_last_error(_sftp);
                
        result = [NSError errorWithDomain:CK2LibSSH2SFTPErrorDomain
                                     code:code
                                 userInfo:[NSDictionary dictionaryWithObjectsAndKeys:
                                           result, NSUnderlyingErrorKey,
                                           path, NSFilePathErrorKey,
                                           nil]];
    }
    
    return result;
}

- (NSError *)sessionError;
{
    return [self sessionErrorWithPath:nil];
}

- (void)failWithError:(NSError *)error
{
    id delegate = _delegate;    // because -cancel will set it to nil
    [self cancel];
    [delegate SFTPSession:self didFailWithError:error];
}

#pragma mark Directories

// Keep compatibility with CK without having to link to it
#define cxFilenameKey @"cxFilenameKey"

- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error;
{
    return [[self attributesOfContentsOfDirectoryAtPath:path error:error] valueForKey:cxFilenameKey];
}

- (NSArray *)attributesOfContentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error;
{
    LIBSSH2_SFTP_HANDLE *handle = libssh2_sftp_opendir(_sftp, [path UTF8String]);
    if (!handle)
    {
        if (error) *error = [self sessionErrorWithPath:path];
        return nil;
    }
    
    NSMutableArray *result = [NSMutableArray array];
    
#define BUFFER_LENGTH 1024
    char buffer[BUFFER_LENGTH];
    
    int filenameLength;
    do
    {
        LIBSSH2_SFTP_ATTRIBUTES attributes;
        filenameLength = libssh2_sftp_readdir(handle, buffer, BUFFER_LENGTH, &attributes);
        
        if (filenameLength > 0)
        {
            NSString *filename = [[NSString alloc] initWithBytes:buffer
                                                          length:filenameLength
                                                        encoding:NSUTF8StringEncoding];
            
            // Exclude . and .. as they're not Cocoa-like
            if (![filename isEqualToString:@"."] && ![filename isEqualToString:@".."])
            {
                NSString *type = (attributes.permissions & LIBSSH2_SFTP_S_IFDIR ?
                                  NSFileTypeDirectory :
                                  NSFileTypeRegular);
                
                [result addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                                   filename, cxFilenameKey,
                                   type, NSFileType,
                                   nil]];
            }
            
            [filename release];
        }
    }
    while (filenameLength > 0);
    
    if (filenameLength < 0) // an error!
    {
        result = nil;
        if (error) *error = [self sessionErrorWithPath:path];
    }
    
    libssh2_sftp_closedir(handle);
    return result;
}

- (BOOL)createDirectoryAtPath:(NSString *)path mode:(long)mode error:(NSError **)error;
{
    int result = libssh2_sftp_mkdir(_sftp, [path UTF8String], mode);
    
    if (result == 0)
    {
        return YES;
    }
    else
    {
        if (error) *error = [self sessionErrorWithPath:path];
        return NO;
    }
}

- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)createIntermediates mode:(long)mode error:(NSError **)outError;
{
    if (!createIntermediates) return [self createDirectoryAtPath:path mode:mode error:outError];
    
    NSError *error;
    BOOL result = [self createDirectoryAtPath:path mode:mode error:&error];
    
    if (!result)
    {
        if (outError) *outError = error;
        
        if ([[error domain] isEqualToString:CK2LibSSH2SFTPErrorDomain] && [error code] == LIBSSH2_FX_NO_SUCH_FILE)
        {
            if ([self createDirectoryAtPath:[path stringByDeletingLastPathComponent]
                withIntermediateDirectories:createIntermediates
                                       mode:mode
                                      error:outError])
            {
                result = [self createDirectoryAtPath:path mode:mode error:outError];
            }
        }
    }
    
    return result;
}


- (BOOL)removeDirectoryAtPath:(NSString *)path error:(NSError **)error {
    NSParameterAssert(path);
    
    [_delegate SFTPSession:self
  appendStringToTranscript:[NSString stringWithFormat:@"Deleting directory %@", [path lastPathComponent]]];
    
    int result=libssh2_sftp_rmdir(_sftp, [path UTF8String]);
    
    if (result == 0)
    {
        return YES;
    }
    else
    {
        if (error) *error = [self sessionErrorWithPath:path];
        return NO;
    }    
}


#pragma mark Files

- (CK2SFTPFileHandle *)openHandleAtPath:(NSString *)path flags:(unsigned long)flags mode:(long)mode error:(NSError **)error;
{
    NSParameterAssert(path);
    
    [_delegate SFTPSession:self
  appendStringToTranscript:[NSString stringWithFormat:@"Uploading file %@", [path lastPathComponent]]];
    
    LIBSSH2_SFTP_HANDLE *handle = libssh2_sftp_open(_sftp, [path UTF8String], flags, mode);
    
    if (!handle)
    {
        if (error) *error = [self sessionErrorWithPath:path];
        return nil;
    }
    
    return [[[CK2SFTPFileHandle alloc] initWithSFTPHandle:handle session:self path:path] autorelease];
}

- (BOOL)removeFileAtPath:(NSString *)path error:(NSError **)error;
{
    NSParameterAssert(path);
    
    [_delegate SFTPSession:self
  appendStringToTranscript:[NSString stringWithFormat:@"Deleting file %@", [path lastPathComponent]]];
    
    int result = libssh2_sftp_unlink(_sftp, [path UTF8String]);
    
    if (result == LIBSSH2_ERROR_NONE)
    {
        return YES;
    }
    else
    {
        if (error) *error = [self sessionErrorWithPath:path];
        return NO;
    }
}

#pragma mark Rename

- (BOOL)moveItemAtPath:(NSString*) oldPath toPath:(NSString*) newPath error:(NSError **)error
{
    NSParameterAssert(oldPath);
    NSParameterAssert(newPath);
    
    [_delegate SFTPSession:self
  appendStringToTranscript:[NSString stringWithFormat:@"Renaming %@ to %@", [oldPath lastPathComponent],[newPath lastPathComponent]]];
  
    int result = libssh2_sftp_rename(_sftp, [oldPath UTF8String], [newPath UTF8String]);
    
    if (result == LIBSSH2_ERROR_NONE)
    {
        return YES;
    }
    else
    {
        if (error) *error = [self sessionErrorWithPath:oldPath];
        return NO;
    }    
}

#pragma mark Host Fingerprint

- (LIBSSH2_KNOWNHOSTS *)createKnownHosts:(NSError **)error;
{
    LIBSSH2_KNOWNHOSTS *result = libssh2_knownhost_init(_session);
    if (result)
    {
        // Read in known hosts file
        int rc = libssh2_knownhost_readfile(result,
                                            [[@"~/.ssh/known_hosts" stringByExpandingTildeInPath] fileSystemRepresentation],
                                            LIBSSH2_KNOWNHOST_FILE_OPENSSH);
        if (rc < LIBSSH2_ERROR_NONE && rc != LIBSSH2_ERROR_FILE)    // assume LIBSSH2_ERROR_FILE is missing known_hosts file
        {
            if (error) *error = [self sessionError];
            libssh2_knownhost_free(result); result = NULL;
        }
    }
    else
    {
        if (error) *error = [self sessionError];
    }
    
    return result;
}

+ (int)checkKnownHostsForFingerprintFromSession:(CK2SFTPSession *)session error:(NSError **)error;
{
    LIBSSH2_KNOWNHOSTS *knownHosts = [session createKnownHosts:error];
    if (!knownHosts) return LIBSSH2_KNOWNHOST_CHECK_FAILURE;
    
    
    @try
    {
        // Ask for server's fingerprint
        size_t fingerprintLength;
        int fingerprintType;
        const char *fingerprint = libssh2_session_hostkey(session->_session, &fingerprintLength, &fingerprintType);
        
        if (!fingerprint)
        {
            if (error) *error = [session sessionError];
            return LIBSSH2_KNOWNHOST_CHECK_FAILURE;
        }
        
        
        // Check fingerprint against known hosts
        // Contrary to what the docs say, passing NULL for host argument crashes
        struct libssh2_knownhost *knownhost;
        int result = libssh2_knownhost_checkp(knownHosts,
                                              [[session->_URL host] cStringUsingEncoding:NSASCIIStringEncoding],
                                              [session portForURL:session->_URL],
                                              fingerprint, fingerprintLength,
                                              (LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW),
                                              &knownhost);
        
        if (result == LIBSSH2_KNOWNHOST_CHECK_FAILURE)
        {
            // I don't know if libssh2 actually supplies error info in this case
            if (error) *error = [session sessionError];
        }
        
        return result;
    }
    @finally
    {
        libssh2_knownhost_free(knownHosts);
    }
    
    // Shouldn't ever be reached by my reckoning
    return LIBSSH2_KNOWNHOST_CHECK_NOTFOUND;
}

- (BOOL)addToKnownHosts:(NSError **)error;
{
    LIBSSH2_KNOWNHOSTS *knownHosts = [self createKnownHosts:error];
    if (!knownHosts) return NO;
    
    
    @try
    {
        // Ask for server's fingerprint
        size_t fingerprintLength;
        int fingerprintType;
        const char *fingerprint = libssh2_session_hostkey(_session, &fingerprintLength, &fingerprintType);
        
        if (!fingerprint)
        {
            if (error) *error = [self sessionError];
            return NO;
        }
        
        
        // Add the fingerprint
        // Have to adjust fingerprint to match libssh2_knownhost_addc's expectations
        switch (fingerprintType)
        {
            case LIBSSH2_HOSTKEY_TYPE_RSA:
                fingerprintType = LIBSSH2_KNOWNHOST_KEY_SSHRSA;
                break;
            case LIBSSH2_HOSTKEY_TYPE_DSS:
                fingerprintType = LIBSSH2_KNOWNHOST_KEY_SSHDSS;
                break;
            default:
                fingerprintType = 0;
        }
        
        int added = libssh2_knownhost_addc(knownHosts,
                                           [[_URL host] UTF8String],
                                           NULL,
                                           fingerprint, fingerprintLength,
                                           NULL, 0,
                                           (LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW | fingerprintType),
                                           NULL);
        if (added != LIBSSH2_ERROR_NONE)
        {
            if (error) *error = [self sessionError];
            return NO;
        }
        
        
        // Store the updated file
        int written = libssh2_knownhost_writefile(knownHosts,
                                                  [[@"~/.ssh/known_hosts" stringByExpandingTildeInPath] fileSystemRepresentation],
                                                  LIBSSH2_KNOWNHOST_FILE_OPENSSH);
        if (written != LIBSSH2_ERROR_NONE)
        {
            if (error) *error = [self sessionError];
            return NO;
        }
    }
    @finally
    {
        libssh2_knownhost_free(knownHosts);
    }
    
    return YES;
}

- (NSData *)hostkeyHashForType:(int)hash_type;
{
    const char *fingerprint = libssh2_hostkey_hash(_session, hash_type);
    if (hash_type == LIBSSH2_HOSTKEY_HASH_SHA1)
    {
        return [NSData dataWithBytes:fingerprint length:20];   // SHA1 hashes are 20bytes
    }
    else if (hash_type == LIBSSH2_HOSTKEY_HASH_MD5)
    {
        return [NSData dataWithBytes:fingerprint length:16];   // MD5 hashes are 16bytes
    }
    
    return nil;
}

#pragma mark Auth

static void kbd_callback(const char *name, int name_len,
                         const char *instruction, int instruction_len,
                         int num_prompts,
                         const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
                         LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
                         void **abstract)
{
    CK2SFTPSession *self = *abstract;    // was provided when session initialized
        
    
    // Append prompts to transcript
    int i;
    for (i = 0; i < num_prompts; i++)
    {
        NSString *aPrompt = [[NSString alloc] initWithBytes:prompts[i].text length:prompts[i].length encoding:NSUTF8StringEncoding];
        [self->_delegate SFTPSession:self appendStringToTranscript:aPrompt];
        [aPrompt release];
    }
    
    
    // Try to auth by plonking the password into response if prompted
    if (num_prompts == 1)
    {
        NSURLCredential *credential = self->_keyboardInteractiveCredential;
        NSString *password = [credential password];
        if (password)
        {
            NSUInteger length = [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
            responses[0].text = malloc(length);
            responses[0].length = length;
            
            [password getBytes:responses[0].text
                     maxLength:length
                    usedLength:NULL
                      encoding:NSUTF8StringEncoding
                       options:0
                         range:NSMakeRange(0, [password length])
                remainingRange:NULL];
        }
    }
}

- (void)sendAuthenticationChallenge;
{
    if ([_challenge error])
    {
        NSString *error = [[_challenge error] description];
        if ([_challenge previousFailureCount] && [_challenge proposedCredential])
        {
            error = [error stringByAppendingFormat:@" for user: %@", [[_challenge proposedCredential] user]];
        }
            
        [_delegate SFTPSession:self appendStringToTranscript:error];
    }
    
    [_delegate SFTPSession:self didReceiveAuthenticationChallenge:_challenge];
}

- (void)startAuthentication;
{
    /* We could authenticate via password */
    NSURLProtectionSpace *protectionSpace = [[CK2SSHProtectionSpace alloc] initWithHost:[_URL host]
                                                                                   port:[self portForURL:_URL]
                                                                               protocol:@"ssh"  // CK2SSHProtectionSpace is always ssh
                                                                                  realm:nil
                                                                   authenticationMethod:NSURLAuthenticationMethodDefault];
    
    _challenge = [[NSURLAuthenticationChallenge alloc]
                  initWithProtectionSpace:protectionSpace
                  proposedCredential:nil
                  previousFailureCount:0
                  failureResponse:nil
                  error:nil
                  sender:self];
    [protectionSpace release];
    
    [self sendAuthenticationChallenge];        
}

- (void)initializeSFTP;
{
    do {
        _sftp = libssh2_sftp_init(_session);
        
        if (!_sftp)
        {
            int lastErrNo = libssh2_session_last_errno(_session);
            
            if (lastErrNo == LIBSSH2_ERROR_EAGAIN)
            {
                waitsocket(CFSocketGetNative(_socket), _session); /* now we wait */
            }
            else
            {
                [self failWithError:[self sessionError]];
                return;
            }
        }
    } while (!_sftp);
    
    [_delegate SFTPSessionDidInitialize:self];
}

- (NSArray *)supportedAuthenticationSchemesForUser:(NSString *)user;
{
    char *userauthlist = libssh2_userauth_list(_session,
                                               [user UTF8String],
                                               [user lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
    
    if (!userauthlist) return nil;
    
    NSString *supportedAuthSchemes = [[NSString alloc] initWithCString:userauthlist encoding:NSUTF8StringEncoding];
    NSArray *result = [supportedAuthSchemes componentsSeparatedByString:@","];
    [supportedAuthSchemes release];
    return result;
}

- (BOOL)useSSHAgentToAuthenticateUser:(NSString *)user error:(NSError **)error;
{
    LIBSSH2_AGENT *agent = libssh2_agent_init(_session);
    if (!agent)
    {
        if (error) *error = [self sessionError];
        return NO;
    }
    
    
    // Before we actually connect, make sure all standard keys are registered
    NSTask *sshAgentTask = [[NSTask alloc] init];
    [sshAgentTask setLaunchPath:@"/usr/bin/ssh-add"];
    [sshAgentTask setStandardInput:[NSPipe pipe]];  // so xcode doesn't start prompting for passphrase!
    [sshAgentTask launch];
    [sshAgentTask waitUntilExit];
    [sshAgentTask release];
    
    
    if (libssh2_agent_connect(agent) != LIBSSH2_ERROR_NONE)
    {
        if (error) *error = [self sessionError];
        libssh2_agent_free(agent);
        return NO;
    }
    
    if (libssh2_agent_list_identities(agent) != LIBSSH2_ERROR_NONE)
    {
        [_delegate SFTPSession:self appendStringToTranscript:@"Failed to list identities from SSH Agent"];
        if (error) *error = [self sessionError];
        libssh2_agent_free(agent);
        return NO;
    }
    
    struct libssh2_agent_publickey *identity = NULL;
    while (YES)
    {
        int rc = libssh2_agent_get_identity(agent, &identity, identity);
        if (rc != LIBSSH2_ERROR_NONE)
        {
            // Reached the end of the identity list, or failed to get identity?
            if (error)
            {
                if (rc == 1)
                {
                    *error = [NSError errorWithDomain:CK2LibSSH2ErrorDomain
                                                 code:rc
                                             userInfo:[NSDictionary dictionaryWithObject:@"No more identities found to try authentication with" forKey:NSLocalizedDescriptionKey]];
                }
                else
                {
                    *error = [self sessionError];
                }
            }
            
            libssh2_agent_disconnect(agent);
            libssh2_agent_free(agent);
            return NO;
        }
        
        if (libssh2_agent_userauth(agent, [user UTF8String], identity) == LIBSSH2_ERROR_NONE)
        {
            break;
        }
        
        // Log each rejected key
        [_delegate SFTPSession:self appendStringToTranscript:
         [NSString stringWithFormat:
          @"%@ (%@)",
          [[self sessionError] localizedDescription],
          [NSString stringWithUTF8String:(*identity).comment]]];
    }
    
    libssh2_agent_disconnect(agent);
    libssh2_agent_free(agent); agent = NULL;
    
    [self initializeSFTP];
    return YES;
}

- (BOOL)usePublicKeyCredential:(NSURLCredential *)credential error:(NSError **)error;
{
    NSString *privateKey = [[credential ck2_privateKeyURL] path];
    NSString *publicKey = [[credential ck2_publicKeyURL] path];
    
    if (!privateKey && !publicKey)
    {
        return [self useSSHAgentToAuthenticateUser:[credential user] error:error];
    }
    else
    {
        int result = libssh2_userauth_publickey_fromfile(_session,
                                                         [[credential user] UTF8String],
                                                         [publicKey fileSystemRepresentation],
                                                         [privateKey fileSystemRepresentation],
                                                         NULL);
        if (result)
        {
            if (error) *error = [self sessionError];
            return NO;
        }
        
        [self initializeSFTP];
    }
    
    return YES;
}

- (void)useCredential:(NSURLCredential *)credential forAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    NSParameterAssert(challenge);
    NSParameterAssert(challenge == _challenge);
    [_challenge autorelease]; _challenge = nil; // autorelease so can use for duration of method
    
    
    if ([credential ck2_isPublicKeyCredential])
    {
        NSError *error;
        if (![self usePublicKeyCredential:credential error:&error])
        {
            _challenge = [[NSURLAuthenticationChallenge alloc]
                          initWithProtectionSpace:[challenge protectionSpace]
                          proposedCredential:credential
                          previousFailureCount:([challenge previousFailureCount] + 1)
                          failureResponse:nil
                          error:error
                          sender:self];
            
            [self sendAuthenticationChallenge];
        }
    }
    else
    {
        NSString *user = [credential user];
        NSArray *authSchemes = [self supportedAuthenticationSchemesForUser:user];
        
        // Use Keyboard-Interactive auth only if forced to
        int rc;
        if ([authSchemes containsObject:CK2SSHAuthenticationSchemeKeyboardInteractive] &&
            ![authSchemes containsObject:CK2SSHAuthenticationSchemePassword])
        {
            _keyboardInteractiveCredential = credential;    // weak, temporary
            rc = libssh2_userauth_keyboard_interactive(_session, [user UTF8String], &kbd_callback);
            _keyboardInteractiveCredential = nil;
        }
        else
        {
            NSString *password = [credential password];
            if (!password) password = @"";  // libssh2 can't handle nil passwords
            rc = libssh2_userauth_password(_session, [user UTF8String], [password UTF8String]);
        }
        
        if (rc)
        {
            NSError *error = [self sessionError];
            
            if (rc == LIBSSH2_ERROR_AUTHENTICATION_FAILED)  // let the client have another go
            {
                _challenge = [[NSURLAuthenticationChallenge alloc]
                              initWithProtectionSpace:[challenge protectionSpace]
                              proposedCredential:credential
                              previousFailureCount:([challenge previousFailureCount] + 1)
                              failureResponse:nil
                              error:error
                              sender:self];
                
                [self sendAuthenticationChallenge];
            }
            else 
            {
                [self failWithError:error];
            }
        }
        else
        {
            // NSURLCredentialStorage will take care of adding to keychain if requested
            [[NSURLCredentialStorage sharedCredentialStorage] setCredential:credential
                                                         forProtectionSpace:[challenge protectionSpace]];
            
            [self initializeSFTP];
        }
    }
}

- (void)continueWithoutCredentialForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;
{
    NSParameterAssert(challenge);
    NSParameterAssert(challenge == _challenge);
    [_challenge release]; _challenge = nil;
    
    [self initializeSFTP];
}

- (void)cancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;
{
    NSParameterAssert(challenge);
    NSParameterAssert(challenge == _challenge);
    [_challenge release]; _challenge = nil;

    [self cancel];
}

#pragma mark Low-level

@synthesize libssh2_sftp = _sftp;
@synthesize libssh2_session = _session;
@end


#pragma mark -


@implementation CK2SSHProtectionSpace

- (NSString *)protocol { return @"ssh"; }

/*	NSURLProtectionSpace is immutable. It probably implements -copyWithZone: in the exact same way we do, but have no guarantee, so re-implement here.
 */
- (id)copyWithZone:(NSZone *)zone { return [self retain]; }

@end

