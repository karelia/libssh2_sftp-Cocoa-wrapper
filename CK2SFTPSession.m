//
//  CK2SFTPSession.m
//  Sandvox
//
//  Created by Mike on 03/07/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import "CK2SFTPSession.h"

#include <libssh2_sftp.h>
#include <libssh2.h>

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
# include <arpa/inet.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>



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

- (NSInteger)port { return 22; }

- (id)initWithURL:(NSURL *)URL delegate:(id <CK2SFTPSessionDelegate>)delegate;
{
    self = [self init];
    
    _delegate = delegate;
    
    
    unsigned long hostaddr;
    int i, auth_pw = 1;
    struct sockaddr_in sin;
    const char *fingerprint;
    int rc;
#if defined(HAVE_IOCTLSOCKET)
    long flag = 1;
#endif
    

    NSHost *host = [NSHost hostWithName:[URL host]];
    NSString *address = [host address];
    
    hostaddr = inet_addr([address UTF8String]);
    
    /*if (argc > 2) {
        username = argv[2];
    }
    if (argc > 3) {
        password = argv[3];
    }
    if (argc > 4) {
        sftppath = argv[4];
    }*/
    
    rc = libssh2_init (0);
    if (rc != 0) {
        fprintf (stderr, "libssh2 initialization failed (%d)\n", rc);
        [self release]; return nil;
    }
    
    /*
     * The application code is responsible for creating the socket
     * and establishing the connection
     */    
    _socket = CFSocketCreate(NULL, AF_INET, SOCK_STREAM, 0, 0, NULL, NULL);
    
    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;
    
    CFDataRef addressData = CFDataCreate(NULL, (UInt8 *)&sin, sizeof(struct sockaddr_in));
    CFSocketError socketError = CFSocketConnectToAddress(_socket, addressData, 60.0);
    CFRelease(addressData);
    
    if (socketError != kCFSocketSuccess)
    {
        [self release]; return nil;
    }
    
    
    /* Create a session instance */
    _session = libssh2_session_init();
    if (!_session)
    {
        [self release]; return nil;
    }
    
    
    /* Since we have set non-blocking, tell libssh2 we are non-blocking */
    libssh2_session_set_blocking(_session, 0);
    
    
    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    while ((rc = libssh2_session_startup(_session, CFSocketGetNative(_socket))) ==
           LIBSSH2_ERROR_EAGAIN);
    if (rc) {
        fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
        return -1;
    }
    
    /* At this point we havn't yet authenticated.  The first thing to do
     * is check the hostkey's fingerprint against our known hosts Your app
     * may have it hard coded, may go to a file, may present it to the
     * user, that's your call
     */
    fingerprint = libssh2_hostkey_hash(_session, LIBSSH2_HOSTKEY_HASH_SHA1);
    fprintf(stderr, "Fingerprint: ");
    for(i = 0; i < 20; i++) {
        fprintf(stderr, "%02X ", (unsigned char)fingerprint[i]);
    }
    fprintf(stderr, "\n");
    
    if (auth_pw) {
        /* We could authenticate via password */
        NSURLProtectionSpace *protectionSpace = [[NSURLProtectionSpace alloc] initWithHost:[URL host]
                                                                                      port:[self port]
                                                                                  protocol:@"ssh"
                                                                                     realm:nil
                                                                      authenticationMethod:NSURLAuthenticationMethodDefault];
        
        NSURLAuthenticationChallenge *challenge = [[NSURLAuthenticationChallenge alloc]
                                                   initWithProtectionSpace:protectionSpace
                                                   proposedCredential:nil
                                                   previousFailureCount:0
                                                   failureResponse:nil
                                                   error:nil
                                                   sender:self];
        
        [_delegate SFTPSession:self didReceiveAuthenticationChallenge:challenge];
        return self;
        
        
        
    } else {
        /* Or by public key /
        while ((rc =
                libssh2_userauth_publickey_fromfile(_session, username,
                                                    "/home/username/"
                                                    ".ssh/id_rsa.pub",
                                                    "/home/username/"
                                                    ".ssh/id_rsa",
                                                    password)) ==
               LIBSSH2_ERROR_EAGAIN);
        if (rc) {
            fprintf(stderr, "\tAuthentication by public key failed\n");
            goto shutdown;
        }*/
    }
#if 0
    libssh2_trace(session, LIBSSH2_TRACE_CONN);
#endif
    
 
    
    
    return self;
}

- (void)useCredential:(NSURLCredential *)credential forAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    int rc;
    const char *sftppath="/tmp/TEST";
    int spin = 0;
    int total = 0;

    
    NSString *username = [credential user];
    NSString *password = [credential password];
    
    while ((rc = libssh2_userauth_password(_session, [username UTF8String], [password UTF8String]))
           == LIBSSH2_ERROR_EAGAIN);
    if (rc) {
        fprintf(stderr, "Authentication by password failed.\n");
        goto shutdown;
    }
    
    
    fprintf(stderr, "libssh2_sftp_init()!\n");
    do {
        _sftp_session = libssh2_sftp_init(_session);
        
        if(!_sftp_session) {
            if(libssh2_session_last_errno(_session) ==
               LIBSSH2_ERROR_EAGAIN) {
                fprintf(stderr, "non-blocking init\n");
                waitsocket(CFSocketGetNative(_socket), _session); /* now we wait */
            }
            else {
                fprintf(stderr, "Unable to init SFTP session\n");
                goto shutdown;
            }
        }
    } while (!_sftp_session);
    
    fprintf(stderr, "libssh2_sftp_open()!\n");
    /* Request a file via SFTP */
    do {
        _sftp_handle = libssh2_sftp_open(_sftp_session, sftppath,
                                         LIBSSH2_FXF_READ, 0);
        
        if (!_sftp_handle) {
            if (libssh2_session_last_errno(_session) != LIBSSH2_ERROR_EAGAIN) {
                fprintf(stderr, "Unable to open file with SFTP\n");
                goto shutdown;
            }
            else {
                fprintf(stderr, "non-blocking open\n");
                waitsocket(CFSocketGetNative(_socket), _session); /* now we wait */
            }
        }
    } while (!_sftp_handle);
    
    fprintf(stderr, "libssh2_sftp_open() is done, now receive data!\n");
    do {
        char mem[1024*24];
        
        /* loop until we fail */
        while ((rc = libssh2_sftp_read(_sftp_handle, mem,
                                       sizeof(mem))) == LIBSSH2SFTP_EAGAIN) {
            spin++;
            waitsocket(CFSocketGetNative(_socket), _session); /* now we wait */
        }
        if (rc > 0) {
            total += rc;
            write(1, mem, rc);
        } else {
            break;
        }
    } while (1);
    
    libssh2_sftp_close(_sftp_handle);
    libssh2_sftp_shutdown(_sftp_session);
    
shutdown:
    
    printf("libssh2_session_disconnect\n");
    while (libssh2_session_disconnect(_session,
                                      "Normal Shutdown, Thank you") ==
           LIBSSH2_ERROR_EAGAIN);
    libssh2_session_free(_session);
    
    CFSocketInvalidate(_socket);
    fprintf(stderr, "all done\n");
    
    libssh2_exit();
}

@end
