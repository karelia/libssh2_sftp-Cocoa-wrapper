//
//  CK2SFTPFileHandle.m
//  Sandvox
//
//  Created by Mike on 03/07/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import "CK2SFTPFileHandle.h"

#import "CK2SFTPSession.h"


@implementation CK2SFTPFileHandle

- (id)initWithSFTPHandle:(LIBSSH2_SFTP_HANDLE *)handle session:(CK2SFTPSession *)session path:(NSString *)path;
{
    if (self = [self init])
    {
        _handle = handle;
        _session = [session retain];
        _path = [path copy];
    }
    
    return self;
}

- (void)closeFile; { [self closeFile:NULL]; }

- (BOOL)closeFile:(NSError **)error;
{
    BOOL result = YES;
    if (_handle)
    {
        result = (libssh2_sftp_close(_handle) == 0);
        
        if (result)
        {
            _handle = NULL;
            [_session release]; _session = nil;
        }
        else if (error)
        {
            *error = [_session performSelector:@selector(sessionErrorWithPath:) withObject:_path];
        }
    }
    
    return result;
}

- (void)dealloc;
{
    [self closeFile];
    [_session release]; _session = nil; // just in case closing failed
    
    [_path release];
    
    [super dealloc];
}

- (void)writeData:(NSData *)data;
{
    NSUInteger offset = 0;
    NSUInteger remainder = [data length];
    
    while (remainder)
    {
        const void *bytes = [data bytes];
        
        NSInteger written = [self write:bytes+offset maxLength:remainder];
        if (written < 0)
        {
            [NSException raise:NSFileHandleOperationException format:@"Failed to write to SFTP handle"];
        }
        
        offset+=written;
        remainder-=written;
    }
}

- (NSInteger)write:(const uint8_t *)buffer maxLength:(NSUInteger)length;
{
    /* write data in a loop until we block */
    NSInteger result = LIBSSH2SFTP_EAGAIN;
    while (result == LIBSSH2SFTP_EAGAIN)
    {
        result = libssh2_sftp_write(_handle, (const char *)buffer, length);
    }
    
    return result;
}

@end
