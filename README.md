# iosurface_uaf-ios

iOS/MacOS kernel double free due to IOSurfaceRootUserClient not respecting MIG ownership rules
I have previously detailed the lifetime management paradigms in MIG in the writeups for:
  [CVE-2016-7612](https://bugs.chromium.org/p/project-zero/issues/detail?id=926) and [CVE-2016-7633](https://bugs.chromium.org/p/project-zero/issues/detail?id=954) <br>
- If a MIG method returns `KERN_SUCCESS` it means that the method took ownership of *all* the arguments passed to it. <br>
- If a MIG method returns an error code, then it took ownership of *none* of the arguments passed to it. <br>
- If an IOKit userclient external method takes an async wake mach port argument then the lifetime of the reference
on that mach port passed to the external method will be managed by MIG semantics. <br>
- If the external method returns
an error then MIG will assume that the reference was not consumed by the external method and as such the MIG
generated coode will drop a reference on the port.
 
IOSurfaceRootUserClient external method 17 (s_set_surface_notify) will drop a reference on the wake_port
(via IOUserClient::releaseAsyncReference64) then return an error code if the client has previously registered
a port with the same callback function.
 
The external method's error return value propagates via the return value of is_io_connect_async_method back to the
MIG generated code which will drop a futher reference on the wake_port when only one was taken. <br>
This bug is reachable from the iOS app sandbox as demonstrated by this PoC. 
 
Tested on iOS 11.0.3 (11A432) on iPhone 6s (MKQL2CN/A) <br>
Tested on MacOS 10.13 (17A365) on MacBookAir5,2
