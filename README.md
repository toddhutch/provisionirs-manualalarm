# provisionirs-manualalarm
Trigger provision NVR manual alarm when on the local network with the NVR

Originally I setup the SDK and then used a rPi with wine to trigger the manual alarm.  That speed was 12-20+ seconds for execution.  This could happen anywhere as it used the NAT2.0 for access.

Since we have rPi next to our gates for monitoring if they are open for longer than 5 minutes we could use the local IP address instead and that meant we could speed it up. Less than 1 second
if the session and token are strill valid, caching that makes super fast.  Login/refresh still takes 6-8 seconds on a rPi Compute 4.

I'm sure you could make this work with the cloud provision ISR website, but I thought that might be abusive use, since this is for openning and closing the gate.

This would have not been needed if Provision would have provided a Linux SDK rather than a .Net with precompiled DLLs that require wine to work on Linux.  That was a mess to get working and days of effort.
