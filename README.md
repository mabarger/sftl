# sftl - Simple FTL
This is a simple flash translation layer intended to be used for ZNS NVMe devices.

### Active zone status
To see the status of the zones during the tests you can enable the flag `DEBUG_ZONE_PRINT` in `src/ftl.h`. This will print the current zone states whenever the active log zone is full.
