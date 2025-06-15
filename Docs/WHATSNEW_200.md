
## What is new in 2.0.0

 - **CmControlVector viewer**

<img src="https://raw.githubusercontent.com/hfiref0x/WinObjEx64/master/Docs/Screenshots/CmControlVector.png" width="600" />

View contents of CmControlVector ntoskrnl parameters array. Can display actual values of variables or dump them when driver support is enabled.

 - **Other**
   + Added entirely new handling of object names to support embedded nulls
   + Added Pico providers, Nmi, SiloMonitor and Errata manager callbacks
   + Added Copy Name/Copy Name (Binary) commands to the main window popup menus
   + Added program statistics (see Help->Statistics)
   + Added legend window description for process list
   + Added ability to fix image sections for dumped drivers
   + Added RegistryTransaction object view and access rights
   + Moved "Globals" from about box to the View->System Information and rearranged it output
   + Drivers dump operation can now be cancelled
   + Fix display of PUNICODE_STRING dump
   + Fix ALPC Port type objects sometimes unable to open while they can be opened
   + Plugin sdk updated to accommodate new named objects handling 
   + Imagescope plugin updated to accomodate plugin sdk changes
   + Elevation required features in "extras" will now request elevation instead of just been disabled
   + Help file updated with drivers and symbols usage
   + Internal rearrange and minor UI changes
