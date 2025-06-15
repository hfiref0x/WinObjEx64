
## What is new in 1.8.0

 - **Plugins subsystem**

Subsystem that allows expand WinObjEx64 functionality without modifying main executable with maximum 20 plugins supported implemented as dlls.

 - **NDIS protocols viewer**

<img src="https://raw.githubusercontent.com/hfiref0x/WinObjEx64/master/Docs/Screenshots/NdisProtocols.png" width="600" />

Show basic information about registered NDIS protocols. Implemented as Sonar plugin, to use it administrative privilege and Windows Debug mode required.

 - **ApiSet viewer**

<img src="https://raw.githubusercontent.com/hfiref0x/WinObjEx64/master/Docs/Screenshots/ApiSetView.png" width="600" />

ApiSet viewer implemented as plugin. Can view current system apiset or parse and display apiset from apiset dll. Supports V2 (Windows 7), V4 (Windows 8+), V6 (Windows 10) apisets.

 - **Other**
 
  Run as LocalSystem feature improved (issue #14), compatibility improvements for upcoming Windows 10 20H1 release.
