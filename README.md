[![Build status](https://ci.appveyor.com/api/projects/status/dxsbgm90sahgwbo0?svg=true)](https://ci.appveyor.com/project/hfiref0x/winobjex64)

# WinObjEx64
## Windows Object Explorer 64-bit

<img src="https://raw.githubusercontent.com/hfiref0x/WinObjEx64/master/Screenshots/MainWindow.png" width="600" />

WinObjEx64 is an advanced utility that lets you explore the Windows Object Manager namespace. For certain object types, you can double-click on it or use the "Properties..." toolbar button to get more information, such as description, attributes, resource usage etc. WinObjEx64 let you view and edit object-related security information if you have required access rights.

# System Requirements

WinObjEx64 does not require administrative privileges. However administrative privilege is required to view much of the namespace and to edit object-related security information.


WinObjEx64 works only on the following x64 Windows: Windows 7, Windows 8, Windows 8.1 and Windows 10, including Server variants.

WinObjEx64 also supports running on Wine, including Wine Staging.


In order to use all program features Windows must be booted in the DEBUG mode.

# Build 

WinObjEx64 comes with full source code.
In order to build from source you need Microsoft Visual Studio 2013 U4 or Visual Studio 2015 and later versions.

## Instructions

* Select Platform ToolSet first for project in solution you want to build (Project->Properties->General): 
  * v120 for Visual Studio 2013;
  * v140 for Visual Studio 2015; 
  * v141 for Visual Studio 2017.
* For v140 and above set Target Platform Version (Project->Properties->General):
  * If v140 then select 8.1 (Note that Windows 8.1 SDK must be installed);
  * If v141 then select 10.0.17134.0 (Note that Windows 10.0.17134 SDK must be installed). 
 
# What is new

[Whats New in 1.8.0](https://github.com/hfiref0x/WinObjEx64/blob/master/Compiled/WHATSNEW_180.md)

[Complete changelog](https://github.com/hfiref0x/WinObjEx64/blob/master/Source/CHANGELOG.txt)

# Authors


(c) 2015 - 2019 WinObjEx64 Project

Original WinObjEx (c) 2003 - 2005 Four-F
