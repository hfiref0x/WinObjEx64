echo ----------------------------------------------
echo %1 post-build script
echo ----------------------------------------------

echo Copy %2 to Bin\Plugins
copy %2 ..\..\Bin\plugins /y

echo Copy %2 to WinObjEx64\Plugins [DEBUG]
copy %2 ..\..\WinObjEx64\plugins /y

IF EXIST %3 (
    Echo Copy %3 to WinObjEx64\Plugins [DEBUG]
    copy %3 ..\..\WinObjEx64\plugins /y 
 ) ELSE ( 
    echo %3 pdb file was not found, skipping
 )
