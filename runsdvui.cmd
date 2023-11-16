cd /d "C:\Users\opq\source\repos\WDMDriver\WDMDriver" &msbuild "WDMDriver.vcxproj" /t:sdvViewer /p:configuration="Debug" /p:platform=x64
exit %errorlevel% 