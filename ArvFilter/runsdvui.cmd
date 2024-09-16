cd /d "D:\VSProjects\ArvKit\ArvFilter" &msbuild "ArvFilter.vcxproj" /t:sdvViewer /p:configuration="Release" /p:platform="x64" /p:SolutionDir="D:\VSProjects\ArvKit" 
exit %errorlevel% 