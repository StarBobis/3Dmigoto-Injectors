# Archived
HSR new version 2.1.0 add a fucking whitelist with GIMI's d3d11.dll and all other compiled 3dmigoto d3d11.dll 
can't inject into it anymore,i successly inject my compiled version with other inject way, but obviously two inject
way in this repository won't work if they only give a fucking whitelist to a specific dll by md5 check, so this repository
is deprecated , i will release and open source a fucking kernel driver to inject my d3d11.dll in my new project.

Fuck the hoyoverse.

# 3Dmigoto-Injectors
Special fork version of 3Dmigoto Loader.exe from original 3Dmigoto repository.

Mainly used to solve the problem that original 3Dmigoto injector can't work good on some game like HI3, HSR.

# How to use
just like the original 3Dmigoto Loader.exe, it need d3dx.ini to work.
- In Kinfe version added a method to automatically quit if can't verify inject feedback.
- In Deviare version, we use inject before ACE to bypass ACE's inject protector, run it will automatically start the game and
inject the d3d11.dll.

(Only tested in x64 version)

# Ask for help
https://discord.gg/Cz577BcRf5

# Why not work?
if injector can not work: 
- check if you have the administrator priviledge,if you don't it normally can't work.
- check if you put your 3dmigoto under game's installation folder,this may lead ACE's driver block your priviledge, yes, anti-cheat always kills your administrator priviledge.
- check your d3dx.ini, does it really configure right? are you sure?
- if Knife can't work, try deviare(by-pass-ace) one.
- if you think everything is right but still can't work, open an issue.

