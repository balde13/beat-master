import r2pipe

rlocal = r2pipe.open("/bin/ping") # Open ping in Radare2
strs = rlocal.cmd("iij") # Grab all imports used by binary ping in json format.
print(strs) # Print imports received.
