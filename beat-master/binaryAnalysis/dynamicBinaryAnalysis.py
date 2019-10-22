import r2pipe

"""
HOW TO USE THIS SCRIPT:

 step 1. Open terminal in current directory and run 'python3 dynamicBinaryAnalysis.py'
 step 2. Open new terminal in current directory and run './client.out 127.0.0.1 12345'
 step 3. When prompted from client.out type a message.
 step 4. See message that was received by dynamicBinaryAnalysis.py
 step 5. type 'exit' into client.out terminal to clean up sockets and quit client.out
"""

r2 = r2pipe.open("server.out") # Open server chat program using radare2.
r2.cmd("aaa") # Perform analysis on server.out so we can find the recv function location.
r2.cmd("doo 12345") # reopen server chat in debug mode and pass in port to listen on.

all_recvs = r2.cmdj("axtj sym.imp.recv") # Find all references to recv in the binary



# Loop over all recv memory locations and add a breakpoint.
for i in range(len(all_recvs)):
    r2breakpoint = 'db ' + hex(all_recvs[i]["from"]) # Create r2 command to add breakpoint
    r2.cmd(r2breakpoint) # Tell r2 to add a breakpoint at recv locations.

while True:

    r2.cmd("dc") # Tell r2 to continue until it hits the breakpoint.

    r2.cmd("dso") # Tell r2 to execute over the recv call.

    messageAddr = r2.cmd("dr rsi") # Memory location to what recv received is in register rsi.

    lookInBuff = "pxj @" + messageAddr # create command to get contents of memory where recv received a message.

    messageArr = r2.cmdj(lookInBuff) # get contents of memory where recv received a message.

    byteStr = "" # variable that will hold hex values of message

    # Loop over byte array and remove each hex value (ie each letter sent in message)
    for i in range(len(messageArr)):

        # If found 0 byte...then is end of message in memory.
        if messageArr[i] == 0:
            break
        # building byte string.
        byteStr = byteStr + str(hex(messageArr[i]))[2:] + " "

    break

# Print message found in binary.
print("Message found in binary: " + bytearray.fromhex(byteStr).decode())
