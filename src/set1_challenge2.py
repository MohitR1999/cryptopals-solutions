inp = input()
target = input()
op = ""

for i in range(0, len(inp)):
    op += hex(int(inp[i], 16) ^ int(target[i], 16))[2:]
    
print(op)