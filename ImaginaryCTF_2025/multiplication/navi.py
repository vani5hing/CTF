for test in range(0, 0x100, 0x10):
	j = (test + 0x10) % 0x100
	print("start: ", hex(test), hex(j))
	for i in range(16):
		j = (j * 2) & 0xff
		print(hex(test), hex(j), i)
		if(j == test):
			print("!!!!")
