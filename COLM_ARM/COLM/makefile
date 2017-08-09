timing-arm: timing-arm.c
	aarch64-linux-gnu-gcc-5 -pipe -O3 -mcpu=cortex-a57+crypto -static -s -o $@ $^
	scp timing-arm phone:kristian/
