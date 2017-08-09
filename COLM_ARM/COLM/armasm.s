.text
.global aesemc
aesemc:
	eor	v0.16b, v0.16b
	aese v1, v0.16b
	aesmc v1, v1
	aese v2, v0.16b
	aesmc v2, v2
	aese v3, v0.16b
	aesmc v3, v3
	aese v4, v0.16b
	aesmc v4, v4

.global aesemcsep
aesemcsep:
	eor	v0.16b, v0.16b
	aese v1, v0.16b
	aese v2, v0.16b
	aese v3, v0.16b
	aese v4, v0.16b
	aesmc v1, v1
	aesmc v2, v2
	aesmc v3, v3
	aesmc v4, v4

// extern void aesemc();
// extern void aesemcsep();
