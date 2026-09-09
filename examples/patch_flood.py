from pathlib import Path
p = Path("flood_all_tampered.o")
data = bytearray(p.read_bytes())
old=bytes.fromhex("18 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00")
new=bytes.fromhex("18 00 00 00 00 00 00 00 00 00 00 00 03 00 00 00")
idx=data.find(old)
if idx == -1:
	raise SystemExit("Pattern not found")
data[idx:idx+len(old)] = new
p.write_bytes(data)
print("Patched at file offset",idx)
