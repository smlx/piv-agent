Generate sample ECC key like so

```
gpg --full-gen-key --expert
# select ECC sign only
# use e.g. Name: foo bar, Email: foo@example.com
```

Generate signing traces like so:

```
echo foo | strace -xs 1024 /usr/bin/gpg --verbose --status-fd=2 -bsau C54A8868468BC138 2> gpg-agent.sign.strace
# grep the agent socket
grep '(5' 
# reads
grep '^read' 
# writes
grep '^write' 
```

Export key for use in CI:
```
gpg --export -ao /tmp/C54A8868468BC138.asc foo@example.com
```
