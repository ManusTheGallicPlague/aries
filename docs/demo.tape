# ARIES demo — recorded with vhs (https://github.com/charmbracelet/vhs)
#
# Reproduce:
#   python3 bench_vuln.py &      # local vulnerable fixture on 127.0.0.1:8099
#   vhs docs/demo.tape           # writes docs/demo.gif
#
# Every lane sends a real payload to the LOCAL fixture only (ALLOWLIST-bounded)
# and prints a VULNERABLE verdict with the exact curl that reproduces it.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1060
Set Height 720
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 35ms

Hide
Type "cd ~/aries && alias aries='python3 aries.py' && export PS1='❯ ' && clear" Enter
Show

Sleep 700ms
Type "# ARIES — facts from code, with the evidence attached. Every finding ships its PoC." Enter
Sleep 1s

Type "aries cors http://127.0.0.1:8099/cors-vuln" Enter
Sleep 2600ms

Type "aries attack http://127.0.0.1:8099/login-vuln" Enter
Sleep 2600ms

Type "aries redirect http://127.0.0.1:8099/redirect-vuln --param to" Enter
Sleep 3400ms
