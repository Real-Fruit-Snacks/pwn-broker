" the pwn-broker note: a box at the top, then one fold per target
if exists('b:current_syntax')
  finish
endif
syntax sync fromstart
syntax case match

" IP addresses and <Placeholders> are coloured everywhere, the box and headings included.
" An address is four octets of 0 to 255 with an optional /0 to /32, and is not part of a longer
" run of digits and dots, so 1.2.3.4.5 and 999.999.999.999 stay plain.
let s:octet = '\%(25[0-5]\|2[0-4]\d\|1\d\d\|[1-9]\=\d\)'
execute 'syntax match pwnnoteIP /\%(\d\|\d\.\)\@<!' . s:octet . '\%(\.' . s:octet . '\)\{3}'
      \ . '\%(\/\%(3[0-2]\|[12]\=\d\)\)\=\%(\d\|\.\d\)\@!/'
unlet s:octet
" a placeholder starts with a capital letter and may hold single spaces between words: <Target Host>
syntax match pwnnotePlaceholder /<\u[0-9A-Za-z_-]*\%( [0-9A-Za-z_-]\+\)*>/

" the box: from a rule line on line 1 to the next rule line, every line in it starting with #
syntax region pwnnoteBox matchgroup=pwnnoteRule start=/\%1l^#\{20,}\s*$/ end=/^#\{20,}\s*$/ end=/^\%(#\)\@!/ contains=pwnnoteBorder,pwnnoteIP,pwnnotePlaceholder
syntax match pwnnoteBorder /^#  \|  #\s*$\|^#\s*$/ contained

syntax match pwnnoteFoldMarker /##########@@@@@@@@@@\|@@@@@@@@@@##########/
syntax match pwnnoteHeading /^## .*$/ contains=pwnnoteIP,pwnnotePlaceholder
syntax match pwnnoteTitle /^Target:/

let b:current_syntax = 'pwnnote'
