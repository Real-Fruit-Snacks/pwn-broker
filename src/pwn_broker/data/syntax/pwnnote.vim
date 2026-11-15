" the pwn-broker note: a box at the top, then one fold per target
if exists('b:current_syntax')
  finish
endif
syntax sync fromstart

" IP addresses and <Placeholders> are coloured everywhere, the box and headings included
syntax match pwnnoteIP /\<\d\{1,3}\%(\.\d\{1,3}\)\{3}\%(\/\d\{1,2}\)\=\>/
syntax match pwnnotePlaceholder /<\a[0-9A-Za-z _-]*>/

" the box: from a rule line on line 1 to the next rule line, every line in it starting with #
syntax region pwnnoteBox matchgroup=pwnnoteRule start=/\%1l^#\{20,}\s*$/ end=/^#\{20,}\s*$/ end=/^\%(#\)\@!/ contains=pwnnoteBorder,pwnnoteIP,pwnnotePlaceholder
syntax match pwnnoteBorder /^#  \|  #\s*$\|^#\s*$/ contained

syntax match pwnnoteFoldMarker /##########@@@@@@@@@@\|@@@@@@@@@@##########/
syntax match pwnnoteHeading /^## .*$/ contains=pwnnoteIP,pwnnotePlaceholder
syntax match pwnnoteTitle /^Target:/

let b:current_syntax = 'pwnnote'
