set background=dark
highlight clear
if exists('syntax_on') | syntax reset | endif
let g:colors_name = 'nightshift'

" Cyclorama Dawn LX 263: bg #050507, surface #0D0E12, raised #161820, text #F2F4F8, mute #8F95A6
highlight Normal guifg=#F2F4F8 guibg=#050507 gui=NONE
highlight Comment guifg=#8F95A6 guibg=NONE gui=NONE
highlight LineNr guifg=#8F95A6 guibg=NONE gui=NONE
highlight NonText guifg=#8F95A6 guibg=NONE gui=NONE
highlight EndOfBuffer guifg=#8F95A6 guibg=NONE gui=NONE
highlight Folded guifg=#F2F4F8 guibg=#161820 gui=NONE
highlight FoldColumn guifg=#8F95A6 guibg=NONE gui=NONE

highlight Search guifg=#050507 guibg=#FFC247 gui=NONE
highlight IncSearch guifg=#050507 guibg=#FFC247 gui=NONE
highlight Visual guifg=NONE guibg=#161820 gui=NONE
highlight StatusLine guifg=#F2F4F8 guibg=#0D0E12 gui=NONE
highlight StatusLineNC guifg=#8F95A6 guibg=#0D0E12 gui=NONE
highlight ErrorMsg guifg=#FF5C6C guibg=NONE gui=NONE

" the note
highlight pwnnoteIP guifg=#FFC247 guibg=NONE gui=NONE
highlight pwnnotePlaceholder guifg=#FF9254 guibg=NONE gui=NONE
highlight pwnnoteRule guifg=#8F95A6 guibg=NONE gui=NONE
highlight pwnnoteBorder guifg=#8F95A6 guibg=NONE gui=NONE
highlight pwnnoteFoldMarker guifg=#8F95A6 guibg=NONE gui=NONE
highlight pwnnoteHeading guifg=#F2F4F8 guibg=NONE gui=bold
highlight pwnnoteTitle guifg=#F2F4F8 guibg=NONE gui=bold
