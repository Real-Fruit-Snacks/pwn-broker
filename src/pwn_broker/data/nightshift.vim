set background=dark
highlight clear
if exists('syntax_on') | syntax reset | endif
let g:colors_name = 'nightshift'

" page #0C0D10, surface #13151A, raised #1A1D24, text #E8E6E1, mute #8A8F99
highlight Normal guifg=#E8E6E1 guibg=#0C0D10 gui=NONE
highlight Comment guifg=#8A8F99 guibg=NONE gui=NONE
highlight LineNr guifg=#8A8F99 guibg=NONE gui=NONE
highlight NonText guifg=#8A8F99 guibg=NONE gui=NONE
highlight EndOfBuffer guifg=#8A8F99 guibg=NONE gui=NONE
highlight Folded guifg=#E8E6E1 guibg=#1A1D24 gui=NONE
highlight FoldColumn guifg=#8A8F99 guibg=NONE gui=NONE

highlight Search guifg=#0C0D10 guibg=#FFC247 gui=NONE
highlight IncSearch guifg=#0C0D10 guibg=#FFC247 gui=NONE
highlight Visual guifg=NONE guibg=#1A1D24 gui=NONE
highlight StatusLine guifg=#E8E6E1 guibg=#13151A gui=NONE
highlight StatusLineNC guifg=#8A8F99 guibg=#13151A gui=NONE
highlight ErrorMsg guifg=#F06292 guibg=NONE gui=NONE

" the note
highlight pwnnoteIP guifg=#FFC247 guibg=NONE gui=NONE
highlight pwnnotePlaceholder guifg=#FF6A3D guibg=NONE gui=NONE
highlight pwnnoteRule guifg=#8A8F99 guibg=NONE gui=NONE
highlight pwnnoteBorder guifg=#8A8F99 guibg=NONE gui=NONE
highlight pwnnoteFoldMarker guifg=#8A8F99 guibg=NONE gui=NONE
highlight pwnnoteHeading guifg=#E8E6E1 guibg=NONE gui=bold
highlight pwnnoteTitle guifg=#E8E6E1 guibg=NONE gui=bold
