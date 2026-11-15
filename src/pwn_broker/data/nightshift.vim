set background=dark
highlight clear
if exists('syntax_on') | syntax reset | endif
let g:colors_name = 'nightshift'

highlight Normal guifg=#E8E6E1 guibg=#0C0D10
highlight Comment guifg=#8A8F99 guibg=NONE gui=NONE
highlight LineNr guifg=#8A8F99 guibg=NONE gui=NONE
highlight NonText guifg=#8A8F99 guibg=NONE gui=NONE
highlight Folded guifg=#8A8F99 guibg=NONE gui=NONE

highlight Title guifg=#E8E6E1 guibg=NONE gui=bold
highlight markdownH1 guifg=#FF6A3D guibg=NONE gui=bold
highlight markdownH2 guifg=#E8E6E1 guibg=NONE gui=bold
highlight markdownH3 guifg=#E8E6E1 guibg=NONE gui=bold
highlight markdownH4 guifg=#E8E6E1 guibg=NONE gui=bold
highlight markdownH5 guifg=#E8E6E1 guibg=NONE gui=bold
highlight markdownH6 guifg=#E8E6E1 guibg=NONE gui=bold
highlight markdownHeadingDelimiter guifg=#E8E6E1 guibg=NONE gui=bold

highlight String guifg=#FFC247 guibg=#070809 gui=NONE
highlight markdownCode guifg=#FFC247 guibg=#070809 gui=NONE
highlight markdownCodeBlock guifg=#FFC247 guibg=#070809 gui=NONE

highlight Search guifg=#0C0D10 guibg=#FFC247 gui=NONE
highlight Visual guifg=NONE guibg=#1A1D24 gui=NONE
highlight StatusLine guifg=#E8E6E1 guibg=#13151A gui=NONE
highlight ErrorMsg guifg=#F06292 guibg=NONE gui=NONE
