# aerc with spark -- the cheatsheet

aerc reads and sends your mail; spark reads it with you. Section 1 is
aerc on its own, section 2 is the one key that puts your own AI inside
it.

The key spellings here are aerc's: `<C-n>` means hold Ctrl and press n;
Alt-s means hold Alt and press s (on a Mac, Option -- when the terminal
sends Option as Meta; spark's Terminal profile does). Keys are
case-sensitive: `C` is Shift-c.

## 1. aerc, the basics

The message list

    j  k           next, previous mail
    Enter          open the mail
    /              search; n and N step through the results
    J  K           next, previous folder
    q              quit (aerc asks first)

A mail, open

    q              back to the list
    rr             reply to all;  Rr  reply to the sender
    f              forward
    o              open a part (an attachment) with its program

Writing

    C              a new mail: aerc opens your $EDITOR
    then           y sends, e edits again, p postpones, q asks

Tabs and help

    <C-n>  <C-p>   next, previous tab
    ?              the keys for the screen you are on
    :              any aerc command; :q quits

## 2. the mail, with spark

Alt-s on a mail -- in the list, or open -- shows its header on a new
tab, then `spark> `. q brings aerc back exactly as it was.

    Enter          the overview: every line quotes the mail
    words          ask the mail; follow-ups ride the same thread
    ? words        the same ask
    q              back to aerc (Ctrl-D too; Enter after an answer)
    Ctrl-C         never mind

On the review screen -- after you write, before you send:

    Alt-s Enter    a review of your draft
    Alt-s words    ask about your draft

By example

    a long thread      Alt-s Enter
                       the overview, before you read it all
    a request          Alt-s what are they asking me to do
    a date             Alt-s when is the deadline
    a reply to write   Alt-s ? which questions do I need to answer
    before you send    Alt-s on the review screen: is the tone right

A mail is someone else's text: spark answers about it, never acts on
it. Spans that look like secrets -- a one-time code, a reset link -- are
held back before the mail leaves; the model sees `[held]`.

Writing the mail itself happens in your `$EDITOR`: micro, neovim and
vim have their own spark apps, with the same Alt-s.
