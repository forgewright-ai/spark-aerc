# spark-aerc -- spark inside aerc

spark (https://spark.forgewright.ai) is your own AI on your own machine.
This puts it under one key in aerc, the mail client: Alt-s on a mail --
in the list, or open -- shows the mail's header on a new tab, then
`spark> `:

    Enter              the overview: every line quotes the mail
    words              ask the mail; follow-ups ride the same thread
    ? words            the same ask
    q                  back to aerc (Ctrl-D too; Enter after an answer)
    Ctrl-C             never mind

A mail is someone else's text: spark answers about it, never acts on
it. When the mail does not hold the answer, the reply says so.

On the review screen -- after you write, before you send -- Alt-s asks
about your own draft: Enter is a review, words ask.

Writing mail: aerc opens your `$EDITOR`. If that is micro, neovim or vim
with its spark app, Alt-s is already there.

## Install

You need spark 1.46 or newer (`spark edit -h` says "held back") and
aerc 0.18 or newer, proven on 0.22 (`aerc -v`).

1. Clone this, and put the wrapper beside spark in `~/.local/bin`:

   ```sh
   git clone https://github.com/forgewright-ai/spark-aerc ~/.local/share/spark-aerc
   mkdir -p ~/.local/bin
   ln -s ~/.local/share/spark-aerc/spark-aerc ~/.local/bin/spark-aerc
   ```

2. Go to aerc's folder. On Linux:

   ```sh
   mkdir -p ~/.config/aerc && cd ~/.config/aerc
   ```

   On macOS:

   ```sh
   mkdir -p ~/Library/Preferences/aerc && cd ~/Library/Preferences/aerc
   ```

3. No `binds.conf` there yet? Start from aerc's own, so its keys stay.
   On Linux:

   ```sh
   cp /usr/share/aerc/binds.conf .
   ```

   On macOS:

   ```sh
   cp "$(brew --prefix)/share/aerc/binds.conf" .
   ```

4. Append the spark keys:

   ```sh
   cat ~/.local/share/spark-aerc/binds.spark >> binds.conf
   ```

5. Start aerc again. Alt-s on a mail opens `spark> `.

aerc merges a section named twice, so every key it had still works. An
update is `git -C ~/.local/share/spark-aerc pull`; when `binds.spark`
changed, delete the old spark lines from `binds.conf` and append again.
The keys, and what to ask: `CHEATSHEET.md`.

## What leaves this machine

The mail's text (its plain part, or its html part as text), your words,
and the subject as a name (60 characters at most) -- to the AI spark is
set up for. spark holds back the spans that look like secrets first: a
key, a token, a one-time code, a reset link. The model sees `[held]`,
and spark says how many it held. A long mail is read in parts: the
overview reads part 1, and says so.

The addresses in the headers, the attachments and the Message-ID stay
here; a hash of the Message-ID names the thread. The text itself is
sent as it is: a signature, or a forward pasted into it, goes with it.
For your own draft, the lines you quote (`>`) stay here: they are
someone else's text.

Every run is one call to `spark read` or `spark edit` with the text on
stdin: spark-aerc speaks no HTTP and hands no mail text to a shell.

## Contributing

`git config core.hooksPath .githooks` once; the hook keeps the tree free
of private names, ASCII, and `binds.spark` binds-only. `python3
tests/aerc_pty.py` drives a real aerc in a pty against a stub spark
(skips without aerc 0.18 or newer); `--live` asks your own spark.
Another app joins spark the same way this one does, in its own repo.

MIT. Credits in `CREDITS.md`. Built with Claude.
