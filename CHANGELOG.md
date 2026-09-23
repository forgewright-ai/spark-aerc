# Changelog

## 1.0.0

- spark in aerc: Alt-s on a mail (the list or the viewer) opens
  `spark> ` on a new tab under the mail's header. Enter is the overview
  (`spark read`); words ask (`spark edit ? --source`, on a thread named
  by a hash of the Message-ID, so follow-ups ride it).
- Alt-s on the compose review screen asks about your own draft: Enter
  is a review, words ask.
- The mail's text goes to spark alone -- the plain part, or the html
  part as text -- with your words and the subject as a name (60
  characters at most, slashes made dashes). The header is drawn with
  its control characters removed, so a subject cannot drive the
  terminal; so is the answer, bidi overrides too. A draft's quoted
  lines stay here. The question always travels after `--`, so a
  question cannot become a flag.
- A long mail's overview reads part 1 and says so; a mail with no text
  says so and calls nothing.
- Needs spark 1.46 or newer, which holds a source's secret-shaped spans
  back before they leave; an older spark is refused before any call.
  Needs aerc 0.18 or newer (`:pipe -s`), proven on 0.22.
- The pty test (`tests/aerc_pty.py`) drives a real aerc against a stub
  spark; CI runs it on Ubuntu, Arch and macOS, and it skips where the
  packaged aerc is older than 0.18.
