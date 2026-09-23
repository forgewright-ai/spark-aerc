#!/usr/bin/env python3
# aerc_pty.py -- the spark binds inside a real aerc, in a pty, against a
# stub `spark` (on PATH: the snippet and the wrapper say `spark` plainly,
# and that is what must be proven) that logs its argv and stdin and
# answers a fixed word. Proves the loop binds.spark promises: Alt-s on a
# mail opens spark-aerc on aerc's terminal tab (header, then spark>),
# Enter is `spark read`, words are `spark edit ? --source` on a thread
# named by a hash, the body travels decoded (html as text) and nothing
# else does -- no address, no Message-ID, no attachment -- a hostile
# subject draws inert, q returns to aerc, an older spark is refused
# before any call, and the review screen asks about your own draft.
#
# The test performs the README's install lines: binds.conf is aerc's own
# default with binds.spark appended, the wrapper linked onto PATH as
# shipped (no chmod here -- the repo file must already be executable).
# aerc runs on a throwaway -C/-A/-B (a maildir fixture, accounts.conf
# 0600) and HOME, never your own configuration. Skips (exit 0) without
# aerc 0.18 or newer (`:pipe -s`, `--no-ipc`; proven on 0.22).
#
#   python3 tests/aerc_pty.py            the stub
#   python3 tests/aerc_pty.py --live     your real spark answers (your
#                                        HOME for spark; aerc still on
#                                        the throwaway files)

import fcntl
import hashlib
import os
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLOOR = (0, 18)
CSI = re.compile(r"\x1b(?:\[[0-9;?<>=]*[ -/]*[@-~]|\([A-Za-z0-9]|\][^\x07\x1b]*(?:\x07|\x1b\\)|P[^\x1b]*\x1b\\|[@-Z\\-_])")
AT = "@"
LIVE = "--live" in sys.argv[1:]

STUB = r'''#!/bin/sh
# the stub spark: log argv (one NUL-ended arg each) and stdin, answer
# one word per verb -- STUB-READ for read, STUB-ASK for edit ?.
# `reveal` is the pass-through pacer; `edit -h` is the wrapper's probe
# (it says "held back" unless STUB_OLD is set). Neither is a turn, so
# neither touches the log.
case ${1-} in
    reveal) [ "${2-}" = "-h" ] && exit 0; exec cat ;;
esac
if [ "${1-}" = edit ] && [ "${2-}" = "-h" ]; then
    printf '  --source   ?: the text is a published source you discuss\n'
    [ -n "${STUB_OLD-}" ] || printf '               -- its secret-shaped spans are held back\n'
    exit 0
fi
printf '%s\n' "$*" >> "$STUB_LOG"
for a do printf '%s\0' "$a"; done > "$STUB_LOG.argv"
cat > "$STUB_LOG.stdin"
case " $* " in
    *" fail "*)   printf 'spark: STUB-REFUSAL -- the source does not answer\n' >&2; exit 1 ;;
    *" escape "*) printf '\033]0;pwned\007STUB-ESC\033[31m red\n'; exit 0 ;;
    *" bidi "*)   printf '\342\200\256STUB-BIDI\n'; exit 0 ;;
    *" split "*)  printf 'caf\303'; sleep 1; printf '\251 STUB-SPLIT\n'; exit 0 ;;
esac
case ${1-} in
    read) printf 'STUB-READ\n' ;;
    *)    printf 'STUB-ASK' ;;      # NO trailing newline: a raw stream
esac
'''

EDITOR = r'''#!/bin/sh
# the fake $EDITOR: writes a whole draft (headers too) and leaves
for f do :; done
printf 'From: Test <%s>\nTo: %s\nSubject: my draft\n\nDear team, the gate opens at nine.\n\nOn Monday, Alice <%s> wrote:\n> QUOTED-SECRET line one\n>> QUOTED-SECRET line two\n' "$DRAFT_FROM" "$DRAFT_FROM" "$DRAFT_FROM" > "$f"
'''

ADDRS = ["alice" + AT + "example.org", "bob" + AT + "example.org", "carol" + AT + "example.org",
         "no-reply" + AT + "example.org", "you" + AT + "example.com"]

PLAIN = ("From: Alice <%s>\nTo: Bob <%s>\nCc: Carol <%s>\nSubject: the gate report\n"
         "Date: Mon, 21 Sep 2026 09:00:00 +0000\nMessage-ID: <gate-1%sexample.org>\n"
         "Content-Type: text/plain; charset=utf-8\n\n"
         "The gate opens at nine and closes at noon.\nTickets are two dollars.\n"
         % (ADDRS[0], ADDRS[1], ADDRS[2], AT))
PLAIN_BODY = "The gate opens at nine and closes at noon.\nTickets are two dollars.\n"
PLAIN_MID = "<gate-1%sexample.org>" % AT

HTML = ("From: Alice <%s>\nTo: Bob <%s>\nSubject: the orchard news\n"
        "Date: Tue, 22 Sep 2026 09:00:00 +0000\nMessage-ID: <orchard-2%sexample.org>\n"
        "Content-Type: text/html; charset=utf-8\n\n"
        "<html><head><title>news</title><style>p { color: red }</style>"
        "<script>alert('x')</script></head><body><p>The orchard stall sells "
        "<b>cider</b> on weekends &amp; holidays.</p><div>Picnics by the gate.</div>"
        "</body></html>\n" % (ADDRS[0], ADDRS[1], AT))

# a subject that carries terminal escapes, encoded the way a hostile
# sender would (RFC 2047), a one-time code, a reset link, an attachment
HOSTILE = ("From: Service <%s>\nTo: %s\n"
           "Subject: =?utf-8?q?Your_code_=1B[31mred=1B[0m_and_=1B]0;pwned=07_inside_a_subject_that_goes_on_and_on_past_sixty?=\n"
           "Date: Wed, 23 Sep 2026 09:00:00 +0000\nMessage-ID: <code-3%sexample.org>\n"
           "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"b1\"\n\n"
           "--b1\nContent-Type: text/plain; charset=utf-8\n\n"
           "Your verification code is 482913.\n"
           "Reset your password: https://example.org/reset?token=AbCdEf0123456789xyz\n"
           "--b1\nContent-Type: application/pdf; name=\"invoice.pdf\"\n"
           "Content-Disposition: attachment; filename=\"invoice.pdf\"\n"
           "Content-Transfer-Encoding: base64\n\nJVBERi0xLjQKJUZBS0UK\n--b1--\n"
           % (ADDRS[3], ADDRS[4], AT))

# past 16000 chars: spark read takes it in parts, the overview part 1
LONG = ("From: Alice <%s>\nSubject: the long report\nMessage-ID: <long-4%sexample.org>\n"
        "Content-Type: text/plain; charset=utf-8\n\n" % (ADDRS[0], AT)
        + "".join("Line %05d of the long report, about the gate.\n" % i for i in range(500)))

# attachments only: no text to read
NOTEXT = ("From: Alice <%s>\nSubject: the scan\nMessage-ID: <scan-5%sexample.org>\n"
          "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"b2\"\n\n"
          "--b2\nContent-Type: image/png; name=\"scan.png\"\n"
          "Content-Disposition: attachment; filename=\"scan.png\"\n"
          "Content-Transfer-Encoding: base64\n\niVBORw0KGgo=\n--b2--\n" % (ADDRS[0], AT))

# no Message-ID, and slashes in the subject
NOMID = ("From: Alice <%s>\nSubject: q3/q4 plan \\ draft\n"
         "Content-Type: text/plain; charset=utf-8\n\nThe plan moves the gate to ten.\n" % ADDRS[0])
NOMID_BODY = "The plan moves the gate to ten.\n"

FIXTURES = {"plain": PLAIN, "html": HTML, "hostile": HOSTILE, "long": LONG, "notext": NOTEXT, "nomid": NOMID}


class Term:
    def __init__(self, argv, env, cwd, rows=30, cols=100):
        self.buf = b""
        self.pos = 0
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(cwd)
            os.execvpe(argv[0], argv, env)
        self.pid, self.fd = pid, fd
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def read(self, timeout):
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    return
                if not data:
                    return
                self.buf += data

    def raw(self):
        return self.buf[self.pos:].decode("utf-8", "replace")

    def plain(self):
        """what was drawn since mark(), with the escape sequences removed"""
        return CSI.sub("", self.raw())

    def expect(self, text, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            if text in self.plain():
                return True
            self.read(0.2)
        return False

    def send(self, s):
        os.write(self.fd, s.encode())
        time.sleep(0.3)

    def mark(self):
        self.pos = len(self.buf)

    def close(self):
        try:
            os.kill(self.pid, 15)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass


def aerc_version(aerc):
    p = subprocess.run([aerc, "-v"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    m = re.search(r"aerc (\d+)\.(\d+)", p.stdout.decode("utf-8", "replace"))
    return (int(m.group(1)), int(m.group(2))) if m else None


def default_binds(aerc):
    """aerc's own binds.conf, as its package installs it."""
    seen = []
    for exe in (aerc, os.path.realpath(aerc)):
        seen.append(os.path.join(os.path.dirname(os.path.dirname(exe)), "share", "aerc", "binds.conf"))
    seen += ["/usr/share/aerc/binds.conf", "/usr/local/share/aerc/binds.conf"]
    for p in seen:
        if os.path.isfile(p):
            return p
    return None


def maildir(root, name, text):
    d = os.path.join(root, name, "INBOX")
    for sub in ("cur", "new", "tmp"):
        os.makedirs(os.path.join(d, sub))
    with open(os.path.join(d, "cur", "1.M1P1.fixture:2,S"), "w") as f:
        f.write(text)
    return os.path.join(root, name)


def main():
    aerc = shutil.which("aerc")
    if not aerc:
        print("aerc_pty: aerc is not installed here -- skipped (pacman -S aerc / brew install aerc)")
        return 0
    ver = aerc_version(aerc)
    if not ver or ver < FLOOR:
        print("aerc_pty: aerc %s here, the snippet needs %d.%d or newer (proven on 0.22) -- skipped"
              % (".".join(map(str, ver)) if ver else "(unknown)", FLOOR[0], FLOOR[1]))
        return 0
    binds_default = default_binds(aerc)
    if not binds_default:
        print("aerc_pty: aerc's own binds.conf was not found beside it -- skipped")
        return 0
    help_text = subprocess.run([aerc, "-h"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
    noipc = ["-I"] if b"--no-ipc" in help_text else []
    if LIVE and not shutil.which("spark"):
        print("aerc_pty --live: no spark on PATH")
        return 1
    fail = 0

    def ok(cond, what, extra=""):
        nonlocal fail
        print("  %s %s%s" % ("ok  " if cond else "FAIL", what, ("   " + extra) if extra and not cond else ""))
        if not cond:
            fail += 1

    with tempfile.TemporaryDirectory(prefix="spark-aerc-") as tmp:
        tmp = os.path.realpath(tmp)
        home, bindir, work = [os.path.join(tmp, d) for d in ("home", "bin", "work")]
        for d in (home, bindir, work):
            os.makedirs(d)
        # the README's install, performed: aerc's own binds.conf with the
        # snippet appended, the wrapper linked onto PATH as shipped
        binds = os.path.join(tmp, "binds.conf")
        shutil.copyfile(binds_default, binds)
        with open(os.path.join(REPO, "binds.spark")) as f:
            snippet = f.read()
        with open(binds, "a") as f:
            f.write("\n" + snippet)
        os.symlink(os.path.join(REPO, "spark-aerc"), os.path.join(bindir, "spark-aerc"))
        if not LIVE:
            with open(os.path.join(bindir, "spark"), "w") as f:
                f.write(STUB)
            os.chmod(os.path.join(bindir, "spark"), 0o755)
        editor = os.path.join(bindir, "fake-editor")
        with open(editor, "w") as f:
            f.write(EDITOR)
        os.chmod(editor, 0o755)
        conf = os.path.join(tmp, "aerc.conf")
        with open(conf, "w") as f:
            # cat, not less, as the pager and filter: a minimal system
            # (the Arch container, a fresh box) may not have less
            f.write("[viewer]\npager=cat\n\n[filters]\ntext/plain=cat\n\n"
                    "[compose]\neditor=%s\nedit-headers=true\n" % editor)
        accounts = {}
        for name, text in sorted(FIXTURES.items()):
            root = maildir(os.path.join(tmp, "mail"), name, text)
            p = os.path.join(tmp, "accounts-%s.conf" % name)
            with open(p, "w") as f:
                f.write("[%s]\nsource = maildir://%s\nfrom = Test <%s>\ndefault = INBOX\n" % (name, root, ADDRS[4]))
            os.chmod(p, 0o600)
            accounts[name] = p
        log = os.path.join(tmp, "stub.log")
        env = {"HOME": home, "TERM": "xterm-256color",
               "PATH": bindir + ":" + os.environ.get("PATH", "/usr/bin:/bin"),
               "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "STUB_LOG": log, "DRAFT_FROM": ADDRS[4]}
        if LIVE:
            env["HOME"] = os.environ.get("HOME", home)
            for k in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "USER"):
                if k in os.environ:
                    env[k] = os.environ[k]

        def logged():
            try:
                with open(log) as f:
                    return f.read()
            except OSError:
                return ""

        def argv_of():
            try:
                with open(log + ".argv", "rb") as f:
                    return [a.decode("utf-8", "replace") for a in f.read().split(b"\0")[:-1]]
            except OSError:
                return []

        def stdin_of():
            try:
                with open(log + ".stdin", encoding="utf-8") as f:
                    return f.read()
            except OSError:
                return ""

        def fresh(which, subject, extra_env=None):
            for p in (log, log + ".argv", log + ".stdin"):
                if os.path.exists(p):
                    os.unlink(p)
            # each run starts from its fixture as written: a stray key in
            # an earlier run (a is :archive) cannot move the mail away
            shutil.rmtree(os.path.join(tmp, "mail", which))
            maildir(os.path.join(tmp, "mail"), which, FIXTURES[which])
            e = dict(env)
            e.update(extra_env or {})
            t = Term([aerc] + noipc + ["-C", conf, "-A", accounts[which], "-B", binds], e, work)
            ok(t.expect(subject, 20), "aerc draws the %s mail in the list" % which, t.plain()[-300:])
            t.mark()
            return t

        def leaks(text):
            return [a for a in ADDRS if a in text] + [m for m in (PLAIN_MID, "gate-1", "code-3", "orchard-2") if m in text]

        if LIVE:
            # your spark answers: fixture 3's code and reset link are held
            # back before they leave, and the held line shows on screen
            t = fresh("hostile", "Your code")
            t.mark()
            t.send("\x1bs")
            ok(t.expect("spark>", 15), "Alt-s opens spark> (live)", t.plain()[-300:])
            t.mark()
            t.send("what is this mail asking me to do\r")
            ok(t.expect("held back", 180), "spark says it held spans back", t.plain()[-400:])
            ok(t.expect("spark>", 240), "an answer, then spark> again", t.plain()[-400:])
            print("  ---- the answer, as drawn:\n" + "\n".join("  | " + l for l in t.plain().strip().splitlines()[-12:]))
            t.send("q\r")
            t.close()
            print("aerc_pty --live: %s" % ("all ok" if not fail else "%d FAILED" % fail))
            return 1 if fail else 0

        # A. Alt-s on the list: the tab opens with the header, then spark>
        t = fresh("plain", "the gate report")
        t.mark()
        t.send("\x1bs")
        ok(t.expect("spark>", 15), "Alt-s on the list opens spark>", t.plain()[-300:])
        ok("From: Alice" in t.plain() and "Date: Mon, 21 Sep 2026" in t.plain() and "the gate report" in t.plain(),
           "the header stands above the prompt: subject, From, Date", t.plain()[-400:])
        ok("Enter: the overview" in t.plain(), "the prompt's keys are on screen", t.plain()[-300:])
        ok(not os.path.exists(log), "opening the room calls nothing")

        # B. Enter alone is the overview: spark read, the decoded body on
        # stdin, the subject as the name, and nothing else of the mail
        t.mark()
        t.send("\r")
        ok(t.expect("STUB-READ", 15), "Enter alone is the overview: the answer shows", t.plain()[-300:])
        ok(argv_of() == ["read", "--name", "the gate report"], "spark read got the name and nothing else", repr(argv_of()))
        ok(stdin_of() == PLAIN_BODY, "the decoded body travelled on stdin, exactly", repr(stdin_of()))
        ok(not leaks(logged() + stdin_of()), "no address, no Message-ID reaches spark", repr(leaks(logged() + stdin_of())))
        ok(tmp not in logged() + stdin_of(), "no path reaches spark")

        # C. words: spark edit ? --source on the mail's thread; a
        # follow-up rides the same thread; a leading ? is the same ask
        t.mark()
        t.send("does it name a --thread price\r")
        ok(t.expect("STUB-ASK", 15), "words ask: the answer shows", t.plain()[-300:])
        want = "aerc-" + hashlib.sha256(PLAIN_MID.encode()).hexdigest()[:16]
        a = argv_of()
        ok(a == ["edit", "?", "--source", "--thread", want, "--about", "an e-mail",
                 "--name", "the gate report", "--", "does it name a --thread price"],
           "spark edit ? --source --thread aerc-<hash> --about --name -- WORDS", repr(a))
        ok(not leaks(logged() + stdin_of()), "the ask sends no address, no Message-ID")
        t.mark()
        t.send("? and the hours\r")
        t.expect("STUB-ASK", 15)
        a2 = argv_of()
        ok(a2[:3] == ["edit", "?", "--source"] and a2[-2:] == ["--", "and the hours"] and want in a2,
           "a follow-up (a leading ? too) rides the same thread", repr(a2))
        # a question that looks like a flag stays a question: after --,
        # and spaced off its dash
        for flag in ("--decline", "--type"):
            t.mark()
            t.send(flag + "\r")
            t.expect("STUB-ASK", 15)
            a3 = argv_of()
            ok(a3[-2:] == ["--", " " + flag] and flag not in a3 and "--source" in a3[:a3.index("--")],
               "a question of %s is a word, never a flag; --source stands" % flag, repr(a3))
        # the answer is drawn clean: no bidi override, a character split
        # across two reads whole
        t.mark()
        t.send("bidi\r")
        ok(t.expect("STUB-BIDI", 15), "an answer arrives", t.plain()[-300:])
        ok("\u202e" not in t.raw(), "a bidi override in the answer is dropped", repr(t.raw()[-200:]))
        t.mark()
        t.send("split\r")
        ok(t.expect("STUB-SPLIT", 15), "a slow answer arrives", t.plain()[-300:])
        ok("\u00e9" in t.raw() and "\ufffd" not in t.raw(),
           "a character split across two reads is drawn whole", repr(t.raw()[-300:]))
        # a refusal on spark's stderr shows where the answer would be
        t.mark()
        t.send("fail\r")
        ok(t.expect("STUB-REFUSAL", 15), "spark's stderr is folded into the answer", t.plain()[-300:])

        # F. q returns to aerc and never reaches spark; the list is back
        n = len(logged().splitlines())
        t.mark()
        t.send("q\r")
        time.sleep(1.0)
        ok(len(logged().splitlines()) == n, "q runs nothing")
        t.mark()
        t.send("\x1bs")
        ok(t.expect("spark>", 15), "the tab closed: Alt-s works again from the list", t.plain()[-300:])
        t.send("\x04")          # Ctrl-D leaves too
        time.sleep(1.0)
        t.mark()
        t.send("\x1bs")
        ok(t.expect("spark>", 15), "Ctrl-D left: Alt-s opens spark> again", t.plain()[-300:])
        t.mark()
        t.send("half a question\x03")   # Ctrl-C: never mind
        ok(t.expect("the gate report", 15), "Ctrl-C closes the tab: the list is back", t.plain()[-300:])
        ok(len(logged().splitlines()) == n, "Ctrl-C runs nothing")
        time.sleep(0.5)
        t.mark()
        t.send("\r")            # aerc's own Enter: the viewer
        ok(t.expect("closes at noon", 15), "aerc's own keys still work (Enter opens the viewer)", t.plain()[-300:])
        t.mark()
        t.send("\x1bs")
        ok(t.expect("spark>", 15), "Alt-s in the viewer opens spark> too", t.plain()[-300:])
        t.send("q\r")
        t.close()

        # D. an html-only mail travels as text: no tags, no script, no style
        t = fresh("html", "the orchard news")
        t.mark()
        t.send("\x1bs")
        t.expect("spark>", 15)
        t.send("\r")
        t.expect("STUB-READ", 15)
        s = stdin_of()
        ok("The orchard stall sells cider on weekends & holidays." in s and "Picnics by the gate." in s,
           "the html body arrives as its text", repr(s))
        ok("<" not in s and "alert" not in s and "color" not in s and "news\n" not in s,
           "no tag, script, style or title reaches spark", repr(s))
        t.send("q\r")
        t.close()

        # E. the hostile mail: the subject's escapes draw inert, the code
        # and link travel as the body (spark holds them back -- --live
        # proves that), the attachment never travels, the name is capped
        t = fresh("hostile", "Your code")
        t.mark()
        t.send("\x1bs")
        ok(t.expect("spark>", 15), "Alt-s opens spark> on the hostile mail", t.plain()[-300:])
        shown = t.plain()
        ok("[31mred" in shown and "]0;pwned" in shown,
           "the subject's escapes are drawn as text, not obeyed", repr(shown[-400:]))
        ok("1 attachment, not read" in shown, "the attachment is counted, not read", shown[-300:])
        t.mark()
        t.send("escape\r")
        ok(t.expect("STUB-ESC", 15), "an answer arrives", t.plain()[-300:])
        # aerc redraws only the cells that change, so match the SGR the
        # stub sent after its word: drawn as text only if its ESC is gone
        after = t.plain()[t.plain().find("STUB-ESC"):][:30]
        ok("[31m" in after and "\x1b]0;pwned" not in t.raw(),
           "an escape in spark's answer is drawn as text, not obeyed", repr(t.raw()[-300:]))
        s, a = stdin_of(), argv_of()
        ok("482913" in s and "reset?token=" in s, "the body travels to spark whole (spark holds secrets back)", repr(s))
        ok("invoice" not in s and "JVBERi0" not in s and not any("invoice" in x for x in a),
           "the attachment never travels", repr(s))
        ok(not leaks(logged() + s), "no address, no Message-ID reaches spark")
        name = a[a.index("--name") + 1] if "--name" in a else ""
        ok(0 < len(name) <= 60 and "\x1b" not in name and "\x07" not in name and name.startswith("Your code"),
           "the subject as a name: inert, 60 chars at most", repr(name))
        ok(not any("\x1b" in x or "\x07" in x for x in a), "no control character in any argument", repr(a))
        t.send("q\r")
        t.close()

        # G. a spark that does not hold a source's secrets back is refused
        # before any call: one line, a key returns to aerc
        t = fresh("plain", "the gate report", {"STUB_OLD": "1"})
        t.mark()
        t.send("\x1bs")
        ok(t.expect("needs spark 1.46 or newer", 15), "an older spark is refused, and says why", t.plain()[-300:])
        ok("spark>" not in t.plain(), "no prompt is offered")
        t.send(" ")
        time.sleep(1.0)
        ok(not os.path.exists(log), "nothing was sent to the older spark")
        t.mark()
        t.send("\x1bs")
        ok(t.expect("needs spark", 15), "a key returned to aerc (Alt-s answers again)", t.plain()[-300:])
        t.send(" ")
        t.close()

        # H. the review screen: Alt-s asks about your own draft -- no
        # --source, Enter is a review, the draft's body alone travels
        t = fresh("plain", "the gate report")
        t.send("C")                 # aerc's compose; the fake editor writes and leaves
        ok(t.expect("Send", 20), "the draft reaches the review screen", t.plain()[-400:])
        ok("spark" in t.plain(), "the review screen lists the spark key", t.plain()[-400:])
        t.mark()
        t.send("\x1bs")
        ok(t.expect("spark>", 15), "Alt-s on the review screen opens spark>", t.plain()[-400:])
        ok("your draft: my draft" in t.plain(), "the room says it is your draft", t.plain()[-300:])
        t.send("\r")
        ok(t.expect("STUB-ASK", 15), "Enter is a review of the draft", t.plain()[-300:])
        a = argv_of()
        ok(a[:2] == ["edit", "?"] and "--source" not in a and "--about" in a and "--thread" in a
           and a[a.index("--name") + 1] == "my draft",
           "spark edit ? on the draft: no --source, the author's review", repr(a))
        ok("Dear team, the gate opens at nine." in stdin_of() and not leaks(stdin_of() + logged()),
           "the draft's own text travels, no address", repr(stdin_of()))
        ok("QUOTED-SECRET" not in stdin_of() and "wrote:" not in stdin_of(),
           "the quoted lines, and the line that opens them, stay here", repr(stdin_of()))
        ok("quoted lines stay here" in t.plain(), "the room says quoted lines stay here", t.plain()[-400:])
        t.send("q\r")
        time.sleep(1.0)
        t.send("n")                 # aerc's review: abort the draft
        t.close()

        # I. a mail past 16000 chars: the overview asks for part 1, and
        # the room says so
        t = fresh("long", "the long report")
        t.mark()
        t.send("\x1bs")
        ok(t.expect("part 1 of 2", 15), "a long mail says the overview reads part 1 of 2", t.plain()[-300:])
        t.send("\r")
        t.expect("STUB-READ", 15)
        ok(argv_of() == ["read", "--part", "1", "--name", "the long report"],
           "spark read --part 1 on a long mail", repr(argv_of()))
        t.send("q\r")
        t.close()

        # J. a mail with no text part: said, and nothing is called
        t = fresh("notext", "the scan")
        t.mark()
        t.send("\x1bs")
        ok(t.expect("no text to read", 15), "a mail with no text says so", t.plain()[-300:])
        ok("spark>" not in t.plain(), "no prompt is offered for it")
        t.send(" ")
        time.sleep(1.0)
        ok(not os.path.exists(log), "nothing was sent for it")
        t.close()

        # K. no Message-ID: a fresh thread (never a hash of the text) that
        # follow-ups still ride; a slash in the subject becomes a dash
        t = fresh("nomid", "q3/q4 plan")
        t.mark()
        t.send("\x1bs")
        t.expect("spark>", 15)
        t.send("when\r")
        t.expect("STUB-ASK", 15)
        a = argv_of()
        tid = a[a.index("--thread") + 1] if "--thread" in a else ""
        ok(re.match(r"^aerc-[0-9a-f]{16}$", tid) is not None
           and tid[5:] != hashlib.sha256(NOMID_BODY.encode()).hexdigest()[:16],
           "no Message-ID: a fresh thread, not a hash of the text", repr(a))
        ok(a[a.index("--name") + 1] == "q3-q4 plan - draft", "slashes in the subject become dashes", repr(a))
        t.mark()
        t.send("and why\r")
        t.expect("STUB-ASK", 15)
        ok(tid in argv_of(), "a follow-up rides that thread", repr(argv_of()))
        t.send("q\r")
        t.close()

        ok(not os.path.exists(os.path.join(REPO, "stub.log")), "the repo tree is untouched")

    print("aerc_pty: %s" % ("all ok" if not fail else "%d FAILED" % fail))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
