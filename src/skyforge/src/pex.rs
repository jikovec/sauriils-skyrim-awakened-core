//! Skyrim compiled Papyrus (.pex, big-endian, format 3.x) reader/writer with exact round-trip,
//! a disassembler for review, and narrowly scoped, pattern-checked patches.
//!
//! A patch never guesses: if the expected instruction pattern is not found exactly, it refuses.

use anyhow::{anyhow, bail, Context, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum Var {
    Null,
    Ident(u16),
    Str(u16),
    Int(i32),
    Float(u32), // raw bits, for exact round-trip
    Bool(u8),
}

#[derive(Debug, Clone)]
pub struct Instr {
    pub op: u8,
    pub args: Vec<Var>, // for variadic ops: fixed args, then Int(count), then the extra args
}

#[derive(Debug, Clone)]
pub struct Function {
    pub return_type: u16,
    pub docstring: u16,
    pub user_flags: u32,
    pub flags: u8,
    pub params: Vec<(u16, u16)>,
    pub locals: Vec<(u16, u16)>,
    pub code: Vec<Instr>,
}

#[derive(Debug, Clone)]
pub struct Property {
    pub name: u16,
    pub type_name: u16,
    pub docstring: u16,
    pub user_flags: u32,
    pub flags: u8,
    pub auto_var: Option<u16>,
    pub read: Option<Function>,
    pub write: Option<Function>,
}

#[derive(Debug, Clone)]
pub struct State {
    pub name: u16,
    pub functions: Vec<(u16, Function)>,
}

#[derive(Debug, Clone)]
pub struct Object {
    pub name: u16,
    pub size_includes_field: bool,
    pub parent: u16,
    pub docstring: u16,
    pub user_flags: u32,
    pub auto_state: u16,
    pub variables: Vec<(u16, u16, u32, Var)>,
    pub properties: Vec<Property>,
    pub states: Vec<State>,
}

#[derive(Debug, Clone)]
pub struct DebugFn {
    pub object: u16,
    pub state: u16,
    pub function: u16,
    pub ftype: u8,
    pub lines: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct Pex {
    pub major: u8,
    pub minor: u8,
    pub game_id: u16,
    pub compile_time: u64,
    pub source: Vec<u8>,
    pub user: Vec<u8>,
    pub machine: Vec<u8>,
    pub strings: Vec<Vec<u8>>,
    pub debug: Option<(u64, Vec<DebugFn>)>,
    pub user_flags: Vec<(u16, u8)>,
    pub objects: Vec<Object>,
}

const MAGIC: u32 = 0xFA57_C0DE;

/// Fixed argument counts for Skyrim opcodes 0x00..=0x23; variadic ops add an Int count + args.
fn op_info(op: u8) -> Result<(usize, bool, &'static str)> {
    Ok(match op {
        0x00 => (0, false, "nop"),
        0x01 => (3, false, "iadd"),
        0x02 => (3, false, "fadd"),
        0x03 => (3, false, "isub"),
        0x04 => (3, false, "fsub"),
        0x05 => (3, false, "imul"),
        0x06 => (3, false, "fmul"),
        0x07 => (3, false, "idiv"),
        0x08 => (3, false, "fdiv"),
        0x09 => (3, false, "imod"),
        0x0A => (2, false, "not"),
        0x0B => (2, false, "ineg"),
        0x0C => (2, false, "fneg"),
        0x0D => (2, false, "assign"),
        0x0E => (2, false, "cast"),
        0x0F => (3, false, "cmp_eq"),
        0x10 => (3, false, "cmp_lt"),
        0x11 => (3, false, "cmp_le"),
        0x12 => (3, false, "cmp_gt"),
        0x13 => (3, false, "cmp_ge"),
        0x14 => (1, false, "jmp"),
        0x15 => (2, false, "jmpt"),
        0x16 => (2, false, "jmpf"),
        0x17 => (3, true, "callmethod"),
        0x18 => (2, true, "callparent"),
        0x19 => (3, true, "callstatic"),
        0x1A => (1, false, "return"),
        0x1B => (3, false, "strcat"),
        0x1C => (3, false, "propget"),
        0x1D => (3, false, "propset"),
        0x1E => (2, false, "array_create"),
        0x1F => (2, false, "array_length"),
        0x20 => (3, false, "array_getelement"),
        0x21 => (3, false, "array_setelement"),
        0x22 => (4, false, "array_findelement"),
        0x23 => (4, false, "array_rfindelement"),
        _ => bail!("unknown opcode {op:#x}"),
    })
}

struct R<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self.b.get(self.p..self.p + n).ok_or_else(|| anyhow!("truncated pex at {}", self.p))?;
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16> { Ok(u16::from_be_bytes(self.take(2)?.try_into()?)) }
    fn u32(&mut self) -> Result<u32> { Ok(u32::from_be_bytes(self.take(4)?.try_into()?)) }
    fn u64(&mut self) -> Result<u64> { Ok(u64::from_be_bytes(self.take(8)?.try_into()?)) }
    fn wstr(&mut self) -> Result<Vec<u8>> { let n = self.u16()? as usize; Ok(self.take(n)?.to_vec()) }
    fn var(&mut self) -> Result<Var> {
        Ok(match self.u8()? {
            0 => Var::Null,
            1 => Var::Ident(self.u16()?),
            2 => Var::Str(self.u16()?),
            3 => Var::Int(self.u32()? as i32),
            4 => Var::Float(self.u32()?),
            5 => Var::Bool(self.u8()?),
            t => bail!("bad variable type {t} at {}", self.p - 1),
        })
    }
    fn function(&mut self) -> Result<Function> {
        let return_type = self.u16()?;
        let docstring = self.u16()?;
        let user_flags = self.u32()?;
        let flags = self.u8()?;
        let np = self.u16()?;
        let mut params = Vec::new();
        for _ in 0..np { params.push((self.u16()?, self.u16()?)); }
        let nl = self.u16()?;
        let mut locals = Vec::new();
        for _ in 0..nl { locals.push((self.u16()?, self.u16()?)); }
        let ni = self.u16()?;
        let mut code = Vec::new();
        for _ in 0..ni {
            let op = self.u8()?;
            let (fixed, variadic, _) = op_info(op)?;
            let mut args = Vec::new();
            for _ in 0..fixed { args.push(self.var()?); }
            if variadic {
                let c = self.var()?;
                let n = match c { Var::Int(n) if n >= 0 => n as usize, other => bail!("bad vararg count {other:?}") };
                args.push(c);
                for _ in 0..n { args.push(self.var()?); }
            }
            code.push(Instr { op, args });
        }
        Ok(Function { return_type, docstring, user_flags, flags, params, locals, code })
    }
}

#[derive(Default)]
struct W {
    b: Vec<u8>,
}
impl W {
    fn u8(&mut self, v: u8) { self.b.push(v); }
    fn u16(&mut self, v: u16) { self.b.extend_from_slice(&v.to_be_bytes()); }
    fn u32(&mut self, v: u32) { self.b.extend_from_slice(&v.to_be_bytes()); }
    fn u64(&mut self, v: u64) { self.b.extend_from_slice(&v.to_be_bytes()); }
    fn wstr(&mut self, s: &[u8]) { self.u16(s.len() as u16); self.b.extend_from_slice(s); }
    fn var(&mut self, v: &Var) {
        match v {
            Var::Null => self.u8(0),
            Var::Ident(i) => { self.u8(1); self.u16(*i) }
            Var::Str(i) => { self.u8(2); self.u16(*i) }
            Var::Int(i) => { self.u8(3); self.u32(*i as u32) }
            Var::Float(f) => { self.u8(4); self.u32(*f) }
            Var::Bool(b) => { self.u8(5); self.u8(*b) }
        }
    }
    fn function(&mut self, f: &Function) {
        self.u16(f.return_type);
        self.u16(f.docstring);
        self.u32(f.user_flags);
        self.u8(f.flags);
        self.u16(f.params.len() as u16);
        for (a, b) in &f.params { self.u16(*a); self.u16(*b); }
        self.u16(f.locals.len() as u16);
        for (a, b) in &f.locals { self.u16(*a); self.u16(*b); }
        self.u16(f.code.len() as u16);
        for i in &f.code {
            self.u8(i.op);
            for a in &i.args { self.var(a); }
        }
    }
}

impl Pex {
    pub fn parse(b: &[u8]) -> Result<Self> {
        let mut r = R { b, p: 0 };
        if r.u32()? != MAGIC {
            bail!("not a Skyrim pex (magic mismatch; Fallout 4 pex are little-endian)");
        }
        let major = r.u8()?;
        let minor = r.u8()?;
        let game_id = r.u16()?;
        let compile_time = r.u64()?;
        let source = r.wstr()?;
        let user = r.wstr()?;
        let machine = r.wstr()?;
        let ns = r.u16()?;
        let mut strings = Vec::new();
        for _ in 0..ns { strings.push(r.wstr()?); }
        let debug = if r.u8()? != 0 {
            let mt = r.u64()?;
            let nf = r.u16()?;
            let mut fs = Vec::new();
            for _ in 0..nf {
                let object = r.u16()?;
                let state = r.u16()?;
                let function = r.u16()?;
                let ftype = r.u8()?;
                let nlines = r.u16()?;
                let mut lines = Vec::new();
                for _ in 0..nlines { lines.push(r.u16()?); }
                fs.push(DebugFn { object, state, function, ftype, lines });
            }
            Some((mt, fs))
        } else {
            None
        };
        let nuf = r.u16()?;
        let mut user_flags = Vec::new();
        for _ in 0..nuf { user_flags.push((r.u16()?, r.u8()?)); }
        let no = r.u16()?;
        let mut objects = Vec::new();
        for _ in 0..no {
            let name = r.u16()?;
            let size_pos = r.p;
            let size = r.u32()? as usize;
            let parent = r.u16()?;
            let docstring = r.u16()?;
            let uflags = r.u32()?;
            let auto_state = r.u16()?;
            let nv = r.u16()?;
            let mut variables = Vec::new();
            for _ in 0..nv { variables.push((r.u16()?, r.u16()?, r.u32()?, r.var()?)); }
            let np = r.u16()?;
            let mut properties = Vec::new();
            for _ in 0..np {
                let (pn, pt, pd, pu, pf) = (r.u16()?, r.u16()?, r.u16()?, r.u32()?, r.u8()?);
                let (mut av, mut rd, mut wr) = (None, None, None);
                if pf & 4 != 0 {
                    av = Some(r.u16()?);
                } else {
                    if pf & 1 != 0 { rd = Some(r.function()?); }
                    if pf & 2 != 0 { wr = Some(r.function()?); }
                }
                properties.push(Property { name: pn, type_name: pt, docstring: pd, user_flags: pu, flags: pf, auto_var: av, read: rd, write: wr });
            }
            let nst = r.u16()?;
            let mut states = Vec::new();
            for _ in 0..nst {
                let sn = r.u16()?;
                let nf = r.u16()?;
                let mut functions = Vec::new();
                for _ in 0..nf {
                    let fname = r.u16()?;
                    functions.push((fname, r.function()?));
                }
                states.push(State { name: sn, functions });
            }
            let consumed = r.p - size_pos;
            let size_includes_field = if size == consumed {
                true
            } else if size == consumed - 4 {
                false
            } else {
                bail!("object size field {size} does not match parsed size {consumed}");
            };
            objects.push(Object { name, size_includes_field, parent, docstring, user_flags: uflags, auto_state, variables, properties, states });
        }
        if r.p != b.len() {
            bail!("{} trailing bytes after objects", b.len() - r.p);
        }
        Ok(Pex { major, minor, game_id, compile_time, source, user, machine, strings, debug, user_flags, objects })
    }

    pub fn write(&self) -> Vec<u8> {
        let mut w = W::default();
        w.u32(MAGIC);
        w.u8(self.major);
        w.u8(self.minor);
        w.u16(self.game_id);
        w.u64(self.compile_time);
        w.wstr(&self.source);
        w.wstr(&self.user);
        w.wstr(&self.machine);
        w.u16(self.strings.len() as u16);
        for s in &self.strings { w.wstr(s); }
        match &self.debug {
            None => w.u8(0),
            Some((mt, fs)) => {
                w.u8(1);
                w.u64(*mt);
                w.u16(fs.len() as u16);
                for f in fs {
                    w.u16(f.object); w.u16(f.state); w.u16(f.function); w.u8(f.ftype);
                    w.u16(f.lines.len() as u16);
                    for l in &f.lines { w.u16(*l); }
                }
            }
        }
        w.u16(self.user_flags.len() as u16);
        for (a, b) in &self.user_flags { w.u16(*a); w.u8(*b); }
        w.u16(self.objects.len() as u16);
        for o in &self.objects {
            w.u16(o.name);
            let mut body = W::default();
            body.u16(o.parent); body.u16(o.docstring); body.u32(o.user_flags); body.u16(o.auto_state);
            body.u16(o.variables.len() as u16);
            for (a, b, c, d) in &o.variables { body.u16(*a); body.u16(*b); body.u32(*c); body.var(d); }
            body.u16(o.properties.len() as u16);
            for p in &o.properties {
                body.u16(p.name); body.u16(p.type_name); body.u16(p.docstring); body.u32(p.user_flags); body.u8(p.flags);
                if let Some(av) = p.auto_var { body.u16(av); } else {
                    if let Some(f) = &p.read { body.function(f); }
                    if let Some(f) = &p.write { body.function(f); }
                }
            }
            body.u16(o.states.len() as u16);
            for s in &o.states {
                body.u16(s.name);
                body.u16(s.functions.len() as u16);
                for (n, f) in &s.functions { body.u16(*n); body.function(f); }
            }
            let size = body.b.len() + if o.size_includes_field { 4 } else { 0 };
            w.u32(size as u32);
            w.b.extend_from_slice(&body.b);
        }
        w.b
    }

    pub fn s(&self, i: u16) -> String {
        self.strings.get(i as usize).map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_else(|| format!("<str{i}>"))
    }

    fn fmt_var(&self, v: &Var) -> String {
        match v {
            Var::Null => "none".into(),
            Var::Ident(i) => self.s(*i),
            Var::Str(i) => format!("{:?}", self.s(*i)),
            Var::Int(n) => n.to_string(),
            Var::Float(f) => f32::from_bits(*f).to_string(),
            Var::Bool(b) => (*b != 0).to_string(),
        }
    }

    /// Locate a function in the default ("") state of any object by case-insensitive name.
    pub fn find_function(&self, name: &str) -> Option<(usize, usize, usize)> {
        for (oi, o) in self.objects.iter().enumerate() {
            for (si, st) in o.states.iter().enumerate() {
                for (fi, (fname, _)) in st.functions.iter().enumerate() {
                    if self.s(*fname).eq_ignore_ascii_case(name) {
                        return Some((oi, si, fi));
                    }
                }
            }
        }
        None
    }

    pub fn disassemble(&self, name: &str) -> Result<String> {
        let (oi, si, fi) = self.find_function(name).ok_or_else(|| anyhow!("function {name} not found"))?;
        let f = &self.objects[oi].states[si].functions[fi].1;
        let mut out = format!("function {name} ({} instructions)\n", f.code.len());
        for (i, ins) in f.code.iter().enumerate() {
            let (_, _, mnem) = op_info(ins.op)?;
            let args: Vec<String> = ins.args.iter().map(|a| self.fmt_var(a)).collect();
            let mut extra = String::new();
            if matches!(ins.op, 0x14..=0x16) {
                if let Some(Var::Int(off)) = ins.args.last() {
                    extra = format!("   -> {}", i as i64 + *off as i64);
                }
            }
            out += &format!("{i:4}  {mnem:<11} {}{extra}\n", args.join(", "));
        }
        Ok(out)
    }

    fn method_name(&self, ins: &Instr) -> Option<String> {
        if ins.op == 0x17 || ins.op == 0x19 {
            let idx = if ins.op == 0x17 { 0 } else { 1 };
            if let Some(Var::Ident(i)) = ins.args.get(idx) { return Some(self.s(*i)); }
        }
        None
    }
}

/// CHIM `AIAgentAIMind.EndDialogueClearScene`: skip both restart branches
/// (Scene.Stop/Start and owning-Quest.Stop/Start), keeping look-at/expression cleanup and traces.
pub fn patch_chim_scene_restart(pex: &mut Pex) -> Result<String> {
    let (oi, si, fi) = pex.find_function("EndDialogueClearScene").ok_or_else(|| anyhow!("EndDialogueClearScene not found"))?;
    let code = pex.objects[oi].states[si].functions[fi].1.code.clone();
    // 1. the condition: callmethod GetCurrentScene ... -> (cast) -> jmpf cond, +else
    let gcs = code
        .iter()
        .position(|i| pex.method_name(i).map_or(false, |m| m.eq_ignore_ascii_case("GetCurrentScene")))
        .ok_or_else(|| anyhow!("pattern: no GetCurrentScene call"))?;
    let j1 = (gcs + 1..(gcs + 4).min(code.len()))
        .find(|&k| code[k].op == 0x16)
        .ok_or_else(|| anyhow!("pattern: no jmpf after GetCurrentScene"))?;
    let off1 = match code[j1].args.last() { Some(Var::Int(o)) => *o as i64, _ => bail!("pattern: bad jmpf offset") };
    let else_start = (j1 as i64 + off1) as usize;
    if else_start == 0 || else_start >= code.len() {
        bail!("pattern: else target out of range");
    }
    // 2. then-branch must stop+start a scene and end with an unconditional jmp over the else-branch
    let then_calls: Vec<String> = code[j1 + 1..else_start].iter().filter_map(|i| pex.method_name(i)).collect();
    if !(then_calls.iter().any(|m| m.eq_ignore_ascii_case("Stop")) && then_calls.iter().any(|m| m.eq_ignore_ascii_case("Start"))) {
        bail!("pattern: then-branch does not Stop/Start a scene ({then_calls:?})");
    }
    let jend = else_start - 1;
    if code[jend].op != 0x14 {
        bail!("pattern: then-branch does not end with jmp");
    }
    let off2 = match code[jend].args.first() { Some(Var::Int(o)) => *o as i64, _ => bail!("pattern: bad jmp offset") };
    let end = (jend as i64 + off2) as usize;
    if end <= else_start || end > code.len() {
        bail!("pattern: end target out of range");
    }
    let else_calls: Vec<String> = code[else_start..end].iter().filter_map(|i| pex.method_name(i)).collect();
    if !(else_calls.iter().any(|m| m.eq_ignore_ascii_case("GetOwningQuest"))
        && else_calls.iter().any(|m| m.eq_ignore_ascii_case("Stop"))
        && else_calls.iter().any(|m| m.eq_ignore_ascii_case("Start")))
    {
        bail!("pattern: else-branch does not restart the owning quest ({else_calls:?})");
    }
    // 3. rewrite the conditional jump into an unconditional jump to the end of the if/else
    let f = &mut pex.objects[oi].states[si].functions[fi].1;
    f.code[j1] = Instr { op: 0x14, args: vec![Var::Int((end - j1) as i32)] };
    Ok(format!(
        "EndDialogueClearScene: instruction {j1} jmpf->jmp +{} (skips scene restart {}..{} and quest restart {}..{}); instruction count unchanged ({})",
        end - j1, j1 + 1, jend, else_start, end - 1, f.code.len()
    ))
}

pub fn roundtrip_check(bytes: &[u8]) -> Result<Pex> {
    let p = Pex::parse(bytes).context("parsing pex")?;
    let again = p.write();
    if again != bytes {
        let first = again.iter().zip(bytes).position(|(a, b)| a != b).unwrap_or(again.len().min(bytes.len()));
        bail!("round-trip mismatch at byte {first} (len {} vs {})", again.len(), bytes.len());
    }
    Ok(p)
}

impl Pex {
    /// Index of a string, appending it to the table if absent (existing indices never change).
    pub fn intern(&mut self, s: &str) -> u16 {
        if let Some(i) = self.strings.iter().position(|x| x.as_slice() == s.as_bytes()) {
            return i as u16;
        }
        self.strings.push(s.as_bytes().to_vec());
        (self.strings.len() - 1) as u16
    }

    fn debug_entry_mut(&mut self, oi: usize, si: usize, fi: usize) -> Option<&mut DebugFn> {
        let o = &self.objects[oi];
        let (oname, sname, fname) = (o.name, o.states[si].name, o.states[si].functions[fi].0);
        self.debug.as_mut()?.1.iter_mut().find(|d| d.object == oname && d.state == sname && d.function == fname && d.ftype == 0)
    }

    /// Insert `new` before instruction `at`. Existing jumps keep their absolute targets; a jump that
    /// targeted exactly `at` lands on the inserted code when `enter_new` (prepending to a block),
    /// or on the original instruction otherwise. Jumps inside `new` are relative to their own position.
    pub fn insert_code(&mut self, oi: usize, si: usize, fi: usize, at: usize, new: Vec<Instr>, enter_new: bool) -> Result<()> {
        let n = new.len() as i64;
        {
            let f = &mut self.objects[oi].states[si].functions[fi].1;
            if at > f.code.len() {
                bail!("insert position out of range");
            }
            // Fix existing jumps before inserting.
            for (i, ins) in f.code.iter_mut().enumerate() {
                if !matches!(ins.op, 0x14..=0x16) {
                    continue;
                }
                let Some(Var::Int(off)) = ins.args.last_mut() else { bail!("jump without offset") };
                let src = i as i64;
                let dst = src + *off as i64;
                let (a, ii) = (at as i64, src);
                // new positions: src' = src + (src >= at ? n : 0); dst' = dst + (dst >= at ? n : 0)
                let src2 = ii + if ii >= a { n } else { 0 };
                let dst2 = if dst > a || (dst == a && !enter_new) { dst + n } else { dst };
                *off = (dst2 - src2) as i32;
            }
            let tail = f.code.split_off(at);
            f.code.extend(new);
            f.code.extend(tail);
        }
        // Debug line numbers: new instructions take the line of the instruction they precede.
        if let Some(d) = self.debug_entry_mut(oi, si, fi).filter(|d| !d.lines.is_empty()) {
            let line = d.lines.get(at).copied().or(d.lines.last().copied()).unwrap_or(0);
            let tail = d.lines.split_off(at.min(d.lines.len()));
            d.lines.extend(std::iter::repeat(line).take(n as usize));
            d.lines.extend(tail);
        }
        Ok(())
    }

    /// Verify every jump in every function lands inside its function (or exactly at its end).
    pub fn check_jumps(&self) -> Result<usize> {
        let mut n = 0;
        for o in &self.objects {
            for st in &o.states {
                for (fname, f) in &st.functions {
                    for (i, ins) in f.code.iter().enumerate() {
                        if matches!(ins.op, 0x14..=0x16) {
                            let Some(Var::Int(off)) = ins.args.last() else { bail!("jump without offset") };
                            let dst = i as i64 + *off as i64;
                            if dst < 0 || dst > f.code.len() as i64 {
                                bail!("{}: jump at {i} targets {dst} outside 0..={}", self.s(*fname), f.code.len());
                            }
                            n += 1;
                        }
                    }
                }
            }
        }
        if let Some((_, dfs)) = &self.debug {
            for d in dfs {
                if d.ftype != 0 { continue; }
                if let Some(o) = self.objects.iter().find(|o| o.name == d.object) {
                    if let Some(st) = o.states.iter().find(|s| s.name == d.state) {
                        if let Some((_, f)) = st.functions.iter().find(|(fname, _)| *fname == d.function) {
                            // The compiler emits no line entries for generated functions (GetState, GotoState).
                            if !d.lines.is_empty() && f.code.len() != d.lines.len() {
                                bail!("debug line table length {} != instruction count {} for {}", d.lines.len(), f.code.len(), self.s(d.function));
                            }
                        }
                    }
                }
            }
        }
        Ok(n)
    }
}

/// CHIM `CHIMSchedule.Execute`: refuse travel/teleport ("busy") for essential actors or actors in a scene.
/// Essential is set by quest aliases while a quest needs the actor, so this protects quest NPCs.
pub fn patch_chim_schedule_guard(pex: &mut Pex) -> Result<String> {
    let (oi, si, fi) = pex.find_function("Execute").ok_or_else(|| anyhow!("Execute not found"))?;
    let code = pex.objects[oi].states[si].functions[fi].1.code.clone();
    // Find: callmethod IsInDialogueWithPlayer ... ; then the branch that assigns result = "busy" followed by jmp END;
    let busy_idx = pex.strings.iter().position(|s| s.as_slice() == b"busy").ok_or_else(|| anyhow!("no \"busy\" string"))? as u16;
    let result_idx = pex.strings.iter().position(|s| s.as_slice() == b"result").ok_or_else(|| anyhow!("no result variable"))? as u16;
    let dlg = code
        .iter()
        .position(|i| pex.method_name(i).map_or(false, |m| m.eq_ignore_ascii_case("IsInDialogueWithPlayer")))
        .ok_or_else(|| anyhow!("pattern: no IsInDialogueWithPlayer call"))?;
    // The busy assignment right after the condition chain.
    let assign = (dlg..(dlg + 25).min(code.len()))
        .find(|&k| code[k].op == 0x0D && code[k].args.first() == Some(&Var::Ident(result_idx)) && code[k].args.get(1) == Some(&Var::Str(busy_idx)))
        .ok_or_else(|| anyhow!("pattern: no result = \"busy\" after the dialogue check"))?;
    let jend = assign + 1;
    if code.get(jend).map(|i| i.op) != Some(0x14) {
        bail!("pattern: busy branch does not end with jmp");
    }
    let else_start = jend + 1; // first instruction of the travel (else) block
    // Guard: tmp = npc.IsEssential(); if tmp -> busy; s = npc.GetCurrentScene(); tmp = s as bool; if !tmp -> else_start; busy...
    let npc = pex.intern("npc");
    let is_ess = pex.intern("IsEssential");
    let gcs = pex.intern("GetCurrentScene");
    let tb = pex.intern("::chimguard_bool");
    let ts = pex.intern("::chimguard_scene");
    let tbool = pex.intern("bool");
    let tscene = pex.intern("scene");
    {
        let f = &mut pex.objects[oi].states[si].functions[fi].1;
        if !f.params.iter().any(|(n, _)| *n == npc) {
            bail!("pattern: Execute has no npc parameter");
        }
        f.locals.push((tb, tbool));
        f.locals.push((ts, tscene));
    }
    let guard = vec![
        Instr { op: 0x17, args: vec![Var::Ident(is_ess), Var::Ident(npc), Var::Ident(tb), Var::Int(0)] }, // 0
        Instr { op: 0x15, args: vec![Var::Ident(tb), Var::Int(4)] },                                     // 1 jmpt -> 5
        Instr { op: 0x17, args: vec![Var::Ident(gcs), Var::Ident(npc), Var::Ident(ts), Var::Int(0)] },    // 2
        Instr { op: 0x0E, args: vec![Var::Ident(tb), Var::Ident(ts)] },                                   // 3 cast
        Instr { op: 0x16, args: vec![Var::Ident(tb), Var::Int(3)] },                                      // 4 jmpf -> 7 (original else)
        Instr { op: 0x0D, args: vec![Var::Ident(result_idx), Var::Str(busy_idx)] },                       // 5 result = "busy"
        Instr { op: 0x14, args: vec![Var::Int(0)] },                                                       // 6 jmp END (fixed below)
    ];
    // END (absolute, before insertion) = target of the busy-branch jmp.
    let end_abs = match code[jend].args.first() { Some(Var::Int(o)) => jend as i64 + *o as i64, _ => bail!("bad jmp") };
    pex.insert_code(oi, si, fi, else_start, guard, true)?;
    // After insertion END moved by +7 (it is >= else_start); the guard's jmp is at else_start+6.
    let end_new = end_abs + 7;
    let f = &mut pex.objects[oi].states[si].functions[fi].1;
    let gj = else_start + 6;
    f.code[gj].args[0] = Var::Int((end_new - gj as i64) as i32);
    pex.check_jumps()?;
    Ok(format!("CHIMSchedule.Execute: inserted 7-instruction essential/scene guard at {else_start} (busy branch at {assign}); END {end_abs}->{end_new}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tiny() -> Pex {
        // function f(npc): 0 jmpf x,+3 ; 1 nop ; 2 jmp +2 ; 3 nop ; 4 return
        let f = Function {
            return_type: 0, docstring: 0, user_flags: 0, flags: 0, params: vec![(1, 2)], locals: vec![],
            code: vec![
                Instr { op: 0x16, args: vec![Var::Ident(1), Var::Int(3)] },
                Instr { op: 0x00, args: vec![] },
                Instr { op: 0x14, args: vec![Var::Int(2)] },
                Instr { op: 0x00, args: vec![] },
                Instr { op: 0x1A, args: vec![Var::Null] },
            ],
        };
        Pex {
            major: 3, minor: 2, game_id: 1, compile_time: 0, source: b"t.psc".to_vec(), user: vec![], machine: vec![],
            strings: vec![b"T".to_vec(), b"npc".to_vec(), b"actor".to_vec(), b"f".to_vec(), b"".to_vec()],
            debug: Some((0, vec![DebugFn { object: 0, state: 4, function: 3, ftype: 0, lines: vec![1, 2, 3, 4, 5] }])),
            user_flags: vec![],
            objects: vec![Object {
                name: 0, size_includes_field: true, parent: 4, docstring: 4, user_flags: 0, auto_state: 4,
                variables: vec![], properties: vec![], states: vec![State { name: 4, functions: vec![(3, f)] }],
            }],
        }
    }
    #[test]
    fn roundtrip_and_insert_keeps_targets() {
        let p = tiny();
        let bytes = p.write();
        let mut q = roundtrip_check(&bytes).unwrap();
        // insert 2 nops before instruction 3 (the else target of the jmpf, and inside the jmp's span)
        let mut r = q.clone();
        let two = || vec![Instr { op: 0, args: vec![] }, Instr { op: 0, args: vec![] }];
        // enter_new = false: the jmpf that targeted 3 still reaches the old instruction (now at 5)
        q.insert_code(0, 0, 0, 3, two(), false).unwrap();
        let c = &q.objects[0].states[0].functions[0].1.code;
        assert_eq!(c[0].args[1], Var::Int(5));
        assert_eq!(c[2].args[0], Var::Int(4)); // jmp at 2 -> old 4 (return) now at 6
        assert_eq!(q.check_jumps().unwrap(), 2);
        assert_eq!(q.debug.as_ref().unwrap().1[0].lines, vec![1, 2, 3, 4, 4, 4, 5]);
        roundtrip_check(&q.write()).unwrap();
        // enter_new = true: the jmpf that targeted 3 now enters the inserted block at 3
        r.insert_code(0, 0, 0, 3, two(), true).unwrap();
        let c = &r.objects[0].states[0].functions[0].1.code;
        assert_eq!(c[0].args[1], Var::Int(3));
        assert_eq!(c[2].args[0], Var::Int(4)); // the return (old 4) is now at 6: unaffected by mode
        r.check_jumps().unwrap();
    }
}
