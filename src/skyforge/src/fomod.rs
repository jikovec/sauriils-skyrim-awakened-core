//! Deterministic FOMOD (ModuleConfig.xml, schema 5.x) resolver.
//!
//! Choices are supplied explicitly from the manifest ("Step/Group" or "Group" ->
//! option names). Groups without an explicit choice fall back to the documented
//! FOMOD defaults (Required, then Recommended, then the first usable option) and
//! every defaulted decision is reported so it can be pinned later.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct FileInstall {
    /// Source path relative to the FOMOD root, '/'-separated.
    pub source: String,
    /// Destination relative to Data, '/'-separated ("" = Data root).
    pub destination: String,
    pub priority: i64,
    pub folder: bool,
    /// Document order, used as a tie-breaker for equal priorities.
    pub seq: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PType {
    Required,
    Optional,
    Recommended,
    NotUsable,
    CouldBeUsable,
}

fn ptype(s: &str) -> PType {
    match s {
        "Required" => PType::Required,
        "Recommended" => PType::Recommended,
        "NotUsable" => PType::NotUsable,
        "CouldBeUsable" => PType::CouldBeUsable,
        _ => PType::Optional,
    }
}

#[derive(Debug, Clone)]
enum Deps {
    All(Vec<Deps>),
    Any(Vec<Deps>),
    Flag { name: String, value: String },
    File { file: String, state: String },
    Game { version: String },
    True,
}

#[derive(Debug, Clone)]
enum TypeDesc {
    Simple(PType),
    Dependent { default: PType, patterns: Vec<(Deps, PType)> },
}

#[derive(Debug, Clone)]
struct Plugin {
    name: String,
    files: Vec<FileInstall>,
    flags: Vec<(String, String)>,
    tdesc: TypeDesc,
}

#[derive(Debug, Clone)]
struct Group {
    name: String,
    gtype: String,
    plugins: Vec<Plugin>,
}

#[derive(Debug, Clone)]
struct Step {
    name: String,
    visible: Option<Deps>,
    groups: Vec<Group>,
}

#[derive(Debug)]
pub struct ModuleConfig {
    pub module_name: String,
    required: Vec<FileInstall>,
    steps: Vec<Step>,
    conditional: Vec<(Deps, Vec<FileInstall>)>,
}

/// Evaluation context for dependencies.
pub struct Context<'a> {
    /// Lower-cased names of plugins (and other files) that will be active.
    pub active_files: &'a HashSet<String>,
    /// Game version, e.g. "1.6.1170.0".
    pub game_version: &'a str,
}

/// Only dependency predicates declared by this XML affect its qualification.
/// An unrelated active plugin must not invalidate every installed FOMOD.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextWatch {
    files: BTreeMap<String, bool>,
    games: BTreeMap<String, bool>,
}

impl ContextWatch {
    pub fn matches(&self, ctx: &Context) -> bool {
        self.files.iter().all(|(file, observed)| file_present(file, ctx) == *observed)
            && self.games.iter().all(|(version, observed)| version_ge(ctx.game_version, version) == *observed)
    }

    fn observe(&mut self, dependency: &Deps, ctx: &Context) {
        match dependency {
            Deps::All(items) | Deps::Any(items) => for item in items { self.observe(item, ctx); },
            Deps::File { file, .. } => { self.files.insert(file.clone(), file_present(file, ctx)); },
            Deps::Game { version } => { self.games.insert(version.clone(), version_ge(ctx.game_version, version)); },
            Deps::True | Deps::Flag { .. } => {},
        }
    }
}

pub struct Resolution {
    pub files: Vec<FileInstall>,
    /// Choices actually used, keyed "Step/Group".
    pub chosen: BTreeMap<String, Vec<String>>,
    /// Groups resolved by default (no explicit choice), for review.
    pub defaulted: Vec<String>,
}

/// Decode FOMOD XML, which is frequently UTF-16 with a BOM.
pub fn decode_xml(bytes: &[u8]) -> Result<String> {
    let s = if bytes.starts_with(&[0xFF, 0xFE]) {
        let u: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16(&u)?
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        let u: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        String::from_utf16(&u)?
    } else if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(&bytes[3..]).into_owned()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    // roxmltree rejects a UTF-16 declaration on an already-decoded string.
    Ok(s.replacen("encoding=\"UTF-16\"", "encoding=\"UTF-8\"", 1)
        .replacen("encoding=\"utf-16\"", "encoding=\"UTF-8\"", 1))
}

fn norm(p: &str) -> String {
    let p = p.replace('\\', "/");
    let p = p.trim_matches('/');
    p.split('/').filter(|c| !c.is_empty() && *c != ".").collect::<Vec<_>>().join("/")
}

fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
    n.children().find(|c| c.is_element() && c.tag_name().name() == name)
}

fn children<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &'a str) -> impl Iterator<Item = roxmltree::Node<'a, 'i>> + 'a
where
    'i: 'a,
{
    n.children().filter(move |c| c.is_element() && c.tag_name().name() == name)
}

fn parse_files(n: Option<roxmltree::Node>, seq: &mut usize) -> Vec<FileInstall> {
    let mut v = Vec::new();
    let Some(n) = n else { return v };
    for c in n.children().filter(|c| c.is_element()) {
        let folder = match c.tag_name().name() {
            "file" => false,
            "folder" => true,
            _ => continue,
        };
        let source = norm(c.attribute("source").unwrap_or(""));
        let destination = match c.attribute("destination") {
            None => source.clone(), // omitted: same as source
            Some(d) => {
                let d = norm(d);
                if d.is_empty() && !folder {
                    // explicit empty destination for a file: place it at the Data root
                    source.rsplit('/').next().unwrap_or("").to_string()
                } else {
                    d
                }
            }
        };
        let priority = c.attribute("priority").and_then(|p| p.parse().ok()).unwrap_or(0);
        *seq += 1;
        v.push(FileInstall { source, destination, priority, folder, seq: *seq });
    }
    v
}

fn parse_deps(n: roxmltree::Node) -> Deps {
    let op_any = n.attribute("operator").map_or(false, |o| o.eq_ignore_ascii_case("or"));
    let mut v = Vec::new();
    for c in n.children().filter(|c| c.is_element()) {
        let d = match c.tag_name().name() {
            "flagDependency" => Deps::Flag {
                name: c.attribute("flag").unwrap_or("").to_string(),
                value: c.attribute("value").unwrap_or("").to_string(),
            },
            "fileDependency" => Deps::File {
                file: c.attribute("file").unwrap_or("").to_lowercase().replace('\\', "/"),
                state: c.attribute("state").unwrap_or("Active").to_string(),
            },
            "gameDependency" => Deps::Game { version: c.attribute("version").unwrap_or("0").to_string() },
            "dependencies" => parse_deps(c),
            // fommDependency / foseDependency / scriptExtender etc.: satisfied in this build.
            _ => Deps::True,
        };
        v.push(d);
    }
    if op_any { Deps::Any(v) } else { Deps::All(v) }
}

fn parse_tdesc(n: Option<roxmltree::Node>) -> TypeDesc {
    let Some(n) = n else { return TypeDesc::Simple(PType::Optional) };
    if let Some(t) = child(n, "type") {
        return TypeDesc::Simple(ptype(t.attribute("name").unwrap_or("Optional")));
    }
    if let Some(dt) = child(n, "dependencyType") {
        let default = child(dt, "defaultType")
            .and_then(|d| d.attribute("name"))
            .map(ptype)
            .unwrap_or(PType::Optional);
        let mut patterns = Vec::new();
        if let Some(ps) = child(dt, "patterns") {
            for p in children(ps, "pattern") {
                let deps = child(p, "dependencies").map(parse_deps).unwrap_or(Deps::True);
                let t = child(p, "type").and_then(|t| t.attribute("name")).map(ptype).unwrap_or(default);
                patterns.push((deps, t));
            }
        }
        return TypeDesc::Dependent { default, patterns };
    }
    TypeDesc::Simple(PType::Optional)
}

fn sort_by_order<T>(items: &mut [T], order: Option<&str>, name: impl Fn(&T) -> String) {
    match order {
        Some("Descending") => items.sort_by(|a, b| name(b).to_lowercase().cmp(&name(a).to_lowercase())),
        Some("Explicit") => {}
        // FOMOD default order is Ascending.
        _ => items.sort_by(|a, b| name(a).to_lowercase().cmp(&name(b).to_lowercase())),
    }
}

impl ModuleConfig {
    pub fn watch_context(&self, ctx: &Context) -> ContextWatch {
        let mut watch = ContextWatch::default();
        for step in &self.steps {
            if let Some(visible) = &step.visible { watch.observe(visible, ctx); }
            for group in &step.groups {
                for plugin in &group.plugins {
                    if let TypeDesc::Dependent { patterns, .. } = &plugin.tdesc {
                        for (dependency, _) in patterns { watch.observe(dependency, ctx); }
                    }
                }
            }
        }
        for (dependency, _) in &self.conditional { watch.observe(dependency, ctx); }
        watch
    }

    pub fn parse(xml: &str) -> Result<Self> {
        let doc = roxmltree::Document::parse_with_options(
            xml,
            roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() },
        )?;
        let root = doc.root_element();
        let mut seq = 0usize;
        let module_name = child(root, "moduleName").and_then(|n| n.text()).unwrap_or("").trim().to_string();
        let required = parse_files(child(root, "requiredInstallFiles"), &mut seq);
        let mut steps = Vec::new();
        if let Some(is) = child(root, "installSteps") {
            let mut raw: Vec<roxmltree::Node> = children(is, "installStep").collect();
            sort_by_order(&mut raw, is.attribute("order"), |n| n.attribute("name").unwrap_or("").to_string());
            for s in raw {
                let visible = child(s, "visible").map(parse_deps);
                let mut groups = Vec::new();
                if let Some(ofg) = child(s, "optionalFileGroups") {
                    let mut graw: Vec<roxmltree::Node> = children(ofg, "group").collect();
                    sort_by_order(&mut graw, ofg.attribute("order"), |n| n.attribute("name").unwrap_or("").to_string());
                    for g in graw {
                        let mut plugins = Vec::new();
                        if let Some(ps) = child(g, "plugins") {
                            let mut praw: Vec<roxmltree::Node> = children(ps, "plugin").collect();
                            sort_by_order(&mut praw, ps.attribute("order"), |n| n.attribute("name").unwrap_or("").to_string());
                            for p in praw {
                                let flags = child(p, "conditionFlags")
                                    .map(|cf| {
                                        children(cf, "flag")
                                            .map(|f| (f.attribute("name").unwrap_or("").to_string(), f.text().unwrap_or("").to_string()))
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                plugins.push(Plugin {
                                    name: p.attribute("name").unwrap_or("").trim().to_string(),
                                    files: parse_files(child(p, "files"), &mut seq),
                                    flags,
                                    tdesc: parse_tdesc(child(p, "typeDescriptor")),
                                });
                            }
                        }
                        groups.push(Group {
                            name: g.attribute("name").unwrap_or("").trim().to_string(),
                            gtype: g.attribute("type").unwrap_or("SelectAny").to_string(),
                            plugins,
                        });
                    }
                }
                steps.push(Step { name: s.attribute("name").unwrap_or("").trim().to_string(), visible, groups });
            }
        }
        let mut conditional = Vec::new();
        if let Some(cfi) = child(root, "conditionalFileInstalls") {
            if let Some(ps) = child(cfi, "patterns") {
                for p in children(ps, "pattern") {
                    let deps = child(p, "dependencies").map(parse_deps).unwrap_or(Deps::True);
                    conditional.push((deps, parse_files(child(p, "files"), &mut seq)));
                }
            }
        }
        Ok(ModuleConfig { module_name, required, steps, conditional })
    }

    pub fn resolve(&self, choices: &BTreeMap<String, Vec<String>>, ctx: &Context) -> Result<Resolution> {
        let mut flags: HashMap<String, String> = HashMap::new();
        let mut files = self.required.clone();
        let mut chosen = BTreeMap::new();
        let mut defaulted = Vec::new();
        let mut used_keys = HashSet::new();
        // Step/group names are trimmed when parsed; trim choice keys the same way so a name copied
        // with the XML's stray spaces still matches.
        let by_norm: HashMap<String, &String> = choices
            .keys()
            .map(|k| (k.split('/').map(str::trim).collect::<Vec<_>>().join("/"), k))
            .collect();

        for step in &self.steps {
            if let Some(v) = &step.visible {
                if !eval(v, &flags, ctx) {
                    continue;
                }
            }
            for g in &step.groups {
                let types: Vec<PType> = g.plugins.iter().map(|p| eval_type(&p.tdesc, &flags, ctx)).collect();
                let k_full = format!("{}/{}", step.name, g.name);
                let explicit = by_norm
                    .get(&k_full)
                    .or_else(|| by_norm.get(&g.name))
                    .map(|orig| ((*orig).clone(), &choices[*orig]));
                let mut sel: Vec<usize> = Vec::new();
                match explicit {
                    Some((k, names)) => {
                        used_keys.insert(k);
                        for n in names {
                            let idx = g
                                .plugins
                                .iter()
                                .position(|p| p.name.eq_ignore_ascii_case(n.trim()))
                                .ok_or_else(|| anyhow!(
                                    "FOMOD option '{n}' not found in group '{k_full}' (options: {:?})",
                                    g.plugins.iter().map(|p| &p.name).collect::<Vec<_>>()
                                ))?;
                            if types[idx] == PType::NotUsable {
                                bail!("FOMOD option '{n}' in '{k_full}' is NotUsable in this context");
                            }
                            sel.push(idx);
                        }
                        for (i, t) in types.iter().enumerate() {
                            if *t == PType::Required && !sel.contains(&i) {
                                sel.push(i);
                            }
                        }
                    }
                    None => {
                        sel = default_selection(&g.gtype, &types);
                        defaulted.push(format!(
                            "{k_full} [{}] -> {:?}",
                            g.gtype,
                            sel.iter().map(|i| &g.plugins[*i].name).collect::<Vec<_>>()
                        ));
                    }
                }
                check_group_constraint(&g.gtype, sel.len(), g.plugins.len(), &k_full)?;
                let mut names = Vec::new();
                for i in sel {
                    let p = &g.plugins[i];
                    for (f, v) in &p.flags {
                        flags.insert(f.clone(), v.clone());
                    }
                    files.extend(p.files.iter().cloned());
                    names.push(p.name.clone());
                }
                chosen.insert(k_full, names);
            }
        }
        for k in choices.keys() {
            if !used_keys.contains(k) {
                bail!("FOMOD choice key '{k}' matched no visible step/group");
            }
        }
        for (deps, fs) in &self.conditional {
            if eval(deps, &flags, ctx) {
                files.extend(fs.iter().cloned());
            }
        }
        Ok(Resolution { files, chosen, defaulted })
    }
}

fn default_selection(gtype: &str, types: &[PType]) -> Vec<usize> {
    let req: Vec<usize> = (0..types.len()).filter(|i| types[*i] == PType::Required).collect();
    let rec: Vec<usize> = (0..types.len()).filter(|i| types[*i] == PType::Recommended).collect();
    let usable: Vec<usize> = (0..types.len()).filter(|i| types[*i] != PType::NotUsable).collect();
    match gtype {
        "SelectAll" => (0..types.len()).collect(),
        "SelectExactlyOne" => req.first().or(rec.first()).or(usable.first()).map(|i| vec![*i]).unwrap_or_default(),
        "SelectAtMostOne" => req.first().or(rec.first()).map(|i| vec![*i]).unwrap_or_default(),
        "SelectAtLeastOne" => {
            let mut v: Vec<usize> = req.iter().chain(rec.iter()).copied().collect();
            v.sort();
            v.dedup();
            if v.is_empty() {
                usable.first().map(|i| vec![*i]).unwrap_or_default()
            } else {
                v
            }
        }
        _ => {
            let mut v: Vec<usize> = req.iter().chain(rec.iter()).copied().collect();
            v.sort();
            v.dedup();
            v
        }
    }
}

fn check_group_constraint(gtype: &str, n: usize, total: usize, key: &str) -> Result<()> {
    let ok = match gtype {
        "SelectExactlyOne" => n == 1,
        "SelectAtMostOne" => n <= 1,
        "SelectAtLeastOne" => n >= 1,
        "SelectAll" => n == total,
        _ => true,
    };
    if !ok {
        bail!("FOMOD group '{key}' ({gtype}) cannot have {n} selection(s)");
    }
    Ok(())
}

fn eval_type(t: &TypeDesc, flags: &HashMap<String, String>, ctx: &Context) -> PType {
    match t {
        TypeDesc::Simple(p) => *p,
        TypeDesc::Dependent { default, patterns } => patterns
            .iter()
            .find(|(d, _)| eval(d, flags, ctx))
            .map(|(_, p)| *p)
            .unwrap_or(*default),
    }
}

fn version_ge(have: &str, want: &str) -> bool {
    let p = |s: &str| s.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    let (a, b) = (p(have), p(want));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    true
}

fn file_present(file: &str, ctx: &Context) -> bool {
    ctx.active_files.contains(file)
        || ctx.active_files.contains(file.rsplit('/').next().unwrap_or(file))
}

fn eval(d: &Deps, flags: &HashMap<String, String>, ctx: &Context) -> bool {
    match d {
        Deps::True => true,
        Deps::All(v) => v.iter().all(|x| eval(x, flags, ctx)),
        Deps::Any(v) => v.iter().any(|x| eval(x, flags, ctx)),
        Deps::Flag { name, value } => flags.get(name).map(|v| v == value).unwrap_or(value.is_empty()),
        Deps::File { file, state } => {
            let present = file_present(file, ctx);
            match state.as_str() {
                "Active" => present,
                "Missing" => !present,
                _ => false, // "Inactive": skyforge never plans inactive-but-present plugins
            }
        }
        Deps::Game { version } => version_ge(ctx.game_version, version),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <moduleName>Test Mod</moduleName>
  <requiredInstallFiles><folder source="Core" destination=""/></requiredInstallFiles>
  <installSteps order="Explicit">
    <installStep name="Runtime">
      <optionalFileGroups order="Explicit">
        <group name="Game version" type="SelectExactlyOne">
          <plugins order="Explicit">
            <plugin name="SE 1.5.97"><files><folder source="SE" destination=""/></files>
              <conditionFlags><flag name="ae">0</flag></conditionFlags>
              <typeDescriptor><type name="Optional"/></typeDescriptor></plugin>
            <plugin name="AE 1.6.1170"><files><folder source="AE" destination=""/></files>
              <conditionFlags><flag name="ae">1</flag></conditionFlags>
              <typeDescriptor><type name="Recommended"/></typeDescriptor></plugin>
          </plugins>
        </group>
      </optionalFileGroups>
    </installStep>
    <installStep name="AE extras">
      <visible><dependencies operator="And"><flagDependency flag="ae" value="1"/></dependencies></visible>
      <optionalFileGroups order="Explicit">
        <group name="Extras" type="SelectAny">
          <plugins order="Explicit">
            <plugin name="Patch for Foo"><files><file source="Patches\Foo.esp" destination="Foo Patch.esp"/></files>
              <typeDescriptor><dependencyType><defaultType name="NotUsable"/>
                <patterns><pattern><dependencies><fileDependency file="Foo.esp" state="Active"/></dependencies><type name="Recommended"/></pattern></patterns>
              </dependencyType></typeDescriptor></plugin>
            <plugin name="Optional Bar"><files><file source="Bar.ini"/></files>
              <typeDescriptor><type name="Optional"/></typeDescriptor></plugin>
          </plugins>
        </group>
      </optionalFileGroups>
    </installStep>
  </installSteps>
  <conditionalFileInstalls><patterns>
    <pattern><dependencies operator="And"><flagDependency flag="ae" value="1"/></dependencies>
      <files><file source="AE\extra.toml" destination="SKSE\Plugins\extra.toml" priority="5"/></files></pattern>
  </patterns></conditionalFileInstalls>
</config>"#;

    fn utf16(s: &str) -> Vec<u8> {
        let mut v = vec![0xFF, 0xFE];
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    #[test]
    fn decodes_utf16_and_resolves_defaults() {
        let xml = decode_xml(&utf16(XML)).unwrap();
        let mc = ModuleConfig::parse(&xml).unwrap();
        assert_eq!(mc.module_name, "Test Mod");
        let active: HashSet<String> = ["foo.esp".to_string()].into();
        let ctx = Context { active_files: &active, game_version: "1.6.1170.0" };
        let r = mc.resolve(&BTreeMap::new(), &ctx).unwrap();
        // Recommended AE chosen by default, flag makes step 2 visible, Foo patch becomes Recommended.
        assert_eq!(r.chosen["Runtime/Game version"], vec!["AE 1.6.1170"]);
        assert_eq!(r.chosen["AE extras/Extras"], vec!["Patch for Foo"]);
        let dests: Vec<&str> = r.files.iter().map(|f| f.destination.as_str()).collect();
        assert!(dests.contains(&"Foo Patch.esp"));
        assert!(dests.contains(&"SKSE/Plugins/extra.toml"));
        assert_eq!(r.defaulted.len(), 2);
    }

    #[test]
    fn explicit_choices_and_hidden_steps() {
        let mc = ModuleConfig::parse(&decode_xml(XML.as_bytes()).unwrap()).unwrap();
        let active = HashSet::new();
        let ctx = Context { active_files: &active, game_version: "1.6.1170.0" };
        let mut ch = BTreeMap::new();
        ch.insert("Game version".to_string(), vec!["SE 1.5.97".to_string()]);
        let r = mc.resolve(&ch, &ctx).unwrap();
        assert_eq!(r.chosen["Runtime/Game version"], vec!["SE 1.5.97"]);
        // flag ae=0 hides the AE step and its conditional file.
        assert!(!r.chosen.contains_key("AE extras/Extras"));
        assert!(!r.files.iter().any(|f| f.destination.ends_with("extra.toml")));
        // a key that matches nothing visible is an error, not silently ignored
        ch.insert("AE extras/Extras".into(), vec!["Optional Bar".into()]);
        assert!(mc.resolve(&ch, &ctx).is_err());
    }

    #[test]
    fn rejects_unknown_and_notusable_options() {
        let mc = ModuleConfig::parse(&decode_xml(XML.as_bytes()).unwrap()).unwrap();
        let active = HashSet::new();
        let ctx = Context { active_files: &active, game_version: "1.6.1170.0" };
        let mut ch = BTreeMap::new();
        ch.insert("Game version".to_string(), vec!["VR".to_string()]);
        assert!(mc.resolve(&ch, &ctx).is_err());
        let mut ch = BTreeMap::new();
        ch.insert("Extras".to_string(), vec!["Patch for Foo".to_string()]); // NotUsable without Foo.esp
        assert!(mc.resolve(&ch, &ctx).is_err());
    }

    #[test]
    fn version_compare() {
        assert!(version_ge("1.6.1170.0", "1.6.640"));
        assert!(!version_ge("1.5.97.0", "1.6.318"));
    }

    #[test]
    fn dependency_watch_retains_basename_semantics_and_ignores_unrelated_names() {
        let xml=r#"<config><moduleName>Watch</moduleName><conditionalFileInstalls><patterns><pattern><dependencies><fileDependency file="Data/Foo.esp" state="Active"/></dependencies><files><file source="a"/></files></pattern></patterns></conditionalFileInstalls></config>"#;
        let mc=ModuleConfig::parse(xml).unwrap();let mut active=HashSet::new();
        let watch=mc.watch_context(&Context{active_files:&active,game_version:"1.6.1170.0"});
        active.insert("other.esp".into());assert!(watch.matches(&Context{active_files:&active,game_version:"1.6.1170.0"}));
        active.insert("foo.esp".into());assert!(!watch.matches(&Context{active_files:&active,game_version:"1.6.1170.0"}));
    }
}
