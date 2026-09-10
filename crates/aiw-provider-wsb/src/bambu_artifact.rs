use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 32;
const MAX_ENTRY_BYTES: u64 = 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 4 * 1024 * 1024;
const ROOT_RELS: &str = "_rels/.rels";
const ROOT_MODEL: &str = "3D/3dmodel.model";
const ROOT_MODEL_RELS: &str = "3D/_rels/3dmodel.model.rels";
const LEAF_MODEL: &str = "3D/Objects/object_1.model";
const MODEL_RELATIONSHIP: &str = "http://schemas.microsoft.com/3dmanufacturing/2013/01/3dmodel";
const CORE_3MF_NAMESPACE: &str = "http://schemas.microsoft.com/3dmanufacturing/core/2015/02";
const PRODUCTION_3MF_NAMESPACE: &str =
    "http://schemas.microsoft.com/3dmanufacturing/production/2015/06";
const COMPONENT_TRANSFORM: &str = "1 0 0 0 1 0 0 0 1 0.5 0.5 0.5";
const BUILD_TRANSFORM: &str = "1 0 0 0 1 0 0 0 1 99.41021 99.41022 0";

/// A bounded, structural verification result for the fixed tetrahedron 3MF export.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambuExportArtifact {
    pub sha256: String,
    pub size_bytes: u64,
    pub vertex_count: u32,
    pub triangle_count: u32,
}

/// Verifies the exact, package-referenced tetrahedron exported by the Bambu Studio feasibility flow.
///
/// The input is never extracted to disk. ZIP and XML parsing are bounded before expansion; the
/// result only succeeds when the root relationship, component relationship, transforms, build
/// item, and leaf mesh form the reviewed reference graph.
pub fn verify_bambu_export(bytes: &[u8]) -> Result<BambuExportArtifact, String> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err("3MF input exceeds 1 MiB limit".to_owned());
    }
    let entries = read_zip_entries(bytes)?;
    verify_content_types(required(&entries, "[Content_Types].xml")?)?;
    verify_relationships(required(&entries, ROOT_RELS)?, ROOT_MODEL)?;
    verify_relationships(required(&entries, ROOT_MODEL_RELS)?, LEAF_MODEL)?;
    verify_root_model(required(&entries, ROOT_MODEL)?)?;
    verify_leaf_model(required(&entries, LEAF_MODEL)?)?;

    Ok(BambuExportArtifact {
        sha256: hex::encode(Sha256::digest(bytes)),
        size_bytes: u64::try_from(bytes.len()).map_err(|_| "3MF input size overflow")?,
        vertex_count: 4,
        triangle_count: 4,
    })
}

fn read_zip_entries(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|error| format!("invalid ZIP: {error}"))?;
    if archive.len() > MAX_ENTRIES {
        return Err("3MF ZIP has more than 32 entries".to_owned());
    }
    let mut entries = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut expanded = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("invalid ZIP entry: {error}"))?;
        let name = canonical_zip_path(entry.name())?;
        if !names.insert(name.to_ascii_lowercase()) {
            return Err("3MF ZIP has duplicate or case-ambiguous entry paths".to_owned());
        }
        if entry.is_dir() || entry.is_symlink() {
            return Err("3MF ZIP must not contain directories or symbolic links".to_owned());
        }
        if entry.encrypted() {
            return Err("3MF ZIP must not contain encrypted entries".to_owned());
        }
        if entry.size() > MAX_ENTRY_BYTES {
            return Err("3MF ZIP entry exceeds 1 MiB expansion limit".to_owned());
        }
        expanded = expanded
            .checked_add(entry.size())
            .ok_or("3MF ZIP expansion size overflow")?;
        if expanded > MAX_EXPANDED_BYTES {
            return Err("3MF ZIP exceeds 4 MiB expansion limit".to_owned());
        }
        let capacity = usize::try_from(entry.size()).map_err(|_| "3MF ZIP entry size overflow")?;
        let mut value = Vec::with_capacity(capacity);
        entry
            .by_ref()
            .take(MAX_ENTRY_BYTES + 1)
            .read_to_end(&mut value)
            .map_err(|error| format!("could not read ZIP entry: {error}"))?;
        if value.len() != capacity {
            return Err(
                "3MF ZIP entry size did not match its central-directory declaration".to_owned(),
            );
        }
        entries.insert(name, value);
    }
    Ok(entries)
}

fn canonical_zip_path(value: &str) -> Result<String, String> {
    if value.is_empty()
        || !value.is_ascii()
        || value.starts_with('/')
        || value.contains(['\\', ':', '\0'])
        || value.ends_with('/')
        || value
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err("3MF ZIP has an ambiguous entry path".to_owned());
    }
    Ok(value.to_owned())
}

fn required<'a>(entries: &'a BTreeMap<String, Vec<u8>>, path: &str) -> Result<&'a [u8], String> {
    entries
        .get(path)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("3MF ZIP is missing required entry {path}"))
}

fn verify_content_types(bytes: &[u8]) -> Result<(), String> {
    let mut has_model = false;
    let mut has_relationships = false;
    parse_xml(bytes, |name, attributes, _depth| {
        if name == "Default" {
            match (
                attribute(&attributes, "Extension"),
                attribute(&attributes, "ContentType"),
            ) {
                (Some("model"), Some("application/vnd.ms-package.3dmanufacturing-3dmodel+xml")) => {
                    has_model = true
                }
                (
                    Some("rels"),
                    Some("application/vnd.openxmlformats-package.relationships+xml"),
                ) => has_relationships = true,
                _ => {}
            }
        }
        Ok(())
    })?;
    if has_model && has_relationships {
        Ok(())
    } else {
        Err("3MF content types do not declare model and relationship parts".to_owned())
    }
}

fn verify_relationships(bytes: &[u8], required_target: &str) -> Result<(), String> {
    let mut matching = 0_u8;
    parse_xml(bytes, |name, attributes, _depth| {
        if name != "Relationship" {
            return Ok(());
        }
        let target =
            attribute(&attributes, "Target").ok_or("3MF relationship is missing Target")?;
        let target_mode = attribute(&attributes, "TargetMode");
        if target_mode.is_some_and(|mode| mode.eq_ignore_ascii_case("external"))
            || !safe_relationship_target(target)
        {
            return Err(
                "3MF package contains an external or ambiguous relationship target".to_owned(),
            );
        }
        if attribute(&attributes, "Type") == Some(MODEL_RELATIONSHIP) {
            if target != format!("/{required_target}") {
                return Err(
                    "3MF model relationship does not target the reviewed model part".to_owned(),
                );
            }
            matching = matching
                .checked_add(1)
                .ok_or("too many 3MF model relationships")?;
        }
        Ok(())
    })?;
    if matching == 1 {
        Ok(())
    } else {
        Err("3MF package must contain exactly one reviewed model relationship".to_owned())
    }
}

fn safe_relationship_target(value: &str) -> bool {
    value.starts_with('/')
        && value.is_ascii()
        && !value.contains(['\\', ':', '#', '?'])
        && value
            .split('/')
            .skip(1)
            .all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."))
}

fn verify_root_model(bytes: &[u8]) -> Result<(), String> {
    let document = parse_model_xml(bytes)?;
    require_model_structure(&document, true)?;
    let resources = exactly_one_named_child(&document, 0, "resources")?;
    let object = exactly_one_child(&document, resources, "object")?;
    let components = exactly_one_child(&document, object, "components")?;
    let component = exactly_one_child(&document, components, "component")?;
    let build = exactly_one_named_child(&document, 0, "build")?;
    let item = exactly_one_child(&document, build, "item")?;
    if attribute(&document[object].attributes, "id") != Some("2")
        || attribute(&document[object].attributes, "type") != Some("model")
        || !document[component].raw_attributes.contains("p:path")
        || attribute(&document[component].attributes, "objectid") != Some("1")
        || attribute(&document[component].attributes, "p:path")
            != Some("/3D/Objects/object_1.model")
        || attribute(&document[component].attributes, "transform") != Some(COMPONENT_TRANSFORM)
        || attribute(&document[item].attributes, "objectid") != Some("2")
        || attribute(&document[item].attributes, "transform") != Some(BUILD_TRANSFORM)
        || attribute(&document[item].attributes, "printable") != Some("1")
    {
        return Err(
            "3MF root model does not contain the reviewed component and build graph".to_owned(),
        );
    }
    Ok(())
}

fn verify_leaf_model(bytes: &[u8]) -> Result<(), String> {
    let expected_vertices = [
        ("-0.5", "-0.5", "-0.5"),
        ("-0.5", "0.5", "-0.5"),
        ("0.5", "-0.5", "-0.5"),
        ("-0.5", "-0.5", "0.5"),
    ];
    let expected_triangles = [
        ("0", "1", "2"),
        ("0", "2", "3"),
        ("0", "3", "1"),
        ("2", "1", "3"),
    ];
    let document = parse_model_xml(bytes)?;
    require_model_structure(&document, false)?;
    let resources = exactly_one_named_child(&document, 0, "resources")?;
    let object = exactly_one_child(&document, resources, "object")?;
    let mesh = exactly_one_child(&document, object, "mesh")?;
    let vertices_element = exactly_one_named_child(&document, mesh, "vertices")?;
    let triangles_element = exactly_one_named_child(&document, mesh, "triangles")?;
    let build = exactly_one_named_child(&document, 0, "build")?;
    if !children(&document, build).is_empty()
        || attribute(&document[object].attributes, "id") != Some("1")
        || attribute(&document[object].attributes, "type") != Some("model")
    {
        return Err("3MF leaf model is not the reviewed tetrahedron".to_owned());
    }
    let vertices = children_named(&document, vertices_element, "vertex")
        .into_iter()
        .map(|index| {
            Ok((
                required_attribute(&document[index].attributes, "x")?.to_owned(),
                required_attribute(&document[index].attributes, "y")?.to_owned(),
                required_attribute(&document[index].attributes, "z")?.to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if children(&document, mesh).len() != 2
        || children(&document, vertices_element).len() != vertices.len()
        || children(&document, triangles_element).len()
            != children_named(&document, triangles_element, "triangle").len()
    {
        return Err("3MF leaf mesh has misplaced elements".to_owned());
    }
    let triangles = children_named(&document, triangles_element, "triangle")
        .into_iter()
        .map(|index| {
            Ok((
                required_attribute(&document[index].attributes, "v1")?.to_owned(),
                required_attribute(&document[index].attributes, "v2")?.to_owned(),
                required_attribute(&document[index].attributes, "v3")?.to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let expected_vertices: Vec<_> = expected_vertices
        .into_iter()
        .map(|(x, y, z)| (x.to_owned(), y.to_owned(), z.to_owned()))
        .collect();
    let expected_triangles: Vec<_> = expected_triangles
        .into_iter()
        .map(|(v1, v2, v3)| (v1.to_owned(), v2.to_owned(), v3.to_owned()))
        .collect();
    if vertices == expected_vertices && triangles == expected_triangles {
        Ok(())
    } else {
        Err("3MF leaf model is not the reviewed four-vertex, four-triangle tetrahedron".to_owned())
    }
}

fn parse_xml<F>(bytes: &[u8], mut on_element: F) -> Result<(), String>
where
    F: FnMut(&str, BTreeMap<String, String>, usize) -> Result<(), String>,
{
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut depth = 0_usize;
    loop {
        match reader
            .read_event_into(&mut buffer)
            .map_err(|error| format!("invalid XML: {error}"))?
        {
            Event::Start(element) => {
                let (name, attributes) = element_parts(&element)?;
                on_element(&name, attributes, depth)?;
                depth = depth.checked_add(1).ok_or("XML nesting depth overflow")?;
            }
            Event::Empty(element) => {
                let (name, attributes) = element_parts(&element)?;
                on_element(&name, attributes, depth)?;
            }
            Event::End(_) => depth = depth.checked_sub(1).ok_or("invalid XML nesting")?,
            Event::DocType(_) | Event::GeneralRef(_) | Event::PI(_) => {
                return Err(
                    "3MF XML must not contain DTDs, entities, or processing instructions"
                        .to_owned(),
                );
            }
            Event::Text(text) if text.as_ref().contains(&b'&') => {
                return Err("3MF XML must not contain entity references".to_owned());
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if depth == 0 {
        Ok(())
    } else {
        Err("invalid XML nesting".to_owned())
    }
}

struct ModelElement {
    name: String,
    attributes: BTreeMap<String, String>,
    raw_attributes: BTreeSet<String>,
    parent: Option<usize>,
}

fn parse_model_xml(bytes: &[u8]) -> Result<Vec<ModelElement>, String> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut elements = Vec::new();
    let mut stack = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buffer)
            .map_err(|error| format!("invalid XML: {error}"))?
        {
            Event::Start(element) => {
                let (name, attributes) = element_parts(&element)?;
                let raw_attributes = raw_attribute_names(&element)?;
                let parent = stack.last().copied();
                reject_namespace_shadow(parent, &raw_attributes)?;
                let index = elements.len();
                elements.push(ModelElement {
                    name,
                    attributes,
                    raw_attributes,
                    parent,
                });
                stack.push(index);
            }
            Event::Empty(element) => {
                let (name, attributes) = element_parts(&element)?;
                let raw_attributes = raw_attribute_names(&element)?;
                reject_namespace_shadow(stack.last().copied(), &raw_attributes)?;
                elements.push(ModelElement {
                    name,
                    attributes,
                    raw_attributes,
                    parent: stack.last().copied(),
                });
            }
            Event::End(_) => {
                stack.pop().ok_or("invalid XML nesting")?;
            }
            Event::DocType(_) | Event::GeneralRef(_) | Event::PI(_) => {
                return Err(
                    "3MF XML must not contain DTDs, entities, or processing instructions"
                        .to_owned(),
                );
            }
            Event::Text(text) if text.as_ref().contains(&b'&') => {
                return Err("3MF XML must not contain entity references".to_owned());
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if stack.is_empty() && !elements.is_empty() {
        Ok(elements)
    } else {
        Err("invalid XML nesting".to_owned())
    }
}

fn raw_attribute_names(element: &BytesStart<'_>) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| format!("invalid XML attribute: {error}"))?;
        let name = std::str::from_utf8(attribute.key.as_ref())
            .map_err(|_| "3MF XML attribute is not UTF-8")?
            .to_owned();
        if !names.insert(name) {
            return Err("3MF XML has duplicate attribute names".to_owned());
        }
    }
    Ok(names)
}

fn reject_namespace_shadow(
    parent: Option<usize>,
    raw_attributes: &BTreeSet<String>,
) -> Result<(), String> {
    if parent.is_some() && raw_attributes.iter().any(|name| name.starts_with("xmlns")) {
        return Err("3MF model must not shadow its reviewed namespaces".to_owned());
    }
    Ok(())
}

fn require_model_structure(
    document: &[ModelElement],
    root_uses_production: bool,
) -> Result<(), String> {
    let root = document.first().ok_or("3MF model is empty")?;
    require_core_model_root(&root.name, &root.attributes)?;
    if root.parent.is_some()
        || document
            .iter()
            .skip(1)
            .any(|element| element.parent.is_none())
        || (root_uses_production && !root.raw_attributes.contains("xmlns:p")
            || root_uses_production
                && attribute(&root.attributes, "xmlns:p") != Some(PRODUCTION_3MF_NAMESPACE))
    {
        return Err("3MF model namespace declarations are not the reviewed values".to_owned());
    }
    for index in 1..document.len() {
        let parent = document[index]
            .parent
            .ok_or("3MF model has a detached element")?;
        if parent >= index {
            return Err("3MF model has an invalid element hierarchy".to_owned());
        }
    }
    let root_children = children(document, 0);
    if root_children.iter().any(|index| {
        !matches!(
            document[*index].name.as_str(),
            "metadata" | "resources" | "build"
        )
    }) || root_children
        .iter()
        .filter(|index| document[**index].name == "resources")
        .count()
        != 1
        || root_children
            .iter()
            .filter(|index| document[**index].name == "build")
            .count()
            != 1
        || root_children
            .iter()
            .filter(|index| document[**index].name == "metadata")
            .any(|index| !children(document, *index).is_empty())
    {
        return Err("3MF model has an unexpected root structure".to_owned());
    }
    Ok(())
}

fn children(document: &[ModelElement], parent: usize) -> Vec<usize> {
    document
        .iter()
        .enumerate()
        .filter_map(|(index, element)| (element.parent == Some(parent)).then_some(index))
        .collect()
}

fn children_named(document: &[ModelElement], parent: usize, name: &str) -> Vec<usize> {
    children(document, parent)
        .into_iter()
        .filter(|index| document[*index].name == name)
        .collect()
}

fn exactly_one_child(
    document: &[ModelElement],
    parent: usize,
    name: &str,
) -> Result<usize, String> {
    let named_children = children_named(document, parent, name);
    if named_children.len() == 1 && children(document, parent).len() == 1 {
        Ok(named_children[0])
    } else {
        Err(format!(
            "3MF model must contain exactly one {name} in the reviewed hierarchy"
        ))
    }
}

fn exactly_one_named_child(
    document: &[ModelElement],
    parent: usize,
    name: &str,
) -> Result<usize, String> {
    let named_children = children_named(document, parent, name);
    if named_children.len() == 1 {
        Ok(named_children[0])
    } else {
        Err(format!(
            "3MF model must contain exactly one {name} in the reviewed hierarchy"
        ))
    }
}

fn element_parts(element: &BytesStart<'_>) -> Result<(String, BTreeMap<String, String>), String> {
    let raw_name = std::str::from_utf8(element.name().as_ref())
        .map_err(|_| "3MF XML element is not UTF-8")?
        .to_owned();
    if raw_name.contains(':') {
        return Err("3MF XML must not use prefixed element names".to_owned());
    }
    let mut attributes = BTreeMap::new();
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| format!("invalid XML attribute: {error}"))?;
        let key = std::str::from_utf8(attribute.key.as_ref())
            .map_err(|_| "3MF XML attribute is not UTF-8")?
            .to_owned();
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|error| format!("invalid XML attribute value: {error}"))?
            .into_owned();
        if value.contains('&') || attributes.insert(key, value).is_some() {
            return Err(
                "3MF XML has entity references or duplicate local attribute names".to_owned(),
            );
        }
    }
    Ok((raw_name, attributes))
}

fn require_core_model_root(
    name: &str,
    attributes: &BTreeMap<String, String>,
) -> Result<(), String> {
    if name != "model" || attribute(attributes, "xmlns") != Some(CORE_3MF_NAMESPACE) {
        return Err("3MF model does not declare the reviewed core namespace".to_owned());
    }
    Ok(())
}

fn attribute<'a>(attributes: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    attributes.get(name).map(String::as_str)
}

fn required_attribute<'a>(
    attributes: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, String> {
    attribute(attributes, name).ok_or_else(|| format!("3MF XML element is missing {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    const TYPES: &str = r#"<Types><Default Extension="model" ContentType="application/vnd.ms-package.3dmanufacturing-3dmodel+xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/></Types>"#;
    const ROOT_RELS_XML: &str = r#"<Relationships><Relationship Id="r" Type="http://schemas.microsoft.com/3dmanufacturing/2013/01/3dmodel" Target="/3D/3dmodel.model"/></Relationships>"#;
    const MODEL_RELS_XML: &str = r#"<Relationships><Relationship Id="r" Type="http://schemas.microsoft.com/3dmanufacturing/2013/01/3dmodel" Target="/3D/Objects/object_1.model"/></Relationships>"#;
    const ROOT_XML: &str = r#"<model xmlns="http://schemas.microsoft.com/3dmanufacturing/core/2015/02" xmlns:p="http://schemas.microsoft.com/3dmanufacturing/production/2015/06"><resources><object id="2" type="model"><components><component p:path="/3D/Objects/object_1.model" objectid="1" transform="1 0 0 0 1 0 0 0 1 0.5 0.5 0.5"/></components></object></resources><build><item objectid="2" printable="1" transform="1 0 0 0 1 0 0 0 1 99.41021 99.41022 0"/></build></model>"#;
    const LEAF_XML: &str = r#"<model xmlns="http://schemas.microsoft.com/3dmanufacturing/core/2015/02"><resources><object id="1" type="model"><mesh><vertices><vertex x="-0.5" y="-0.5" z="-0.5"/><vertex x="-0.5" y="0.5" z="-0.5"/><vertex x="0.5" y="-0.5" z="-0.5"/><vertex x="-0.5" y="-0.5" z="0.5"/></vertices><triangles><triangle v1="0" v2="1" v3="2"/><triangle v1="0" v2="2" v3="3"/><triangle v1="0" v2="3" v3="1"/><triangle v1="2" v2="1" v3="3"/></triangles></mesh></object></resources><build/></model>"#;

    fn package(parts: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        for (path, contents) in parts {
            writer
                .start_file(
                    *path,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
                )
                .expect("ZIP entry should start");
            writer.write_all(contents).expect("ZIP entry should write");
        }
        writer.finish().expect("ZIP should finish").into_inner()
    }

    fn valid_package() -> Vec<u8> {
        package_with_models(ROOT_XML, LEAF_XML)
    }

    fn package_with_models(root: &str, leaf: &str) -> Vec<u8> {
        package(&[
            ("[Content_Types].xml", TYPES.as_bytes()),
            (ROOT_RELS, ROOT_RELS_XML.as_bytes()),
            (ROOT_MODEL_RELS, MODEL_RELS_XML.as_bytes()),
            (ROOT_MODEL, root.as_bytes()),
            (LEAF_MODEL, leaf.as_bytes()),
        ])
    }

    #[test]
    fn verifies_referenced_tetrahedron() {
        let bytes = valid_package();
        assert_eq!(
            verify_bambu_export(&bytes).expect("valid fixture"),
            BambuExportArtifact {
                sha256: hex::encode(Sha256::digest(&bytes)),
                size_bytes: bytes.len() as u64,
                vertex_count: 4,
                triangle_count: 4
            }
        );
    }

    #[test]
    fn rejects_wrong_mesh_and_references() {
        let wrong_leaf = LEAF_XML.replacen("x=\"0.5\"", "x=\"0.6\"", 1);
        let bytes = package(&[
            ("[Content_Types].xml", TYPES.as_bytes()),
            (ROOT_RELS, ROOT_RELS_XML.as_bytes()),
            (ROOT_MODEL_RELS, MODEL_RELS_XML.as_bytes()),
            (ROOT_MODEL, ROOT_XML.as_bytes()),
            (LEAF_MODEL, wrong_leaf.as_bytes()),
        ]);
        assert!(verify_bambu_export(&bytes).is_err());
        let foreign = ROOT_RELS_XML.replace("/3D/3dmodel.model", "https://example.invalid/model");
        let bytes = package(&[
            ("[Content_Types].xml", TYPES.as_bytes()),
            (ROOT_RELS, foreign.as_bytes()),
            (ROOT_MODEL_RELS, MODEL_RELS_XML.as_bytes()),
            (ROOT_MODEL, ROOT_XML.as_bytes()),
            (LEAF_MODEL, LEAF_XML.as_bytes()),
        ]);
        assert!(verify_bambu_export(&bytes).is_err());
    }

    #[test]
    fn rejects_xml_entities_duplicate_paths_and_bombs() {
        let dtd = b"<!DOCTYPE model [<!ENTITY x 'bad'>]><model>&x;</model>";
        let bytes = package(&[
            ("[Content_Types].xml", TYPES.as_bytes()),
            (ROOT_RELS, ROOT_RELS_XML.as_bytes()),
            (ROOT_MODEL_RELS, MODEL_RELS_XML.as_bytes()),
            (ROOT_MODEL, ROOT_XML.as_bytes()),
            (LEAF_MODEL, dtd),
        ]);
        assert!(verify_bambu_export(&bytes).is_err());
        let bytes = package(&[
            ("[Content_Types].xml", TYPES.as_bytes()),
            ("[content_types].xml", TYPES.as_bytes()),
        ]);
        assert!(verify_bambu_export(&bytes).is_err());
        let bomb = vec![0_u8; MAX_ENTRY_BYTES as usize + 1];
        let bytes = package(&[("large.bin", &bomb)]);
        assert!(bytes.len() <= MAX_INPUT_BYTES);
        assert!(verify_bambu_export(&bytes).is_err());
    }

    #[test]
    fn rejects_misplaced_mesh_graphs_and_namespace_shadowing() {
        let misplaced_root = r#"<model xmlns="http://schemas.microsoft.com/3dmanufacturing/core/2015/02" xmlns:p="http://schemas.microsoft.com/3dmanufacturing/production/2015/06"><resources><object id="2" type="model"/></resources><component p:path="/3D/Objects/object_1.model" objectid="1" transform="1 0 0 0 1 0 0 0 1 0.5 0.5 0.5"/><build><item objectid="2" printable="1" transform="1 0 0 0 1 0 0 0 1 99.41021 99.41022 0"/></build></model>"#;
        assert!(verify_bambu_export(&package_with_models(misplaced_root, LEAF_XML)).is_err());

        let misplaced_leaf = r#"<model xmlns="http://schemas.microsoft.com/3dmanufacturing/core/2015/02"><resources><object id="1" type="model"><mesh/></object></resources><metadata><vertices><vertex x="-0.5" y="-0.5" z="-0.5"/><vertex x="-0.5" y="0.5" z="-0.5"/><vertex x="0.5" y="-0.5" z="-0.5"/><vertex x="-0.5" y="-0.5" z="0.5"/></vertices><triangles><triangle v1="0" v2="1" v3="2"/><triangle v1="0" v2="2" v3="3"/><triangle v1="0" v2="3" v3="1"/><triangle v1="2" v2="1" v3="3"/></triangles></metadata><build/></model>"#;
        assert!(verify_bambu_export(&package_with_models(ROOT_XML, misplaced_leaf)).is_err());

        let shadowed_namespace =
            ROOT_XML.replacen("<components>", "<components xmlns=\"urn:unreviewed\">", 1);
        assert!(verify_bambu_export(&package_with_models(&shadowed_namespace, LEAF_XML)).is_err());

        let prefixed_object_id = ROOT_XML
            .replacen("<model ", "<model xmlns:x=\"urn:unreviewed\" ", 1)
            .replacen("objectid=\"1\"", "x:objectid=\"1\"", 1);
        assert!(verify_bambu_export(&package_with_models(&prefixed_object_id, LEAF_XML)).is_err());
    }

    #[test]
    fn verifies_retained_export_when_opted_in() {
        let Some(path) = std::env::var_os("AIW_BAMBU_RETAINED_3MF") else {
            return;
        };
        let bytes = std::fs::read(path).expect("retained export should be readable");
        let result = verify_bambu_export(&bytes).expect("retained export should verify");
        assert_eq!(
            result.sha256,
            "56511b82a0f9a10c4d10e60aa87e6074a182063acc14c3927f6b706e14fb2355"
        );
        assert_eq!(result.size_bytes, 9061);
    }
}
