use std::io::{BufRead, Read, Write};

use aiw_orchestrator::{ApprovalRecord, RunPlan};
use anyhow::Result;

pub(super) fn confirm(
    approval: &ApprovalRecord,
    plan: &RunPlan,
    input: impl Read,
    mut output: impl Write,
) -> Result<bool> {
    writeln!(
        output,
        "Review run approval\n\nThis records permission for the exact plan below. It does not start the run.\n"
    )?;
    // Escape terminal controls and Unicode direction overrides in untrusted text.
    // Show the whole plan so no action or trust delta is hidden by a summary.
    write_review_json(&mut output, plan)?;
    writeln!(output, "\n\nApproval identity and disclosures:")?;
    write_review_json(&mut output, approval)?;
    let expected = format!("approve {}", approval.plan_hash);
    writeln!(
        output,
        "\n\nTo approve, type exactly: {expected}\nAny other response cancels approval."
    )?;
    output.flush()?;
    let mut response = String::new();
    std::io::BufReader::new(input.take(256)).read_line(&mut response)?;
    Ok(response.trim_end_matches(['\r', '\n']) == expected)
}

fn write_review_json(output: &mut impl Write, value: &impl serde::Serialize) -> Result<()> {
    let mut escaped = Vec::new();
    for ch in serde_json::to_string_pretty(value)?.chars() {
        if ch.is_ascii() && ch != '\u{7f}' {
            write!(escaped, "{ch}")?;
        } else {
            for unit in ch.encode_utf16(&mut [0; 2]) {
                write!(escaped, "\\u{unit:04x}")?;
            }
        }
    }
    output.write_all(&escaped)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_requires_the_displayed_hash_and_escapes_controls() {
        let plan = RunPlan::new(
            "review-test",
            "project",
            "a".repeat(64),
            aiw_orchestrator::RunLifecycleKind::Assessment,
            "now",
            vec![aiw_orchestrator::PlannedAction::AssessHost],
            vec!["untrusted\u{1b}[2Jtext\u{009b}\u{202e}".into()],
        )
        .unwrap();
        let approval = ApprovalRecord::for_plan(&plan, "operator", "now").unwrap();
        for reply in [
            String::new(),
            "yes\n".into(),
            format!("approve {}\n", "b".repeat(64)),
            "x".repeat(300),
        ] {
            assert!(!confirm(&approval, &plan, reply.as_bytes(), Vec::new()).unwrap());
        }
        let mut rendered = Vec::new();
        assert!(
            confirm(
                &approval,
                &plan,
                format!("approve {}\r\n", approval.plan_hash).as_bytes(),
                &mut rendered,
            )
            .unwrap()
        );
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{009b}'));
        assert!(!rendered.contains('\u{202e}'));
        assert!(rendered.contains("untrusted\\u001b[2Jtext"));
        assert!(rendered.contains(&approval.plan_hash));
    }
}
