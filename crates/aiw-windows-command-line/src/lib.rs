#![forbid(unsafe_code)]

/// Quote one argument using the escaping rules consumed by CommandLineToArgvW.
pub fn quote_argument(value: &str) -> String {
    if !value.is_empty()
        && !value.chars().any(|character| {
            character.is_whitespace()
                || matches!(character, '"' | '&' | '|' | '<' | '>' | '(' | ')' | '^')
        })
    {
        return value.to_owned();
    }

    let mut result = String::from("\"");
    let mut backslashes = 0;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            result.push_str(&"\\".repeat(backslashes * 2 + 1));
            result.push('"');
            backslashes = 0;
        } else {
            result.push_str(&"\\".repeat(backslashes));
            backslashes = 0;
            result.push(character);
        }
    }
    result.push_str(&"\\".repeat(backslashes * 2));
    result.push('"');
    result
}

pub fn join_arguments<'a>(arguments: impl IntoIterator<Item = &'a str>) -> String {
    arguments
        .into_iter()
        .map(quote_argument)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_command_line_to_argv_w_edge_cases() {
        assert_eq!(quote_argument("simple"), "simple");
        assert_eq!(quote_argument("two words"), "\"two words\"");
        assert_eq!(quote_argument(""), "\"\"");
        assert_eq!(
            quote_argument("C:\\path with space\\"),
            "\"C:\\path with space\\\\\""
        );
        assert_eq!(quote_argument("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quote_argument("alpha&beta"), "\"alpha&beta\"");
    }

    #[test]
    fn joins_arguments_without_a_shell() {
        assert_eq!(
            join_arguments(["C:\\Program Files\\probe.exe", "--output", "C:\\out.json"]),
            "\"C:\\Program Files\\probe.exe\" --output C:\\out.json"
        );
    }
}
