//! Minimal line-oriented diff for staged configuration previews.

pub fn unified(old: &str, new: &str, old_label: &str, new_label: &str) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let mut table = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            table[i][j] = if a[i] == b[j] {
                table[i + 1][j + 1] + 1
            } else {
                table[i + 1][j].max(table[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0usize, 0usize);
    let mut body = Vec::new();
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            body.push(format!(" {}", a[i]));
            i += 1;
            j += 1;
        } else if table[i + 1][j] >= table[i][j + 1] {
            body.push(format!("-{}", a[i]));
            i += 1;
        } else {
            body.push(format!("+{}", b[j]));
            j += 1;
        }
    }
    while i < a.len() {
        body.push(format!("-{}", a[i]));
        i += 1;
    }
    while j < b.len() {
        body.push(format!("+{}", b[j]));
        j += 1;
    }
    let mut out = format!("--- {old_label}\n+++ {new_label}\n");
    out.push_str(&body.join("\n"));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_insertions_and_deletions() {
        let text = unified("a\nb\n", "a\nc\n", "running", "candidate");
        assert!(text.contains("-b"));
        assert!(text.contains("+c"));
        assert!(text.contains("--- running"));
    }

    #[test]
    fn identical_config_is_empty() {
        let text = unified("a\nb\n", "a\nb\n", "running", "candidate");
        assert!(!text.contains("-a") && !text.contains("+a"));
    }
}
