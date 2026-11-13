package kb

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/gleicon/secskills"
	"github.com/gleicon/secskills/internal/textutil"
)

// KBClasses lists the embedded knowledge-base classes.
func KBClasses() []string {
	var out []string
	entries, _ := fs.ReadDir(secskills.KB, "kb")
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// KBClassText returns a class's content (used by the MCP server).
func KBClassText(class string) (string, error) {
	if !textutil.Contains(KBClasses(), class) {
		return "", fmt.Errorf("unknown class %q", class)
	}
	b, err := secskills.KB.ReadFile("kb/" + class + "/README.md")
	return string(b), err
}

// KBSummary lists classes as one string (MCP tool description helper).
func KBSummary() string {
	return "classes: " + strings.Join(KBClasses(), ", ")
}

// RecipeNames lists the embedded per-stack recipes.
func RecipeNames() []string {
	var out []string
	entries, _ := fs.ReadDir(secskills.Recipes, "recipes")
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") && e.Name() != "README.md" {
			out = append(out, strings.TrimSuffix(e.Name(), ".md"))
		}
	}
	sort.Strings(out)
	return out
}

// RecipeText returns one recipe by name (".md" optional).
func RecipeText(name string) (string, error) {
	b, err := secskills.Recipes.ReadFile("recipes/" + strings.TrimSuffix(name, ".md") + ".md")
	return string(b), err
}

// KBRemediation extracts the remediation guidance for a class from its embedded
// OWASP cheat-sheet entry, so reports quote the actual cheat sheet rather than a
// generic string. Returns "" if the class has no kb entry.
func KBRemediation(class string) string {
	b, err := secskills.KB.ReadFile("kb/" + class + "/README.md")
	if err != nil {
		return ""
	}
	body := stripFrontmatter(string(b))
	// collect lines under any heading whose text mentions remediation, or the
	// "Direction after findings" section — the actionable content of the sheet.
	var out []string
	capture := false
	for _, line := range strings.Split(body, "\n") {
		h := strings.HasPrefix(line, "#")
		if h {
			l := strings.ToLower(line)
			capture = strings.Contains(l, "remediation") || strings.Contains(l, "direction after") || strings.Contains(l, "prevention")
			continue
		}
		if capture && strings.TrimSpace(line) != "" {
			out = append(out, strings.TrimSpace(line))
			if len(strings.Join(out, " ")) > 900 {
				break
			}
		}
	}
	if len(out) == 0 {
		// fall back to actionable bullet lines anywhere in the sheet
		for _, line := range strings.Split(body, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "1.") {
				lt := strings.ToLower(t)
				if strings.Contains(lt, "use ") || strings.Contains(lt, "enforce") || strings.Contains(lt, "disable") ||
					strings.Contains(lt, "never") || strings.Contains(lt, "prefer") || strings.Contains(lt, "set ") {
					out = append(out, t)
				}
			}
			if len(strings.Join(out, " ")) > 700 {
				break
			}
		}
	}
	return strings.Join(out, "\n")
}

func stripFrontmatter(s string) string {
	s = strings.TrimLeft(s, "\n ")
	if strings.HasPrefix(s, "---") {
		if i := strings.Index(s[3:], "\n---"); i >= 0 {
			rest := s[3+i+4:]
			return strings.TrimLeft(rest, "\n")
		}
	}
	return s
}
