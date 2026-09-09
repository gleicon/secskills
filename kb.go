package main

import (
	"flag"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// cmdKB serves the embedded OWASP knowledge base offline.
//
//	secskills kb                 list classes
//	secskills kb <class>         print a class's cheat-sheet content
//	secskills kb top10           the Top 10 -> class index
func cmdKB(args []string) error {
	fs2 := flag.NewFlagSet("kb", flag.ContinueOnError)
	list := fs2.Bool("list", false, "list classes and exit")
	if err := fs2.Parse(args); err != nil {
		return err
	}
	classes := kbClasses()
	if *list || fs2.NArg() == 0 {
		fmt.Println("OWASP knowledge base classes (offline, CC BY-SA 4.0):")
		for _, c := range classes {
			fmt.Println("  " + c)
		}
		fmt.Println("\nUsage: secskills kb <class>   (e.g. secskills kb injection)")
		return nil
	}
	class := fs2.Arg(0)
	if !contains(classes, class) {
		return fmt.Errorf("unknown class %q; run `secskills kb` to list", class)
	}
	data, err := kbFS.ReadFile("kb/" + class + "/README.md")
	if err != nil {
		return fmt.Errorf("reading class %q: %w", class, err)
	}
	fmt.Print(string(data))
	return nil
}

func kbClasses() []string {
	var out []string
	entries, _ := fs.ReadDir(kbFS, "kb")
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// kbClassText returns a class's content (used by the MCP server).
func kbClassText(class string) (string, error) {
	if !contains(kbClasses(), class) {
		return "", fmt.Errorf("unknown class %q", class)
	}
	b, err := kbFS.ReadFile("kb/" + class + "/README.md")
	return string(b), err
}

// kbSummary lists classes as one string (MCP tool description helper).
func kbSummary() string {
	return "classes: " + strings.Join(kbClasses(), ", ")
}

// cmdRecipes serves the embedded per-stack (Node/Python/Go) recipes.
//
//	secskills recipes            list recipe files
//	secskills recipes <name>     print a recipe (e.g. injection)
func cmdRecipes(args []string) error {
	names := recipeNames()
	if len(args) == 0 {
		fmt.Println("Per-stack recipes (Node.js / Python / Go):")
		for _, n := range names {
			fmt.Println("  " + n)
		}
		fmt.Println("\nUsage: secskills recipes <name>   (e.g. secskills recipes injection)")
		return nil
	}
	name := strings.TrimSuffix(args[0], ".md")
	b, err := recipesFS.ReadFile("recipes/" + name + ".md")
	if err != nil {
		return fmt.Errorf("no recipe %q; run `secskills recipes` to list", name)
	}
	fmt.Print(string(b))
	return nil
}

func recipeNames() []string {
	var out []string
	entries, _ := fs.ReadDir(recipesFS, "recipes")
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") && e.Name() != "README.md" {
			out = append(out, strings.TrimSuffix(e.Name(), ".md"))
		}
	}
	sort.Strings(out)
	return out
}

func recipeText(name string) (string, error) {
	b, err := recipesFS.ReadFile("recipes/" + strings.TrimSuffix(name, ".md") + ".md")
	return string(b), err
}

// kbRemediation extracts the remediation guidance for a class from its embedded
// OWASP cheat-sheet entry, so reports quote the actual cheat sheet rather than a
// generic string. Returns "" if the class has no kb entry.
func kbRemediation(class string) string {
	b, err := kbFS.ReadFile("kb/" + class + "/README.md")
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
