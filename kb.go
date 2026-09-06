package main

import (
	"flag"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// cmdKB serves the embedded OWASP knowledge base offline.
//   secskills kb                 list classes
//   secskills kb <class>         print a class's cheat-sheet content
//   secskills kb top10           the Top 10 -> class index
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
//   secskills recipes            list recipe files
//   secskills recipes <name>     print a recipe (e.g. injection)
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
