package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/gleicon/secskills"

	"github.com/gleicon/secskills/internal/kb"
	"github.com/gleicon/secskills/internal/textutil"
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
	classes := kb.KBClasses()
	if *list || fs2.NArg() == 0 {
		fmt.Println("OWASP knowledge base classes (offline, CC BY-SA 4.0):")
		for _, c := range classes {
			fmt.Println("  " + c)
		}
		fmt.Println("\nUsage: secskills kb <class>   (e.g. secskills kb injection)")
		return nil
	}
	class := fs2.Arg(0)
	if !textutil.Contains(classes, class) {
		return fmt.Errorf("unknown class %q; run `secskills kb` to list", class)
	}
	data, err := secskills.KB.ReadFile("kb/" + class + "/README.md")
	if err != nil {
		return fmt.Errorf("reading class %q: %w", class, err)
	}
	fmt.Print(string(data))
	return nil
}

// cmdRecipes serves the embedded per-stack (Node/Python/Go) recipes.
//
//	secskills recipes            list recipe files
//	secskills recipes <name>     print a recipe (e.g. injection)
func cmdRecipes(args []string) error {
	names := kb.RecipeNames()
	if len(args) == 0 {
		fmt.Println("Per-stack recipes (Node.js / Python / Go):")
		for _, n := range names {
			fmt.Println("  " + n)
		}
		fmt.Println("\nUsage: secskills recipes <name>   (e.g. secskills recipes injection)")
		return nil
	}
	name := strings.TrimSuffix(args[0], ".md")
	b, err := secskills.Recipes.ReadFile("recipes/" + name + ".md")
	if err != nil {
		return fmt.Errorf("no recipe %q; run `secskills recipes` to list", name)
	}
	fmt.Print(string(b))
	return nil
}
