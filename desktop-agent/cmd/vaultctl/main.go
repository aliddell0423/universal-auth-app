package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/logins"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/passgen"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/sshagent"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmds := map[string]func([]string) error{
		"add": add, "get": get, "list": list, "edit": edit, "delete": del,
		"generate": generate, "link": link, "unlink": unlink,
	}
	run, ok := cmds[os.Args[1]]
	if !ok {
		usage()
		os.Exit(1)
	}
	if err := run(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: vaultctl <command> [flags]

Selecting an entry (get, edit, delete):
  --id CREDENTIAL_ID | --origin URL | --name NAME   [--account LABEL] [--kind KIND]

  add       --origin URL [--account LABEL] --username U
                [--password-stdin | --generate [--rules R] [--length N] [--no-symbols]]
            --kind secret|ssh_key --name NAME --field KEY=VALUE ... [--field-file KEY=PATH]
            Stores a new entry. No Pixel approval is needed.
  get       <select> [--field KEY] [--json]
            Releases the entry after Pixel approval and prints it.
  list      [--origin URL | --name NAME]   Metadata only, no secrets.
  edit      <select> [--set-origin URL | --set-name NAME] [--set-account LABEL]
                [--username U] [--password-stdin | --prompt-password | --generate ...]
                [--field KEY=VALUE ...] [--field-file KEY=PATH] [--remove-field KEY]
            Changes an entry after Pixel approval. Fields you do not supply are
            kept, which needs one extra approval to read them first.
  delete    <select>   Deletes after Pixel approval.
  generate  [--rules R] [--length N] [--no-symbols] [--symbols SET]
            Prints a password. R uses the passwordrules syntax, e.g.
            "minlength: 8; maxlength: 16; required: upper; required: digit; allowed: lower".
  link      --site URL --to URL   Offer logins saved for --to on --site too.
  unlink    --site URL --to URL`)
}

// ---- flag helpers ----

type multiFlag []string

func (f *multiFlag) String() string { return strings.Join(*f, ",") }
func (f *multiFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

type selector struct {
	id, origin, name, account, kind *string
	accountSet                      bool
}

func addSelector(fs *flag.FlagSet) *selector {
	return &selector{
		id:      fs.String("id", "", "credential id"),
		origin:  fs.String("origin", "", "login origin, e.g. https://github.com"),
		name:    fs.String("name", "", "secret name, e.g. api-keys/github"),
		account: fs.String("account", "", "account label, when a site has several"),
		kind:    fs.String("kind", "", "restrict to this kind"),
	}
}

func (s *selector) parsed(fs *flag.FlagSet) {
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "account" {
			s.accountSet = true
		}
	})
}

// resolve finds the single entry the selector names.
func (s *selector) resolve(ctx context.Context, vc *vault.Client) (vault.CredentialMeta, error) {
	if *s.id != "" {
		pkg, err := vc.GetPackageByID(ctx, *s.id, "")
		if err != nil {
			return vault.CredentialMeta{}, err
		}
		return vault.CredentialMeta{CredentialID: pkg.CredentialID, Kind: kindOf(pkg), Resource: pkg.Res(), Account: pkg.Account}, nil
	}
	resource, kind, err := resolveResource(*s.origin, *s.name, *s.kind)
	if err != nil {
		return vault.CredentialMeta{}, err
	}
	items, err := vc.ListResource(ctx, resource, kind, "")
	if err != nil {
		return vault.CredentialMeta{}, err
	}
	var hits []vault.CredentialMeta
	for _, m := range items {
		if !s.accountSet || m.Account == *s.account {
			hits = append(hits, m)
		}
	}
	switch len(hits) {
	case 0:
		return vault.CredentialMeta{}, fmt.Errorf("no saved entry for %s", resource)
	case 1:
		return hits[0], nil
	}
	var accts []string
	for _, m := range hits {
		accts = append(accts, fmt.Sprintf("%q (%s)", m.Account, m.CredentialID))
	}
	return vault.CredentialMeta{}, fmt.Errorf("%s has several entries; pick one with --account or --id: %s", resource, strings.Join(accts, ", "))
}

func resolveResource(origin, name, kind string) (string, string, error) {
	switch {
	case origin != "" && name != "":
		return "", "", errors.New("use only one of --origin or --name")
	case origin != "":
		r, err := vaultcrypto.NormalizeOrigin(origin)
		if kind == "" {
			kind = vaultcrypto.KindLogin
		}
		return r, kind, err
	case name != "":
		r, err := vaultcrypto.NormalizeSecretName(name)
		return r, kind, err
	default:
		return "", "", errors.New("one of --id, --origin or --name is required")
	}
}

func kindOf(pkg *vaultcrypto.Package) string {
	if pkg.Kind == "" {
		return vaultcrypto.KindLogin
	}
	return pkg.Kind
}

type genFlags struct {
	generate  *bool
	rules     *string
	length    *int
	noSymbols *bool
	symbols   *string
}

func addGenFlags(fs *flag.FlagSet, withSwitch bool) *genFlags {
	g := &genFlags{
		rules:     fs.String("rules", "", "site password rules (passwordrules syntax)"),
		length:    fs.Int("length", 0, "password length (default 20, or what --rules allow)"),
		noSymbols: fs.Bool("no-symbols", false, "letters and digits only"),
		symbols:   fs.String("symbols", "", "use exactly these symbol characters"),
	}
	if withSwitch {
		g.generate = fs.Bool("generate", false, "generate a strong password")
	} else {
		t := true
		g.generate = &t
	}
	return g
}

func (g *genFlags) password() (string, error) {
	p := passgen.Default()
	if *g.rules != "" {
		var err error
		if p, err = passgen.ParseRules(*g.rules); err != nil {
			return "", err
		}
	}
	if *g.noSymbols || *g.symbols != "" {
		sym := *g.symbols
		var req []string
		for _, r := range p.Required {
			if r != passgen.DefaultSymbols && r != passgen.Special {
				req = append(req, r)
			}
		}
		if sym != "" {
			req = append(req, sym)
		}
		p.Required = req
		p.Allowed = passgen.Lower + passgen.Upper + passgen.Digit + sym
	}
	if *g.length > 0 {
		p.Length = *g.length
	}
	return passgen.Generate(p)
}

func readPassword(fromStdin bool) (string, error) {
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("reading password: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

func parseFields(pairs, files multiFlag) (map[string]string, error) {
	fields := map[string]string{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid --field %q (want KEY=VALUE)", p)
		}
		fields[k] = v
	}
	for _, p := range files {
		k, path, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid --field-file %q (want KEY=PATH)", p)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		fields[k] = strings.TrimRight(string(b), "\r\n")
	}
	return fields, nil
}

func ctx10() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// ---- commands ----

func add(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	kind := fs.String("kind", vaultcrypto.KindLogin, "login, secret or ssh_key")
	origin := fs.String("origin", "", "login origin")
	name := fs.String("name", "", "secret name")
	account := fs.String("account", "", "account label (default: the username)")
	username := fs.String("username", "", "login username (may be empty)")
	pwStdin := fs.Bool("password-stdin", false, "read the password from stdin")
	gen := addGenFlags(fs, true)
	var pairs, files multiFlag
	fs.Var(&pairs, "field", "KEY=VALUE (repeatable)")
	fs.Var(&files, "field-file", "KEY=PATH (repeatable)")
	_ = fs.Parse(args)
	accountSet := false
	fs.Visit(func(f *flag.Flag) { accountSet = accountSet || f.Name == "account" })
	if !vaultcrypto.ValidKind(*kind) {
		return fmt.Errorf("unsupported kind %q", *kind)
	}

	var fields map[string]string
	var generated string
	resource := *name
	if *kind == vaultcrypto.KindLogin {
		resource = *origin
		var pw string
		var err error
		if *gen.generate {
			if pw, err = gen.password(); err != nil {
				return err
			}
			generated = pw
		} else if pw, err = readPassword(*pwStdin); err != nil {
			return err
		}
		if pw == "" {
			return errors.New("password is required")
		}
		fields = map[string]string{"username": *username, "password": pw}
		if !accountSet {
			*account = *username
		}
	} else {
		var err error
		if fields, err = parseFields(pairs, files); err != nil {
			return err
		}
		if len(fields) == 0 {
			return errors.New("at least one --field or --field-file is required")
		}
	}

	var sshID *sshagent.Identity
	if *kind == vaultcrypto.KindSSHKey {
		id, err := sshagent.IdentityFromFields(resource, fields)
		if err != nil {
			return err
		}
		sshID = &id
	}

	svc, err := logins.Load()
	if err != nil {
		return err
	}
	ctx, cancel := ctx10()
	defer cancel()
	pkg, err := svc.Save(ctx, *kind, resource, *account, fields, "")
	var exists *logins.ErrExists
	if errors.As(err, &exists) {
		return fmt.Errorf("%s already has an entry for account %q (%s); use 'vaultctl edit' or a different --account", resource, *account, exists.CredentialID)
	}
	if err != nil {
		return err
	}
	label := ""
	if pkg.Account != "" {
		label = " [" + pkg.Account + "]"
	}
	fmt.Fprintf(os.Stderr, "Stored %s %s%s (%s)\n", pkg.Kind, pkg.Resource, label, pkg.CredentialID)
	if generated != "" {
		fmt.Println(generated)
	}
	if sshID != nil {
		cache, err := sshagent.LoadPublicKeyCache(config.SSHPublicKeysPath())
		if err == nil {
			err = cache.Put(pkg.Resource, *sshID)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not cache public key (ua-ssh-agent will ask for one approval to learn it): %v\n", err)
		}
	}
	return nil
}

func get(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	sel := addSelector(fs)
	field := fs.String("field", "", "print only this field")
	asJSON := fs.Bool("json", false, "print fields as JSON")
	timeout := fs.Duration("timeout", 90*time.Second, "approval timeout")
	_ = fs.Parse(args)
	sel.parsed(fs)

	svc, err := logins.Load()
	if err != nil {
		return err
	}
	svc.Timeout = *timeout
	ctx, cancel := ctx10()
	meta, err := sel.resolve(ctx, svc.Vault)
	cancel()
	if err != nil {
		return err
	}
	res, _, err := svc.Release(context.Background(), meta.CredentialID, "")
	if err != nil {
		return fmt.Errorf("release failed: %w", err)
	}
	switch {
	case *asJSON:
		b, _ := json.Marshal(res.Fields)
		fmt.Println(string(b))
	case *field != "":
		v, ok := res.Fields[*field]
		if !ok {
			return fmt.Errorf("field %q not present", *field)
		}
		fmt.Println(v)
	default:
		keys := make([]string, 0, len(res.Fields))
		for k := range res.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("%s=%s\n", k, res.Fields[k])
		}
	}
	return nil
}

func list(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	origin := fs.String("origin", "", "only this login origin")
	name := fs.String("name", "", "only this secret name")
	_ = fs.Parse(args)
	svc, err := logins.Load()
	if err != nil {
		return err
	}
	ctx, cancel := ctx10()
	defer cancel()
	var items []vault.CredentialMeta
	if *origin != "" || *name != "" {
		resource, kind, err := resolveResource(*origin, *name, "")
		if err != nil {
			return err
		}
		items, err = svc.Vault.ListResource(ctx, resource, kind, "")
		if err != nil {
			return err
		}
	} else if items, err = svc.Vault.List(ctx, ""); err != nil {
		return err
	}
	for _, m := range items {
		fmt.Printf("%-8s %-42s %-28s %s\n", m.Kind, m.Resource, m.Account, m.CredentialID)
	}
	return nil
}

func edit(args []string) error {
	fs := flag.NewFlagSet("edit", flag.ExitOnError)
	sel := addSelector(fs)
	setOrigin := fs.String("set-origin", "", "move a login to this origin")
	setName := fs.String("set-name", "", "rename a secret")
	setAccount := fs.String("set-account", "", "new account label")
	username := fs.String("username", "", "new username")
	pwStdin := fs.Bool("password-stdin", false, "read the new password from stdin")
	pwPrompt := fs.Bool("prompt-password", false, "prompt for the new password")
	gen := addGenFlags(fs, true)
	var pairs, files, remove multiFlag
	fs.Var(&pairs, "field", "set KEY=VALUE (repeatable)")
	fs.Var(&files, "field-file", "set KEY=PATH (repeatable)")
	fs.Var(&remove, "remove-field", "remove KEY (repeatable)")
	timeout := fs.Duration("timeout", 90*time.Second, "approval timeout per step")
	_ = fs.Parse(args)
	sel.parsed(fs)
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	svc, err := logins.Load()
	if err != nil {
		return err
	}
	svc.Timeout = *timeout
	ctx, cancel := ctx10()
	meta, err := sel.resolve(ctx, svc.Vault)
	cancel()
	if err != nil {
		return err
	}
	account := meta.Account
	if set["set-account"] {
		account = *setAccount
	}
	newResource := *setOrigin
	if *setName != "" {
		newResource = *setName
	}

	changes, err := parseFields(pairs, files)
	if err != nil {
		return err
	}
	var generated string
	if meta.Kind == vaultcrypto.KindLogin {
		if set["username"] {
			changes["username"] = *username
		}
		switch {
		case *gen.generate:
			if generated, err = gen.password(); err != nil {
				return err
			}
			changes["password"] = generated
		case *pwStdin || *pwPrompt:
			pw, err := readPassword(*pwStdin)
			if err != nil {
				return err
			}
			if pw == "" {
				return errors.New("password is empty")
			}
			changes["password"] = pw
		}
	}

	bg := context.Background()
	if len(changes) == 0 && len(remove) == 0 && newResource == "" {
		if !set["set-account"] {
			return errors.New("nothing to change")
		}
		fmt.Fprintln(os.Stderr, "Approve the change on the Pixel...")
		if err := svc.Relabel(bg, meta.CredentialID, account, ""); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Updated %s (%s)\n", meta.Resource, meta.CredentialID)
		return nil
	}

	fields := changes
	complete := meta.Kind == vaultcrypto.KindLogin && set["username"] && changes["password"] != ""
	if !complete {
		fmt.Fprintln(os.Stderr, "Approve on the Pixel to read the current values...")
		res, _, err := svc.Release(bg, meta.CredentialID, "")
		if err != nil {
			return fmt.Errorf("release failed: %w", err)
		}
		fields = res.Fields
		for k, v := range changes {
			fields[k] = v
		}
	}
	for _, k := range remove {
		delete(fields, k)
	}
	fmt.Fprintln(os.Stderr, "Approve the change on the Pixel...")
	pkg, err := svc.Update(bg, meta.CredentialID, newResource, account, fields, "")
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Updated %s (%s)\n", pkg.Resource, pkg.CredentialID)
	if generated != "" {
		fmt.Println(generated)
	}
	return nil
}

func del(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	sel := addSelector(fs)
	timeout := fs.Duration("timeout", 90*time.Second, "approval timeout")
	_ = fs.Parse(args)
	sel.parsed(fs)
	svc, err := logins.Load()
	if err != nil {
		return err
	}
	svc.Timeout = *timeout
	ctx, cancel := ctx10()
	meta, err := sel.resolve(ctx, svc.Vault)
	cancel()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Approve deleting %s on the Pixel...\n", meta.Resource)
	if err := svc.Delete(context.Background(), meta.CredentialID, ""); err != nil {
		return err
	}
	fmt.Printf("Credential deleted: %s\n", meta.CredentialID)
	return nil
}

func generate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	gen := addGenFlags(fs, false)
	_ = fs.Parse(args)
	pw, err := gen.password()
	if err != nil {
		return err
	}
	fmt.Println(pw)
	return nil
}

func link(args []string) error   { return aliasCmd("link", args) }
func unlink(args []string) error { return aliasCmd("unlink", args) }

func aliasCmd(name string, args []string) error {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	site := fs.String("site", "", "page origin where the login should be offered")
	to := fs.String("to", "", "origin the login is saved under")
	_ = fs.Parse(args)
	if *site == "" || *to == "" {
		return errors.New("--site and --to are required")
	}
	store, err := logins.LoadAliases(logins.AliasesPath())
	if err != nil {
		return err
	}
	if name == "link" {
		err = store.Link(*site, *to)
	} else {
		err = store.Unlink(*site, *to)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%sed %s -> %s\n", name, *site, *to)
	return nil
}
