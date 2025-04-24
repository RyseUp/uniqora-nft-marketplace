package template

import (
	"bytes"
	"embed"
	"fmt"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/email_center/types"
	"path/filepath"
	"text/template"
)

//go:embed *.tmpl
var templateFiles embed.FS

type Manager struct {
	templates       map[types.EmailType]*template.Template
	defaultSubjects map[types.EmailType]string
}

func NewManager() (*Manager, error) {
	tm := &Manager{
		templates:       make(map[types.EmailType]*template.Template),
		defaultSubjects: make(map[types.EmailType]string),
	}

	tm.defaultSubjects[types.TypeVerification] = "Uniqora verification code"
	tm.defaultSubjects[types.TypeWelcome] = "Welcome to Uniqora"
	tm.defaultSubjects[types.TypeAccountCreated] = "Your Uniqora Account Has Been Created"
	tm.defaultSubjects[types.TypePasswordReset] = "Password Reset Request"
	tm.defaultSubjects[types.TypeNotification] = "Uniqora Notification"

	// Load templates from files
	if err := tm.loadTemplates(); err != nil {
		return nil, err
	}

	return tm, nil
}

func (tm *Manager) loadTemplates() error {
	templateMapping := map[string]types.EmailType{
		"verification.tmpl":    types.TypeVerification,
		"welcome.tmpl":         types.TypeWelcome,
		"account_created.tmpl": types.TypeAccountCreated,
		"password_reset.tmpl":  types.TypePasswordReset,
		"notification.tmpl":    types.TypeNotification,
	}

	entries, err := templateFiles.ReadDir(".")
	if err != nil {
		return fmt.Errorf("failed to read template directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".tmpl" {
			emailType, exists := templateMapping[entry.Name()]
			if !exists {
				continue
			}

			content, err := templateFiles.ReadFile(entry.Name())
			if err != nil {
				return fmt.Errorf("failed to read template %s: %w", entry.Name(), err)
			}

			tmpl, err := template.New(entry.Name()).Parse(string(content))
			if err != nil {
				return fmt.Errorf("failed to parse template %s: %w", entry.Name(), err)
			}

			tm.templates[emailType] = tmpl
		}
	}

	for _, emailType := range []types.EmailType{
		types.TypeVerification,
		types.TypeWelcome,
		types.TypeAccountCreated,
		types.TypePasswordReset,
		types.TypeNotification,
	} {
		if _, exists := tm.templates[emailType]; !exists {
			return fmt.Errorf("required template for email_center type %s not found", emailType)
		}
	}

	return nil
}

func (tm *Manager) RenderEmail(emailType types.EmailType, data map[string]string) (string, error) {
	tmpl, exists := tm.templates[emailType]
	if !exists {
		return "", fmt.Errorf("no template found for email_center type: %s", emailType)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("template execution error: %w", err)
	}

	return buf.String(), nil
}

func (tm *Manager) GetDefaultSubject(emailType types.EmailType) string {
	if subject, exists := tm.defaultSubjects[emailType]; exists {
		return subject
	}
	return "Uniqora Notification"
}
