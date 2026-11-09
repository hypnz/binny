package gateway

import "openbin.ai/binny/internal/app"

// Profile is one bighelp "agent" the phone can pick. Per the chosen mapping,
// each profile is a binny project in a fixed analysis mode: the host is launched
// pointed at a project (and a mode), and that becomes a profile. The phone sees
// a short list and starts/reopens chats against one.
type Profile struct {
	Name      string   // stable id used on the wire (session.create "profile")
	Display   string   // human label
	IsDefault bool     // one profile is the default
	Mode      app.Mode // MALWARE | VULN_RESEARCH — the lens for this profile
	ProjectID string   // the binny project this profile analyzes
	ProjectNm string   // project display name (for description)
}

// wireProfile is the profiles.list row shape bighelp requires: name, is_default,
// has_avatar are mandatory; display_name/description are consumed when present.
func (p Profile) wire() map[string]any {
	desc := p.ProjectNm
	if desc != "" {
		desc = "binny " + string(p.Mode) + " · " + desc
	}
	return map[string]any{
		"name":         p.Name,
		"is_default":   p.IsDefault,
		"has_avatar":   false,
		"display_name": p.Display,
		"description":  desc,
	}
}
