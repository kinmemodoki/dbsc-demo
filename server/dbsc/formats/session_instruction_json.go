package formats

type SessionInstructionResponse struct {
	SessionIdentifier        string                         `json:"session_identifier,omitempty"`
	RefreshURL               string                         `json:"refresh_url,omitempty"`
	Continue                 bool                           `json:"continue,omitempty"`
	Scope                    SessionInstructionScope        `json:"scope,omitempty"`       // MUST(except when the value of the continue key is false)
	Credentials              []SessionInstructionCredential `json:"credentials,omitempty"` // MUST(except when the value of the continue key is false)
	AllowedRefreshInitiators []string                       `json:"allowed_refresh_initiators,omitempty"`
}

type SessionInstructionCredential struct {
	Type       string `json:"type"` // MUST be "cookie"
	Name       string `json:"name,omitempty"`
	Attributes string `json:"attributes,omitempty"`
}

type SessionInstructionScope struct {
	Origin             string                                 `json:"origin,omitempty"`
	IncludeSite        bool                                   `json:"include_site,omitempty"`
	ScopeSpecification []SessionInstructionScopeSpecification `json:"scope_specification,omitempty"`
}

type SessionInstructionScopeSpecification struct {
	Type   string `json:"type"`
	Domain string `json:"domain,omitempty"`
	Path   string `json:"path,omitempty"`
}
