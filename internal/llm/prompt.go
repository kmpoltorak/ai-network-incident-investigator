package llm

import (
	_ "embed"
	"encoding/json"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
)

//go:embed system_prompt.txt
var systemPrompt string

// analysisSchema is the JSON schema sent to providers that support
// constrained output. It is written in OpenAI strict-mode form (every
// property required, no additional properties), which Ollama also accepts.
var analysisSchema = json.RawMessage(`{
  "type": "object",
  "additionalProperties": false,
  "required": ["summary", "root_cause", "confidence", "severity", "evidence", "possible_causes", "recommended_actions"],
  "properties": {
    "summary": {"type": "string"},
    "root_cause": {"type": "string"},
    "confidence": {"type": "number"},
    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
    "evidence": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["source", "description"],
        "properties": {"source": {"type": "string"}, "description": {"type": "string"}}
      }
    },
    "possible_causes": {"type": "array", "items": {"type": "string"}},
    "recommended_actions": {"type": "array", "items": {"type": "string"}}
  }
}`)

type promptIncident struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	TargetHost  string `json:"target_host"`
	TargetPort  int    `json:"target_port,omitempty"`
}

type promptEvidence struct {
	Source  string          `json:"source"`
	Health  domain.Health   `json:"health"`
	Summary string          `json:"summary"`
	Data    json.RawMessage `json:"data"`
}

// userPrompt renders the incident and evidence as JSON. Only fields useful
// for analysis are included; database IDs and timestamps are omitted.
func userPrompt(in AnalysisInput) (string, error) {
	msg := struct {
		Incident promptIncident   `json:"incident"`
		Evidence []promptEvidence `json:"evidence"`
	}{
		Incident: promptIncident{
			Title:       in.Incident.Title,
			Description: in.Incident.Description,
			TargetHost:  in.Incident.TargetHost,
			TargetPort:  in.Incident.TargetPort,
		},
	}
	for _, e := range in.Evidence {
		msg.Evidence = append(msg.Evidence, promptEvidence{Source: e.Source, Health: e.Health, Summary: e.Summary, Data: e.Data})
	}
	b, err := json.MarshalIndent(msg, "", "  ")
	return string(b), err
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func messages(in AnalysisInput) ([]chatMessage, error) {
	user, err := userPrompt(in)
	if err != nil {
		return nil, err
	}
	return []chatMessage{{Role: "system", Content: systemPrompt}, {Role: "user", Content: user}}, nil
}
