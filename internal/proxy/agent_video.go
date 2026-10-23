package proxy

// Explicit allowlist for the shared part of guest video telemetry. Application
// input, clipboard, tickets and controller-specific telemetry never fan out.
type agentVideoFacts struct {
	Capture *struct {
		Backend  string `json:"backend"`
		Output   string `json:"output"`
		Adapter  string `json:"adapter"`
		VendorID uint32 `json:"vendorId"`
		DeviceID uint32 `json:"deviceId"`
		Software *bool  `json:"software"`
	} `json:"capture"`
	Encoder *struct {
		Name     string `json:"name"`
		Codec    string `json:"codec"`
		Hardware *bool  `json:"hardware"`
	} `json:"encoder"`
}
