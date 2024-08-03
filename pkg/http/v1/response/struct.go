package response

type response struct {
	Success bool       `json:"success"`
	Err     []errorMsg `json:"error,omitempty"`
	Data    any        `json:"data,omitempty"`
}

type errorMsg struct {
	Msg string `json:"msg"`
}
