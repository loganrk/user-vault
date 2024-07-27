package response

import (
	"encoding/json"
	"net/http"
)

type Response interface {
	SetError(err string)
	SetData(data any)
	Send(w http.ResponseWriter)
}

type response struct {
	Success bool       `json:"success"`
	Err     []ErrorMsg `json:"error,omitempty"`
	Data    any        `json:"data,omitempty"`
}

type ErrorMsg struct {
	Msg string `json:"msg"`
}

func New() Response {
	return &response{}
}

func (r *response) SetError(err string) {
	r.Err = append(r.Err, ErrorMsg{
		Msg: err,
	})
}

func (r *response) SetData(data any) {
	r.Data = data
}

func (r *response) Send(w http.ResponseWriter) {
	if len(r.Err) > 0 {
		r.Success = false
		r.Data = struct{}{}
	} else {
		r.Success = true
		r.Err = make([]ErrorMsg, 0)
	}

	json.NewEncoder(w).Encode(r)
}
