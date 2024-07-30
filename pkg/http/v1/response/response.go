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

func New() Response {
	return &response{}
}

func (r *response) SetError(err string) {
	r.Err = append(r.Err, errorMsg{
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
		r.Err = make([]errorMsg, 0)
	}

	json.NewEncoder(w).Encode(r)
}
