package response

import (
	"encoding/json"
	"net/http"
)

type Response interface {
	SetError(errCode string, errMsg string)
	SetStatus(status int)
	SetData(data any)
	Send(w http.ResponseWriter)
}

func New() Response {
	return &response{}
}

func (r *response) SetError(errCode string, errMsg string) {
	r.Err = append(r.Err, errorMsg{
		Code: errCode,
		Msg:  errMsg,
	})
}

func (r *response) SetStatus(status int) {
	r.Status = status
}

func (r *response) SetData(data any) {
	r.Data = data
}

func (r *response) Send(w http.ResponseWriter) {
	if len(r.Err) > 0 {
		w.WriteHeader(r.Status)
		r.Success = false
		r.Data = struct{}{}
	} else {
		w.WriteHeader(http.StatusOK)
		r.Status = http.StatusOK
		r.Success = true
		r.Err = make([]errorMsg, 0)
	}

	json.NewEncoder(w).Encode(r)
}
