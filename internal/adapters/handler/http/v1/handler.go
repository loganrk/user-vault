package v1

import (
	"encoding/json"
	"net/http"
	"userVault/internal/domain"
	"userVault/internal/port"
)

type handler struct {
	usecases       domain.List
	logger         port.Logger
	tokenEngineIns port.Token
}

func New(loggerIns port.Logger, tokenEngineIns port.Token, svcList domain.List) port.Handler {
	return &handler{
		usecases:       svcList,
		logger:         loggerIns,
		tokenEngineIns: tokenEngineIns,
	}
}

type response struct {
	Status  int        `json:"status"`
	Success bool       `json:"success"`
	Err     []errorMsg `json:"error,omitempty"`
	Data    any        `json:"data,omitempty"`
}

type errorMsg struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
}

func (r *response) SetError(errMsg string) {
	r.Err = append(r.Err, errorMsg{
		Msg: errMsg,
	})
}

func (r *response) SetStatus(status int) {
	r.Status = status
}

func (r *response) SetData(data any) {
	r.Data = data
}

func (r *response) Send(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
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
