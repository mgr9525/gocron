package models

type HbtpRequest struct {
	Id      int64  `json:"id"`
	Timeout int    `json:"timeout"`
	Command string `json:"command"`
}
