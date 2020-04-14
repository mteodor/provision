package api

import (
	provSDK "github.com/mainflux/provision/sdk"
)

type addThingReq struct {
	ExternalID  string `json:"externalid"`
	ExternalKey string `json:"externalkey"`
}

func (req addThingReq) validate() error {
	if req.ExternalID == "" || req.ExternalKey == "" {
		return provSDK.ErrMalformedEntity
	}

	return nil
}
