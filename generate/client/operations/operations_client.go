// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"
)

// New creates a new operations API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) *Client {
	return &Client{transport: transport, formats: formats}
}

/*
Client for operations API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

/*
Range searches for exposed hashes

Search for exposed hases
*/
func (a *Client) Range(params *RangeParams) (*RangeOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRangeParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "range",
		Method:             "GET",
		PathPattern:        "/range/{prefix}",
		ProducesMediaTypes: []string{"*/*"},
		ConsumesMediaTypes: []string{""},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RangeReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*RangeOK), nil

}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
