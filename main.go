package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	dexapi "github.com/dexidp/dex/api/v2"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// OIDCConfig represents the configuration required for an OIDC connector.
type OIDCConfig struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
}

// CreateConnectorRequest represents the expected payload for creating or updating a connector.
type CreateConnectorRequest struct {
	ConnectorType    string `json:"connector_type" validate:"required,oneof=oidc"`                                  // 'oidc' is supported for now
	ConnectorSubType string `json:"connector_sub_type" validate:"omitempty,oneof=general google-workspace entraid"` // Optional sub-type
	Issuer           string `json:"issuer" validate:"omitempty,url"`
	TenantID         string `json:"tenant_id" validate:"omitempty,uuid"`
	ClientID         string `json:"client_id" validate:"required"`
	ClientSecret     string `json:"client_secret" validate:"required"`
	ID               string `json:"id,omitempty"`   // Optional
	Name             string `json:"name,omitempty"` // Optional
}

// DexClient wraps the Dex gRPC client and manages the connection.
type DexClient struct {
	client   dexapi.DexClient
	conn     *grpc.ClientConn
	logger   *logrus.Logger
	validate *validator.Validate
	restrict bool
}

// ConnectorCreator is a function type for creating connectors based on type.
type ConnectorCreator func(dc *DexClient, params map[string]string) (*dexapi.CreateConnectorResp, error)

// connectorCreators maps connector types to their respective creator functions.
var connectorCreators = map[string]ConnectorCreator{
	"oidc": (*DexClient).CreateOIDCConnector,
	// Future connector types can be added here, e.g., "saml": (*DexClient).CreateSAMLConnector
}

// SupportedConnectors holds the supported connector types and their sub-types.
var SupportedConnectors = map[string][]string{
	"oidc": {"general", "google-workspace", "entraid"},
	// Add more connector types and their sub-types here as needed.
}

// NewDexClient initializes a new DexClient with a connection to the Dex gRPC server.
// Supports both secure (TLS) and insecure (HTTP) connections based on provided certificates.
func NewDexClient(hostAndPort, caPath, clientCrt, clientKey string, logger *logrus.Logger, restrict bool) (*DexClient, error) {
	var opts []grpc.DialOption

	if caPath != "" && clientCrt != "" && clientKey != "" {
		// Setup TLS credentials
		cPool := x509.NewCertPool()
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			logger.Errorf("Invalid CA crt file: %s", caPath)
			return nil, fmt.Errorf("invalid CA crt file: %w", err)
		}
		if !cPool.AppendCertsFromPEM(caCert) {
			logger.Errorf("Failed to parse CA crt")
			return nil, fmt.Errorf("failed to parse CA crt")
		}

		clientCert, err := tls.LoadX509KeyPair(clientCrt, clientKey)
		if err != nil {
			logger.Errorf("Invalid client crt/key file: %s, %s", clientCrt, clientKey)
			return nil, fmt.Errorf("invalid client crt/key file: %w", err)
		}

		clientTLSConfig := &tls.Config{
			RootCAs:      cPool,
			Certificates: []tls.Certificate{clientCert},
		}
		creds := credentials.NewTLS(clientTLSConfig)
		opts = append(opts, grpc.WithTransportCredentials(creds))
		logger.Info("Configured gRPC client with TLS")
	} else {
		// Use insecure connection
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		logger.Info("Configured gRPC client with insecure connection")
	}

	// Set up blocking dial with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts = append(opts, grpc.WithBlock())

	conn, err := grpc.DialContext(ctx, hostAndPort, opts...)
	if err != nil {
		logger.Errorf("Failed to connect to Dex gRPC server: %v", err)
		return nil, fmt.Errorf("failed to connect to Dex gRPC server: %w", err)
	}

	client := dexapi.NewDexClient(conn)
	logger.Infof("Successfully connected to Dex gRPC server at %s", hostAndPort)

	// Initialize the validator
	validate := validator.New()

	return &DexClient{
		client:   client,
		conn:     conn,
		logger:   logger,
		validate: validate,
		restrict: restrict,
	}, nil
}

// Close gracefully closes the gRPC connection.
func (dc *DexClient) Close() error {
	err := dc.conn.Close()
	if err != nil {
		dc.logger.Errorf("Error closing Dex gRPC connection: %v", err)
		return err
	}
	dc.logger.Info("Dex gRPC connection closed successfully")
	return nil
}

// CreateOIDCConnector creates a new OIDC connector in Dex based on connector type and parameters.
func (dc *DexClient) CreateOIDCConnector(params map[string]string) (*dexapi.CreateConnectorResp, error) {
	connectorType := strings.ToLower(params["ConnectorType"])
	connectorSubType := strings.ToLower(params["ConnectorSubType"])

	var oidcConfig OIDCConfig
	var connectorID, connectorName string

	switch connectorType {
	case "oidc":
		switch connectorSubType {
		case "google-workspace":
			oidcConfig = OIDCConfig{
				Issuer:       params["Issuer"],
				ClientID:     params["ClientID"],
				ClientSecret: params["ClientSecret"],
			}
			connectorID = params["id"]
			connectorName = params["name"]
		case "entraid":
			if params["Issuer"] == "" && params["TenantID"] != "" {
				issuer, err := fetchEntraIDIssuer(params["TenantID"], dc.logger)
				if err != nil {
					return nil, fmt.Errorf("failed to fetch issuer for entraid: %w", err)
				}
				params["Issuer"] = issuer
			}
			oidcConfig = OIDCConfig{
				Issuer:       params["Issuer"],
				ClientID:     params["ClientID"],
				ClientSecret: params["ClientSecret"],
			}
			connectorID = params["id"]
			connectorName = params["name"]
		case "general":
			oidcConfig = OIDCConfig{
				Issuer:       params["Issuer"],
				ClientID:     params["ClientID"],
				ClientSecret: params["ClientSecret"],
			}
			connectorID = params["id"]
			connectorName = params["name"]

			if connectorID == "" {
				connectorID = "default-oidc"
			}
			if connectorName == "" {
				connectorName = "Default OIDC Connector"
			}
		default:
			return nil, fmt.Errorf("unsupported connector_sub_type: %s", connectorSubType)
		}
	default:
		return nil, fmt.Errorf("unsupported connector_type: %s", connectorType)
	}

	// If ID is still empty (for non-general types), set a default or handle accordingly
	if connectorID == "" {
		connectorID = fmt.Sprintf("%s-connector", connectorSubType) // e.g., "google-workspace-connector"
	}
	if connectorName == "" {
		connectorName = fmt.Sprintf("%s Connector", strings.Title(connectorSubType)) // e.g., "Google-Workspace Connector"
	}

	// **[Optional]** Add logging to verify connectorID and connectorName
	dc.logger.Debugf("Connector ID: %s, Connector Name: %s", connectorID, connectorName)

	// Serialize the OIDCConfig to JSON.
	configBytes, err := json.Marshal(oidcConfig)
	if err != nil {
		dc.logger.Errorf("Failed to marshal OIDC config: %v", err)
		return nil, fmt.Errorf("failed to marshal OIDC config: %w", err)
	}

	// Construct the Connector message.
	connector := &dexapi.Connector{
		Id:     connectorID,
		Type:   "oidc",
		Name:   connectorName,
		Config: configBytes,
	}

	// Create the CreateConnectorReq message.
	req := &dexapi.CreateConnectorReq{
		Connector: connector,
	}

	// Create a context with timeout for the gRPC call.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Execute the CreateConnector RPC.
	resp, err := dc.client.CreateConnector(ctx, req)
	if err != nil {
		dc.logger.Errorf("Failed to create connector (%s): %v", connectorID, err)
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}

	if resp.AlreadyExists {
		dc.logger.Infof("Connector (%s) already exists", connectorID)
	} else {
		dc.logger.Infof("Connector (%s) created successfully", connectorID)
	}

	return resp, nil
}

// fetchEntraIDIssuer fetches the issuer URL for EntraID based on tenant ID.
func fetchEntraIDIssuer(tenantID string, logger *logrus.Logger) (string, error) {
	url := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", tenantID)
	resp, err := http.Get(url)
	if err != nil {
		logger.Errorf("Failed to fetch OpenID configuration from %s: %v", url, err)
		return "", fmt.Errorf("failed to fetch OpenID configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Errorf("Unexpected status code %d when fetching OpenID configuration from %s", resp.StatusCode, url)
		return "", fmt.Errorf("unexpected status code %d when fetching OpenID configuration", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("Failed to read OpenID configuration response: %v", err)
		return "", fmt.Errorf("failed to read OpenID configuration response: %w", err)
	}

	var config struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		logger.Errorf("Failed to parse OpenID configuration: %v", err)
		return "", fmt.Errorf("failed to parse OpenID configuration: %w", err)
	}

	if config.Issuer == "" {
		logger.Error("Issuer not found in OpenID configuration")
		return "", fmt.Errorf("issuer not found in OpenID configuration")
	}

	logger.Debugf("Fetched EntraID issuer: %s", config.Issuer)

	return config.Issuer, nil
}

// UpdateOIDCConnector updates an existing OIDC connector's configuration in Dex.
func (dc *DexClient) UpdateOIDCConnector(connectorID string, params map[string]string) (*dexapi.UpdateConnectorResp, error) {
	connectorType := strings.ToLower(params["ConnectorType"])
	connectorSubType := strings.ToLower(params["ConnectorSubType"])

	var newOIDCConfig OIDCConfig

	switch connectorType {
	case "oidc":
		switch connectorSubType {
		case "google-workspace", "entraid", "general":
			if connectorSubType == "entraid" && params["Issuer"] == "" && params["TenantID"] != "" {
				issuer, err := fetchEntraIDIssuer(params["TenantID"], dc.logger)
				if err != nil {
					return nil, fmt.Errorf("failed to fetch issuer for entraid: %w", err)
				}
				params["Issuer"] = issuer
			}
			newOIDCConfig = OIDCConfig{
				Issuer:       params["Issuer"],
				ClientID:     params["ClientID"],
				ClientSecret: params["ClientSecret"],
			}
		default:
			return nil, fmt.Errorf("unsupported connector_sub_type: %s", connectorSubType)
		}
	default:
		return nil, fmt.Errorf("unsupported connector_type: %s", connectorType)
	}

	// Serialize the new OIDCConfig to JSON.
	configBytes, err := json.Marshal(newOIDCConfig)
	if err != nil {
		dc.logger.Errorf("Failed to marshal new OIDC config: %v", err)
		return nil, fmt.Errorf("failed to marshal new OIDC config: %w", err)
	}

	// Construct the UpdateConnectorReq message.
	req := &dexapi.UpdateConnectorReq{
		Id:        connectorID,
		NewConfig: configBytes,
	}

	// Create a context with timeout for the gRPC call.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Execute the UpdateConnector RPC.
	resp, err := dc.client.UpdateConnector(ctx, req)
	if err != nil {
		dc.logger.Errorf("Failed to update connector (%s): %v", connectorID, err)
		return nil, fmt.Errorf("failed to update connector: %w", err)
	}

	if resp.NotFound {
		dc.logger.Warnf("Connector (%s) not found for update", connectorID)
	} else {
		dc.logger.Infof("Connector (%s) updated successfully", connectorID)
	}

	return resp, nil
}

// DeleteConnectorByID deletes an existing connector from Dex based on connector ID.
func (dc *DexClient) DeleteConnectorByID(connectorID string) (*dexapi.DeleteConnectorResp, error) {
	// Construct the DeleteConnectorReq message.
	req := &dexapi.DeleteConnectorReq{
		Id: connectorID,
	}

	// Create a context with timeout for the gRPC call.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Execute the DeleteConnector RPC.
	resp, err := dc.client.DeleteConnector(ctx, req)
	if err != nil {
		dc.logger.Errorf("Failed to delete connector (%s): %v", connectorID, err)
		return nil, fmt.Errorf("failed to delete connector: %w", err)
	}

	if resp.NotFound {
		dc.logger.Warnf("Connector (%s) not found for deletion", connectorID)
	} else {
		dc.logger.Infof("Connector (%s) deleted successfully", connectorID)
	}

	return resp, nil
}

// ListConnectors retrieves all connectors from Dex.
func (dc *DexClient) ListConnectors() ([]*dexapi.Connector, error) {
	// Create the ListConnectorReq message.
	req := &dexapi.ListConnectorReq{}

	// Create a context with timeout for the gRPC call.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Execute the ListConnectors RPC.
	resp, err := dc.client.ListConnectors(ctx, req)
	if err != nil {
		dc.logger.Errorf("Failed to list connectors: %v", err)
		return nil, fmt.Errorf("failed to list connectors: %w", err)
	}

	dc.logger.Infof("Retrieved %d connectors from Dex", len(resp.Connectors))

	return resp.Connectors, nil
}

// CreateConnectorHandler handles the creation of connectors based on the type and sub-type specified in the URL.
func (dc *DexClient) CreateConnectorHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorType, exists := vars["connector_type"]
	connectorSubType, hasSubType := vars["connector_sub_type"]

	if !exists || strings.TrimSpace(connectorType) == "" {
		dc.logger.Warn("Missing connector_type in CreateConnectorHandler request")
		http.Error(w, "connector_type is required in the URL path", http.StatusBadRequest)
		return
	}

	connectorTypeLower := strings.ToLower(connectorType)
	creator, supported := connectorCreators[connectorTypeLower]
	if !supported {
		dc.logger.Warnf("Unsupported connector type: %s", connectorType)
		http.Error(w, fmt.Sprintf("unsupported connector type: %s", connectorType), http.StatusBadRequest)
		return
	}

	// Decode the request body into CreateConnectorRequest
	var reqData CreateConnectorRequest
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		dc.logger.Errorf("Invalid request body for CreateConnectorHandler: %v", err)
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Set the ConnectorType from URL path
	reqData.ConnectorType = connectorType

	// Set the ConnectorSubType from URL path or default to 'general'
	connectorSubTypeLower := "general" // default
	if hasSubType {
		connectorSubTypeLower = strings.ToLower(connectorSubType)
	}
	reqData.ConnectorSubType = connectorSubTypeLower

	// Validate the request payload
	if err := dc.validate.Struct(reqData); err != nil {
		dc.logger.Errorf("Validation error in CreateConnectorHandler: %v", err)
		http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
		return
	}

	// Additional conditional validation based on connector_type and connector_sub_type
	switch connectorTypeLower {
	case "oidc":
		if connectorSubTypeLower == "general" {
			// For 'general', either Issuer or TenantID is required
			if reqData.Issuer == "" && reqData.TenantID == "" {
				dc.logger.Warn("Missing issuer or tenant_id for general OIDC connector")
				http.Error(w, "issuer or tenant_id is required for general OIDC connector", http.StatusBadRequest)
				return
			}
		} else {
			// For specific sub-types like 'google-workspace' or 'entraid', ensure Issuer is provided
			if reqData.Issuer == "" {
				dc.logger.Warnf("Missing issuer for %s connector", connectorSubTypeLower)
				http.Error(w, fmt.Sprintf("issuer is required for %s connector", connectorSubTypeLower), http.StatusBadRequest)
				return
			}
		}
	default:
		// This case should not occur due to earlier check, but added for completeness
		dc.logger.Warnf("Unsupported connector type during validation: %s", connectorTypeLower)
		http.Error(w, fmt.Sprintf("unsupported connector type: %s", connectorTypeLower), http.StatusBadRequest)
		return
	}

	// Prepare parameters map with corrected key names and include sub-type
	params := map[string]string{
		"Issuer":           reqData.Issuer,
		"TenantID":         reqData.TenantID,
		"ClientID":         reqData.ClientID,
		"ClientSecret":     reqData.ClientSecret,
		"ConnectorType":    reqData.ConnectorType,
		"ConnectorSubType": reqData.ConnectorSubType, // New key for sub-type
		"id":               reqData.ID,               // Corrected to lowercase 'id'
		"name":             reqData.Name,             // Corrected to lowercase 'name'
	}

	// **[Optional]** Add logging to verify params
	dc.logger.Debugf("Creating connector with params: %+v", params)

	// Use the creator function to create the connector
	resp, err := creator(dc, params)
	if err != nil {
		dc.logger.Errorf("Error creating connector (%s/%s): %v", connectorType, connectorSubTypeLower, err)
		http.Error(w, fmt.Sprintf("error creating connector: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"message": "Connector created successfully.",
	}

	if resp.AlreadyExists {
		response["message"] = "Connector already exists."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	dc.logger.Debug("CreateConnectorHandler response sent to client")
}

// ListAndDescribeConnectorsHandler handles the GET /list and GET /list/{connector_type} endpoints.
func (dc *DexClient) ListAndDescribeConnectorsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorType, exists := vars["connector_type"]

	connectors, err := dc.ListConnectors()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error listing connectors: %v", err), http.StatusInternalServerError)
		return
	}

	type ConnectorInfo struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Name     string `json:"name"`
		Issuer   string `json:"issuer,omitempty"`
		ClientID string `json:"client_id,omitempty"`
	}

	var connectorInfos []ConnectorInfo

	for _, connector := range connectors {
		// If connector_type is specified in the path, filter by connector.Type
		if exists && strings.ToLower(connectorType) != strings.ToLower(connector.Type) {
			continue
		}

		info := ConnectorInfo{
			ID:   connector.Id,
			Type: connector.Type,
			Name: connector.Name,
		}

		// Attempt to unmarshal the Config based on connector type.
		if connector.Type == "oidc" {
			var config OIDCConfig
			if err := json.Unmarshal(connector.Config, &config); err == nil {
				info.Issuer = config.Issuer
				info.ClientID = config.ClientID
				// ClientSecret is omitted for security reasons.
			} else {
				dc.logger.Errorf("Failed to unmarshal config for connector (%s): %v", connector.Id, err)
			}
		}

		connectorInfos = append(connectorInfos, info)
	}

	// If connector_type is specified, ensure that the response is limited to that type
	if exists && len(connectorInfos) == 0 {
		http.Error(w, fmt.Sprintf("No connectors found for connector_type: %s", connectorType), http.StatusNotFound)
		return
	}

	response, err := json.Marshal(connectorInfos)
	if err != nil {
		dc.logger.Errorf("Error marshaling connectors: %v", err)
		http.Error(w, fmt.Sprintf("Error marshaling connectors: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)

	dc.logger.Debug("ListConnectorsHandler response sent to client")
}

// UpdateConnectorByIDHandler handles the updating of a connector based on connector_id in the path.
func (dc *DexClient) UpdateConnectorByIDHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID, exists := vars["connector_id"]
	if !exists || strings.TrimSpace(connectorID) == "" {
		dc.logger.Warn("Missing connector_id in UpdateConnectorByIDHandler request")
		http.Error(w, "connector_id is required in the URL path", http.StatusBadRequest)
		return
	}

	var reqData CreateConnectorRequest

	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		dc.logger.Errorf("Invalid request body for UpdateConnectorByIDHandler: %v", err)
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Set the ConnectorType from URL path if not provided in the body
	if strings.TrimSpace(reqData.ConnectorType) == "" {
		dc.logger.Warn("Missing connector_type in request body, defaulting to 'oidc'")
		reqData.ConnectorType = "oidc"
	}

	// Validate the request payload
	if err := dc.validate.Struct(reqData); err != nil {
		dc.logger.Errorf("Validation error in UpdateConnectorByIDHandler: %v", err)
		http.Error(w, fmt.Sprintf("Validation error: %v", err), http.StatusBadRequest)
		return
	}

	// Additional conditional validation based on connector_type and connector_sub_type
	switch strings.ToLower(reqData.ConnectorType) {
	case "oidc":
		switch strings.ToLower(reqData.ConnectorSubType) {
		case "google-workspace", "entraid", "general":
			if strings.ToLower(reqData.ConnectorSubType) == "general" {
				// For 'general', either Issuer or TenantID is required
				if reqData.Issuer == "" && reqData.TenantID == "" {
					dc.logger.Warn("Missing issuer or tenant_id for general OIDC connector update")
					http.Error(w, "issuer or tenant_id is required for general OIDC connector update", http.StatusBadRequest)
					return
				}
			} else {
				// For specific sub-types like 'google-workspace' or 'entraid', ensure Issuer is provided
				if reqData.Issuer == "" {
					dc.logger.Warnf("Missing issuer for %s connector update", reqData.ConnectorSubType)
					http.Error(w, fmt.Sprintf("issuer is required for %s connector update", reqData.ConnectorSubType), http.StatusBadRequest)
					return
				}
			}
		default:
			http.Error(w, fmt.Sprintf("unsupported connector_sub_type: %s", reqData.ConnectorSubType), http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, fmt.Sprintf("unsupported connector type: %s", reqData.ConnectorType), http.StatusBadRequest)
		return
	}

	// Prepare parameters map
	params := map[string]string{
		"Issuer":           reqData.Issuer,
		"TenantID":         reqData.TenantID,
		"ClientID":         reqData.ClientID,
		"ClientSecret":     reqData.ClientSecret,
		"ConnectorType":    reqData.ConnectorType,
		"ConnectorSubType": reqData.ConnectorSubType, // Include sub-type if needed
		"id":               reqData.ID,               // Corrected to lowercase 'id'
		"name":             reqData.Name,             // Corrected to lowercase 'name'
	}

	// Update the connector
	resp, err := dc.UpdateOIDCConnector(connectorID, params)
	if err != nil {
		dc.logger.Errorf("Error updating connector (%s): %v", connectorID, err)
		http.Error(w, fmt.Sprintf("Error updating connector: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"message": "Connector updated successfully.",
	}

	if resp.NotFound {
		response["message"] = "Connector not found for update."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	dc.logger.Debug("UpdateConnectorByIDHandler response sent to client")
}

// DeleteConnectorByIDHandler handles the deletion of a connector based on connector_id in the path.
func (dc *DexClient) DeleteConnectorByIDHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID, exists := vars["connector_id"]
	if !exists || strings.TrimSpace(connectorID) == "" {
		dc.logger.Warn("Missing connector_id in DeleteConnectorByIDHandler request")
		http.Error(w, "connector_id is required in the URL path", http.StatusBadRequest)
		return
	}

	resp, err := dc.DeleteConnectorByID(connectorID)
	if err != nil {
		dc.logger.Errorf("Error deleting connector by ID (%s): %v", connectorID, err)
		http.Error(w, fmt.Sprintf("Error deleting connector: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"message": "Connector deleted successfully.",
	}

	if resp.NotFound {
		response["message"] = "Connector not found for deletion."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	dc.logger.Debug("DeleteConnectorByIDHandler response sent to client")
}

// GetSupportedConnectorTypesHandler handles the GET /get/supported-connector-types endpoint.
func (dc *DexClient) GetSupportedConnectorTypesHandler(w http.ResponseWriter, r *http.Request) {
	// Define a struct to represent each connector type and its sub-types.
	type ConnectorTypeInfo struct {
		ConnectorType string   `json:"connector_type"`
		SubTypes      []string `json:"sub_types"`
	}

	var connectors []ConnectorTypeInfo

	// Populate the connectors slice with data from SupportedConnectors.
	for ct, subTypes := range SupportedConnectors {
		connectors = append(connectors, ConnectorTypeInfo{
			ConnectorType: ct,
			SubTypes:      subTypes,
		})
	}

	// Marshal the connectors slice to JSON.
	response, err := json.Marshal(connectors)
	if err != nil {
		dc.logger.Errorf("Error marshaling supported connector types: %v", err)
		http.Error(w, fmt.Sprintf("Error retrieving supported connector types: %v", err), http.StatusInternalServerError)
		return
	}

	// Set the Content-Type header and write the response.
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)

	dc.logger.Debug("GetSupportedConnectorTypesHandler response sent to client")
}

// main function sets up the server and routes.
func main() {
	// Initialize Logrus logger
	logger := logrus.New()

	// Set log format to JSON for better integration with Kubernetes logging
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Set log level based on environment variable, default to info
	logLevelStr := strings.ToLower(os.Getenv("LOG_LEVEL"))
	switch logLevelStr {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.Infof("Logger initialized with level: %s", logger.GetLevel().String())

	// Parse command-line flags for gRPC certificates and server addresses
	caCrt := flag.String("ca-crt", "", "Path to CA certificate (optional)")
	clientCrt := flag.String("client-crt", "", "Path to client certificate (optional)")
	clientKey := flag.String("client-key", "", "Path to client key (optional)")
	dexAddress := flag.String("dex-address", "127.0.0.1:5557", "Dex gRPC server address")
	serverAddress := flag.String("server-address", ":8080", "HTTP server address")
	flag.Parse()

	// Determine if operations should be restricted to "oidc" connector types
	restrictToOIDC := true // Default to true
	if envVal, exists := os.LookupEnv("RESTRICT_TO_OIDC"); exists {
		restrictToOIDC = strings.ToLower(envVal) == "true"
	}
	if restrictToOIDC {
		logger.Info("Operations are restricted to 'oidc' connector types")
	} else {
		logger.Info("Operations are not restricted to 'oidc' connector types")
	}

	// Initialize the Dex client.
	dexClient, err := NewDexClient(*dexAddress, *caCrt, *clientCrt, *clientKey, logger, restrictToOIDC)
	if err != nil {
		logger.Fatalf("Failed to initialize Dex client: %v", err)
	}
	defer func() {
		if err := dexClient.Close(); err != nil {
			logger.Errorf("Failed to close Dex client: %v", err)
		}
	}()

	// Initialize the router.
	router := mux.NewRouter()

	// Define the routes.
	// New route with connector_sub_type
	router.HandleFunc("/create/{connector_type}/{connector_sub_type}", dexClient.CreateConnectorHandler).Methods("POST")
	// Existing route without connector_sub_type (defaults to 'general')
	router.HandleFunc("/create/{connector_type}", dexClient.CreateConnectorHandler).Methods("POST")
	router.HandleFunc("/update/{connector_id}", dexClient.UpdateConnectorByIDHandler).Methods("PUT")
	router.HandleFunc("/delete/{connector_id}", dexClient.DeleteConnectorByIDHandler).Methods("DELETE")
	router.HandleFunc("/list", dexClient.ListAndDescribeConnectorsHandler).Methods("GET")
	router.HandleFunc("/list/{connector_type}", dexClient.ListAndDescribeConnectorsHandler).Methods("GET")
	// New endpoint for supported connector types
	router.HandleFunc("/get/supported-connector-types", dexClient.GetSupportedConnectorTypesHandler).Methods("GET")

	// Apply middleware if needed (e.g., authentication, rate limiting)

	// Start the HTTP server.
	logger.Infof("Starting server on %s...", *serverAddress)
	if err := http.ListenAndServe(*serverAddress, router); err != nil {
		logger.Fatalf("Server failed to start: %v", err)
	}
}
